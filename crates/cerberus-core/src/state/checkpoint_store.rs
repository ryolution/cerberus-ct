use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ct::StaticCtEntryParseError;
use crate::error::{CerberusError, Result};
use crate::finding::{Evidence, Finding, Severity};

pub const WATCH_CT_STATE_SCHEMA_VERSION: u32 = 2;
const DEFAULT_ALERT_TTL_SECS: u64 = 90 * 24 * 60 * 60;
const MAX_DEAD_LETTER_ENTRIES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchCtState {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub log_url: String,
    pub last_checkpoint_size: u64,
    #[serde(default)]
    pub last_checkpoint_root_hash: Option<String>,
    #[serde(default)]
    pub last_scanned_tile_index: Option<u64>,
    #[serde(default)]
    pub last_scanned_entry_index: Option<u64>,
    #[serde(default)]
    pub alerted_domains: Vec<String>,
    #[serde(default)]
    pub alerted_events: BTreeMap<String, AlertRecord>,
    #[serde(default)]
    pub dead_letter_entries: Vec<DeadLetterEntry>,
    #[serde(default)]
    pub outbox: Vec<OutboxEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertIdentity {
    pub log_id: String,
    pub certificate_index: Option<u64>,
    pub certificate_fingerprint: Option<String>,
    pub normalized_domain: String,
    pub detector: String,
    pub evidence_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRecord {
    pub identity: AlertIdentity,
    pub highest_severity: Severity,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub expires_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadLetterEntry {
    pub log_url: String,
    pub index: u64,
    pub error: String,
    pub recorded_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxEvent {
    pub id: String,
    pub sink: String,
    pub payload: serde_json::Value,
    pub created_at_unix: u64,
    pub attempts: u32,
    pub last_error: Option<String>,
}

impl WatchCtState {
    pub fn new(log_url: impl Into<String>) -> Self {
        Self {
            schema_version: WATCH_CT_STATE_SCHEMA_VERSION,
            log_url: log_url.into(),
            last_checkpoint_size: 0,
            last_checkpoint_root_hash: None,
            last_scanned_tile_index: None,
            last_scanned_entry_index: None,
            alerted_domains: Vec::new(),
            alerted_events: BTreeMap::new(),
            dead_letter_entries: Vec::new(),
            outbox: Vec::new(),
        }
    }

    pub fn has_alerted(&self, domain: &str) -> bool {
        self.alerted_domains
            .iter()
            .any(|seen| seen.eq_ignore_ascii_case(domain))
    }

    pub fn remember_alerted_domain(&mut self, domain: impl Into<String>) {
        let domain = domain.into();
        if !self.has_alerted(&domain) {
            self.alerted_domains.push(domain);
        }
    }

    pub fn has_alerted_finding(&self, finding: &Finding) -> bool {
        let identity = AlertIdentity::from_finding(finding, &self.log_url);
        let Some(record) = self.alerted_events.get(&identity.key()) else {
            return false;
        };

        if record.is_expired(unix_now()) {
            return false;
        }

        finding.severity <= record.highest_severity
    }

    pub fn remember_alerted_finding(&mut self, finding: &Finding) {
        let now = unix_now();
        let identity = AlertIdentity::from_finding(finding, &self.log_url);
        let key = identity.key();

        self.alerted_events
            .entry(key)
            .and_modify(|record| {
                record.highest_severity = record.highest_severity.max(finding.severity);
                record.last_seen_unix = now;
                record.expires_at_unix = Some(now.saturating_add(DEFAULT_ALERT_TTL_SECS));
            })
            .or_insert_with(|| AlertRecord {
                identity,
                highest_severity: finding.severity,
                first_seen_unix: now,
                last_seen_unix: now,
                expires_at_unix: Some(now.saturating_add(DEFAULT_ALERT_TTL_SECS)),
            });
    }

    pub fn remember_alerted_findings<'a>(
        &mut self,
        findings: impl IntoIterator<Item = &'a Finding>,
    ) {
        for finding in findings {
            self.remember_alerted_finding(finding);
        }
    }

    pub fn prune_expired_alerts(&mut self) {
        let now = unix_now();
        self.alerted_events
            .retain(|_, record| !record.is_expired(now));
    }

    pub fn record_parse_errors(
        &mut self,
        log_url: &str,
        parse_errors: impl IntoIterator<Item = StaticCtEntryParseError>,
    ) {
        let recorded_at_unix = unix_now();

        for parse_error in parse_errors {
            self.dead_letter_entries.push(DeadLetterEntry {
                log_url: log_url.to_string(),
                index: parse_error.index,
                error: parse_error.error,
                recorded_at_unix,
            });
        }

        if self.dead_letter_entries.len() > MAX_DEAD_LETTER_ENTRIES {
            let excess = self.dead_letter_entries.len() - MAX_DEAD_LETTER_ENTRIES;
            self.dead_letter_entries.drain(..excess);
        }
    }

    pub fn update_position(
        &mut self,
        checkpoint_size: u64,
        checkpoint_root_hash: impl Into<String>,
        tile_index: u64,
        entry_index: u64,
    ) {
        self.last_checkpoint_size = checkpoint_size;
        self.last_checkpoint_root_hash = Some(checkpoint_root_hash.into());
        self.last_scanned_tile_index = Some(tile_index);
        self.last_scanned_entry_index = Some(entry_index);
    }

    pub fn enqueue_outbox(
        &mut self,
        sink: impl Into<String>,
        payload: serde_json::Value,
    ) -> Result<Option<String>> {
        let sink = sink.into();
        let id = outbox_event_id(&sink, &payload)?;

        if self.outbox.iter().any(|event| event.id == id) {
            return Ok(None);
        }

        self.outbox.push(OutboxEvent {
            id: id.clone(),
            sink,
            payload,
            created_at_unix: unix_now(),
            attempts: 0,
            last_error: None,
        });

        Ok(Some(id))
    }

    pub fn pending_outbox(&self) -> Vec<OutboxEvent> {
        self.outbox.clone()
    }

    pub fn mark_outbox_delivered(&mut self, id: &str) {
        self.outbox.retain(|event| event.id != id);
    }

    pub fn mark_outbox_attempt_failed(&mut self, id: &str, error: impl Into<String>) {
        if let Some(event) = self.outbox.iter_mut().find(|event| event.id == id) {
            event.attempts = event.attempts.saturating_add(1);
            event.last_error = Some(error.into());
        }
    }
}

impl AlertIdentity {
    pub fn from_finding(finding: &Finding, default_log_id: &str) -> Self {
        Self {
            log_id: evidence_value(&finding.evidence, "ct.source_log")
                .unwrap_or(default_log_id)
                .to_string(),
            certificate_index: evidence_value(&finding.evidence, "ct.certificate_index")
                .and_then(|value| value.parse::<u64>().ok()),
            certificate_fingerprint: evidence_value(&finding.evidence, "ct.certificate_sha256")
                .map(ToOwned::to_owned),
            normalized_domain: finding.domain.to_ascii_lowercase(),
            detector: finding.detector.clone(),
            evidence_fingerprint: finding_evidence_fingerprint(finding),
        }
    }

    pub fn key(&self) -> String {
        let encoded = serde_json::to_vec(self).unwrap_or_default();
        hex::encode(Sha256::digest(encoded))
    }
}

impl AlertRecord {
    fn is_expired(&self, now: u64) -> bool {
        self.expires_at_unix.is_some_and(|expires| expires <= now)
    }
}

#[derive(Debug, Clone)]
pub struct FileWatchStateStore {
    path: PathBuf,
}

impl FileWatchStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> Result<Option<WatchCtState>> {
        if !Path::new(&self.path).exists() {
            return Ok(None);
        }

        self.with_lock(|| {
            let input = fs::read_to_string(&self.path)?;
            match serde_json::from_str::<WatchCtState>(&input) {
                Ok(mut state) => {
                    state.schema_version = WATCH_CT_STATE_SCHEMA_VERSION;
                    state.prune_expired_alerts();
                    Ok(Some(state))
                }
                Err(primary_error) => {
                    let backup_path = self.backup_path();
                    if backup_path.exists() {
                        let backup = fs::read_to_string(&backup_path)?;
                        let mut state = serde_json::from_str::<WatchCtState>(&backup)?;
                        state.schema_version = WATCH_CT_STATE_SCHEMA_VERSION;
                        state.prune_expired_alerts();
                        Ok(Some(state))
                    } else {
                        Err(CerberusError::State(format!(
                            "failed to parse state file `{}` and no backup is available: {primary_error}",
                            self.path.display()
                        )))
                    }
                }
            }
        })
    }

    pub fn save(&self, state: &WatchCtState) -> Result<()> {
        self.with_lock(|| {
            self.ensure_parent_dir()?;

            let mut state = state.clone();
            state.schema_version = WATCH_CT_STATE_SCHEMA_VERSION;
            state.prune_expired_alerts();

            let output = serde_json::to_vec_pretty(&state)?;
            let tmp_path = self.tmp_path();
            let backup_path = self.backup_path();

            {
                let mut file = File::create(&tmp_path)?;
                file.write_all(&output)?;
                file.write_all(b"\n")?;
                file.sync_all()?;
            }

            if self.path.exists() {
                fs::copy(&self.path, &backup_path)?;
            }

            replace_file(&tmp_path, &self.path)?;
            fs::copy(&self.path, backup_path)?;
            Ok(())
        })
    }

    fn with_lock<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        self.ensure_parent_dir()?;
        let lock_path = self.lock_path();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;

        lock.lock_exclusive()?;
        let result = operation();
        let unlock_result = FileExt::unlock(&lock);

        match (result, unlock_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error.into()),
        }
    }

    fn ensure_parent_dir(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        Ok(())
    }

    fn lock_path(&self) -> PathBuf {
        sibling_path(&self.path, "lock")
    }

    fn tmp_path(&self) -> PathBuf {
        sibling_path(&self.path, "tmp")
    }

    fn backup_path(&self) -> PathBuf {
        sibling_path(&self.path, "bak")
    }
}

fn sibling_path(path: &Path, extension: &str) -> PathBuf {
    let mut path = path.to_path_buf();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state.json");
    path.set_file_name(format!("{file_name}.{extension}"));
    path
}

fn evidence_value<'a>(evidence: &'a [Evidence], kind: &str) -> Option<&'a str> {
    evidence
        .iter()
        .find(|item| item.kind == kind)
        .map(|item| item.value.as_str())
}

fn finding_evidence_fingerprint(finding: &Finding) -> String {
    let mut parts = Vec::new();

    for reason in &finding.reasons {
        parts.push(format!("reason={reason}"));
    }

    for item in &finding.evidence {
        if item.kind == "ct.observed_at" {
            continue;
        }

        parts.push(format!("{}={}", item.kind, item.value));
    }

    parts.sort();
    parts.dedup();
    hex::encode(Sha256::digest(parts.join("\n").as_bytes()))
}

fn outbox_event_id(sink: &str, payload: &serde_json::Value) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(sink.as_bytes());
    hasher.update([0]);
    hasher.update(serde_json::to_vec(payload)?);
    Ok(hex::encode(hasher.finalize()))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(not(windows))]
fn replace_file(tmp_path: &Path, destination: &Path) -> Result<()> {
    fs::rename(tmp_path, destination)?;
    Ok(())
}

#[cfg(windows)]
fn replace_file(tmp_path: &Path, destination: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let tmp_path = wide_path(tmp_path);
    let destination = wide_path(destination);
    let result = unsafe {
        MoveFileExW(
            tmp_path.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };

    if result == 0 {
        return Err(CerberusError::State(format!(
            "failed to atomically replace state file: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn default_schema_version() -> u32 {
    WATCH_CT_STATE_SCHEMA_VERSION
}

#[cfg(test)]
mod tests {
    use super::{
        FileWatchStateStore, MAX_DEAD_LETTER_ENTRIES, WATCH_CT_STATE_SCHEMA_VERSION, WatchCtState,
        unix_now,
    };
    use crate::ct::StaticCtEntryParseError;
    use crate::finding::{Finding, Severity};

    #[test]
    fn tracks_alerted_domains_case_insensitively() {
        let mut state = WatchCtState::new("https://example.com/log");
        state.remember_alerted_domain("Paypa1-login.com");
        state.remember_alerted_domain("paypa1-login.com");

        assert!(state.has_alerted("PAYPA1-LOGIN.COM"));
        assert_eq!(state.alerted_domains.len(), 1);
    }

    #[test]
    fn updates_scan_position() {
        let mut state = WatchCtState::new("https://example.com/log");
        state.update_position(1000, "root", 3, 999);

        assert_eq!(state.schema_version, WATCH_CT_STATE_SCHEMA_VERSION);
        assert_eq!(state.last_checkpoint_size, 1000);
        assert_eq!(state.last_checkpoint_root_hash, Some("root".to_string()));
        assert_eq!(state.last_scanned_tile_index, Some(3));
        assert_eq!(state.last_scanned_entry_index, Some(999));
    }

    #[test]
    fn dedupes_findings_by_event_identity_not_domain_only() {
        let mut state = WatchCtState::new("https://example.com/log");
        let first = Finding::new("paypa1-login.com", "keyword", Severity::Low, 30)
            .with_evidence("ct.certificate_index", "10")
            .with_evidence("ct.certificate_sha256", "abc");
        let second = Finding::new("paypa1-login.com", "typosquat", Severity::High, 85)
            .with_evidence("ct.certificate_index", "10")
            .with_evidence("ct.certificate_sha256", "abc");

        state.remember_alerted_finding(&first);

        assert!(state.has_alerted_finding(&first));
        assert!(!state.has_alerted_finding(&second));
    }

    #[test]
    fn recovers_from_backup_when_state_is_truncated() {
        let path =
            std::env::temp_dir().join(format!("cerberus-state-recovery-{}.json", unix_now()));
        let store = FileWatchStateStore::new(&path);
        let mut state = WatchCtState::new("https://example.com/log");
        state.update_position(1000, "root", 3, 999);

        store.save(&state).unwrap();
        std::fs::write(&path, "{").unwrap();

        let recovered = store.load().unwrap().unwrap();
        assert_eq!(recovered.last_scanned_entry_index, Some(999));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(store.backup_path());
        let _ = std::fs::remove_file(store.lock_path());
    }

    #[test]
    fn dedupes_outbox_events_by_sink_and_payload() {
        let mut state = WatchCtState::new("https://example.com/log");
        let payload = serde_json::json!({"kind": "findings", "count": 0, "findings": []});

        let first = state.enqueue_outbox("webhook", payload.clone()).unwrap();
        let second = state.enqueue_outbox("webhook", payload).unwrap();

        assert!(first.is_some());
        assert!(second.is_none());
        assert_eq!(state.outbox.len(), 1);
    }

    #[test]
    fn caps_dead_letter_entries_to_recent_failures() {
        let mut state = WatchCtState::new("https://example.com/log");
        let errors = (0..MAX_DEAD_LETTER_ENTRIES + 10).map(|index| StaticCtEntryParseError {
            index: index as u64,
            error: format!("parse error {index}"),
        });

        state.record_parse_errors("https://example.com/log", errors);

        assert_eq!(state.dead_letter_entries.len(), MAX_DEAD_LETTER_ENTRIES);
        assert_eq!(state.dead_letter_entries[0].index, 10);
        assert_eq!(
            state.dead_letter_entries.last().map(|entry| entry.index),
            Some((MAX_DEAD_LETTER_ENTRIES + 9) as u64)
        );
    }
}
