use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchCtState {
    pub log_url: String,
    pub last_checkpoint_size: u64,
    pub last_scanned_tile_index: Option<u64>,
    pub last_scanned_entry_index: Option<u64>,
    pub alerted_domains: Vec<String>,
}

impl WatchCtState {
    pub fn new(log_url: impl Into<String>) -> Self {
        Self {
            log_url: log_url.into(),
            last_checkpoint_size: 0,
            last_scanned_tile_index: None,
            last_scanned_entry_index: None,
            alerted_domains: Vec::new(),
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

    pub fn update_position(&mut self, checkpoint_size: u64, tile_index: u64, entry_index: u64) {
        self.last_checkpoint_size = checkpoint_size;
        self.last_scanned_tile_index = Some(tile_index);
        self.last_scanned_entry_index = Some(entry_index);
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

        let input = fs::read_to_string(&self.path)?;
        Ok(Some(serde_json::from_str(&input)?))
    }

    pub fn save(&self, state: &WatchCtState) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let output = serde_json::to_string_pretty(state)?;
        fs::write(&self.path, output)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::WatchCtState;

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
        state.update_position(1000, 3, 999);

        assert_eq!(state.last_checkpoint_size, 1000);
        assert_eq!(state.last_scanned_tile_index, Some(3));
        assert_eq!(state.last_scanned_entry_index, Some(999));
    }
}
