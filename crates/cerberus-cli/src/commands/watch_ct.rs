use anyhow::{Result, anyhow};
use cerberus_core::{
    DetectionEngine, DomainAlert, FileWatchStateStore, Finding, OutboxEvent, StaticCtClient,
    StaticCtTileMetadata, StaticCtTilePath, WatchCtState, WebhookPayload,
    decode_static_ct_data_tile, decoded_entries_to_certificate_events, group_findings_by_domain,
    verify_entries_against_level_zero_hashes,
};
use serde::Serialize;
use tokio::time::{Duration, sleep};

use crate::cli::{OutputFormat, WatchCtArgs};
use crate::commands::{apply_rule_overrides, enrichment, load_config, webhook};
use crate::display;

#[derive(Debug, Clone, Serialize)]
struct WatchCtSummary {
    log_url: String,
    state_path: String,
    checkpoint_size: u64,
    latest_tile_index: u64,
    latest_entry_index: u64,
    scan_start_tile_index: Option<u64>,
    scan_end_tile_index: Option<u64>,
    scanned_tile_count: u64,
    scanned_entry_count: usize,
    parse_error_count: usize,
    finding_count: usize,
    alert_count: usize,
    deduped_count: usize,
    last_scanned_entry_index: Option<u64>,
    message: String,
    scanned_tiles: Vec<StaticCtTileMetadata>,
}

#[derive(Debug, Serialize)]
struct WatchCtAlertReport {
    summary: WatchCtSummary,
    alerts: Vec<DomainAlert>,
}

#[derive(Debug, Serialize)]
struct WatchCtFindingReport {
    summary: WatchCtSummary,
    findings: Vec<Finding>,
}

pub async fn run(args: WatchCtArgs) -> Result<()> {
    tracing::info!(
        url = %args.url,
        state = %args.state.display(),
        once = args.once,
        interval_ms = args.interval_ms,
        max_tiles = args.max_tiles,
        seed_index = ?args.seed_index,
        reset_state = args.reset_state,
        grouped = args.grouped,
        min_score = ?args.min_score,
        allowlist_suffix_count = args.allowlist_suffixes.len(),
        summary = args.summary,
        dns = args.dns,
        takeover = args.takeover,
        webhook = args.webhook_url.is_some(),
        format = ?args.format,
        "running watch-ct command"
    );

    if args.max_tiles == 0 {
        return Err(anyhow!("--max-tiles must be greater than zero"));
    }

    if args.interval_ms == 0 {
        return Err(anyhow!("--interval-ms must be greater than zero"));
    }

    let mut config = load_config(args.config.as_deref())?;
    apply_rule_overrides(&mut config, args.min_score, &args.allowlist_suffixes);
    let webhook_url = args
        .webhook_url
        .as_deref()
        .or(config.outputs.webhook_url.as_deref());
    let webhook_signing_secret = config.outputs.webhook_signing_secret.as_deref();
    let slack_webhook_url = config.outputs.slack_webhook_url.as_deref();

    let engine = DetectionEngine::default();
    let trusted_log = config
        .trusted_log_for_url(&args.url)?
        .ok_or_else(|| anyhow!("watch-ct requires a matching ct.trusted_logs entry"))?;
    let client = StaticCtClient::with_trusted_log(trusted_log)?;
    let store = FileWatchStateStore::new(args.state.clone());
    let base_url = client.monitoring_base_url();
    let mut first_iteration = true;

    loop {
        let reset_state = args.reset_state && first_iteration;
        let mut state = load_state(&store, &base_url, reset_state)?;
        deliver_pending_outbox(
            &store,
            &mut state,
            webhook_url,
            webhook_signing_secret,
            slack_webhook_url,
        )
        .await?;
        let checkpoint = client.fetch_checkpoint().await?;
        client
            .verify_checkpoint_consistency(
                state.last_checkpoint_size,
                state.last_checkpoint_root_hash.as_deref(),
                &checkpoint,
            )
            .await?;
        client.verify_checkpoint_tree(&checkpoint).await?;
        let checkpoint_root_hex = checkpoint.root_hash_hex()?;
        validate_checkpoint_progress(&state, &checkpoint_root_hex, checkpoint.size)?;
        let latest_path = cerberus_core::latest_data_tile_for_size(checkpoint.size)?
            .ok_or_else(|| anyhow!("checkpoint tree size does not contain a data tile"))?;
        let latest_entry_index = checkpoint.size.saturating_sub(1);

        if state
            .last_scanned_entry_index
            .is_some_and(|last| last >= latest_entry_index)
        {
            state.last_checkpoint_size = checkpoint.size;
            state.last_checkpoint_root_hash = Some(checkpoint_root_hex);
            store.save(&state)?;

            let summary = WatchCtSummary {
                log_url: base_url.clone(),
                state_path: args.state.display().to_string(),
                checkpoint_size: checkpoint.size,
                latest_tile_index: latest_path.index,
                latest_entry_index,
                scan_start_tile_index: None,
                scan_end_tile_index: None,
                scanned_tile_count: 0,
                scanned_entry_count: 0,
                parse_error_count: 0,
                finding_count: 0,
                alert_count: 0,
                deduped_count: 0,
                last_scanned_entry_index: state.last_scanned_entry_index,
                message: "No new CT entries to scan".to_string(),
                scanned_tiles: Vec::new(),
            };

            if args.once || args.summary {
                output_empty_report(&summary, args.grouped, args.format)?;
            }

            if args.once {
                break;
            }

            first_iteration = false;
            sleep(Duration::from_millis(args.interval_ms)).await;
            continue;
        }

        let next_entry_index = state
            .last_scanned_entry_index
            .map(|index| index.saturating_add(1));

        let start_tile_index = match next_entry_index {
            Some(index) => index / 256,
            None => args.seed_index.unwrap_or(latest_path.index),
        };

        let first_entry_to_scan = next_entry_index.unwrap_or_else(|| start_tile_index * 256);
        let end_tile_index = latest_path.index;

        if start_tile_index > end_tile_index {
            state.last_checkpoint_size = checkpoint.size;
            state.last_checkpoint_root_hash = Some(checkpoint_root_hex);
            store.save(&state)?;

            let summary = WatchCtSummary {
                log_url: base_url.clone(),
                state_path: args.state.display().to_string(),
                checkpoint_size: checkpoint.size,
                latest_tile_index: latest_path.index,
                latest_entry_index,
                scan_start_tile_index: None,
                scan_end_tile_index: None,
                scanned_tile_count: 0,
                scanned_entry_count: 0,
                parse_error_count: 0,
                finding_count: 0,
                alert_count: 0,
                deduped_count: 0,
                last_scanned_entry_index: state.last_scanned_entry_index,
                message: "No new CT entries to scan".to_string(),
                scanned_tiles: Vec::new(),
            };

            if args.once || args.summary {
                output_empty_report(&summary, args.grouped, args.format)?;
            }

            if args.once {
                break;
            }

            first_iteration = false;
            sleep(Duration::from_millis(args.interval_ms)).await;
            continue;
        }

        let scan_end_tile_index = start_tile_index
            .saturating_add(args.max_tiles.saturating_sub(1))
            .min(end_tile_index);

        let mut findings = Vec::new();
        let mut observed_domains = Vec::new();
        let mut scanned_tile_count = 0u64;
        let mut scanned_entry_count = 0usize;
        let mut parse_error_count = 0usize;
        let mut scanned_tiles = Vec::new();

        for tile_index in start_tile_index..=scan_end_tile_index {
            let width = if tile_index == latest_path.index {
                latest_path.width
            } else {
                None
            };

            let path = StaticCtTilePath::data(tile_index, width)?;
            let tile = client.fetch_tile(path).await?;
            let metadata = tile.metadata()?;
            let entries = decode_static_ct_data_tile(&tile)?;
            let level_zero_hashes = client
                .fetch_level_zero_hashes_for_data_tile(&tile.path, checkpoint.size)
                .await?;
            verify_entries_against_level_zero_hashes(&entries, &level_zero_hashes)?;
            let highest_decoded_entry_index = entries
                .last()
                .map(|entry| entry.index)
                .ok_or_else(|| anyhow!("decoded Static CT tile contained no entries"))?;
            let decoded = decoded_entries_to_certificate_events(&entries, base_url.clone());
            let tile_end_entry_index = highest_decoded_entry_index;
            let tile_start_entry_index = tile_index.saturating_mul(256);
            let first_index_for_tile = first_entry_to_scan.max(tile_start_entry_index);

            scanned_tile_count += 1;
            parse_error_count += decoded.parse_error_count;
            scanned_tiles.push(metadata);

            scanned_entry_count += entries
                .iter()
                .filter(|entry| entry.index >= first_index_for_tile)
                .count();

            state.record_parse_errors(&base_url, decoded.parse_errors.clone());

            for event in decoded.events {
                if event.index.is_some_and(|index| index < first_entry_to_scan) {
                    continue;
                }

                observed_domains.extend(
                    event
                        .domains
                        .iter()
                        .map(|domain| domain.as_str().to_string()),
                );

                findings.extend(engine.detect_event(event, &config)?);
            }

            state.update_position(
                checkpoint.size,
                checkpoint_root_hex.clone(),
                tile_index,
                tile_end_entry_index,
            );
        }

        tracing::info!(
            scanned_tile_count,
            scanned_entry_count,
            parse_error_count,
            finding_count = findings.len(),
            "watch-ct batch scanned"
        );

        enrichment::apply_enrichment(
            &mut findings,
            observed_domains,
            args.dns,
            args.takeover,
            &config,
        )
        .await?;

        if args.grouped {
            let raw_alerts = group_findings_by_domain(findings);
            let raw_alert_count = raw_alerts.len();
            let alerts = raw_alerts
                .into_iter()
                .filter(|alert| {
                    alert
                        .findings
                        .iter()
                        .any(|finding| !state.has_alerted_finding(finding))
                })
                .filter(|alert| config.should_keep_alert(alert.score))
                .collect::<Vec<_>>();

            let deduped_count = raw_alert_count.saturating_sub(alerts.len());

            let summary = WatchCtSummary {
                log_url: base_url.clone(),
                state_path: args.state.display().to_string(),
                checkpoint_size: checkpoint.size,
                latest_tile_index: latest_path.index,
                latest_entry_index,
                scan_start_tile_index: Some(start_tile_index),
                scan_end_tile_index: Some(scan_end_tile_index),
                scanned_tile_count,
                scanned_entry_count,
                parse_error_count,
                finding_count: alerts.iter().map(|alert| alert.findings.len()).sum(),
                alert_count: alerts.len(),
                deduped_count,
                last_scanned_entry_index: state.last_scanned_entry_index,
                message: watch_message(alerts.len(), 0, deduped_count),
                scanned_tiles,
            };

            enqueue_outbox_payloads(
                &mut state,
                webhook_url,
                slack_webhook_url,
                WebhookPayload::alerts(alerts.clone()),
            )?;
            for alert in &alerts {
                state.remember_alerted_findings(&alert.findings);
            }

            store.save(&state)?;
            deliver_pending_outbox(
                &store,
                &mut state,
                webhook_url,
                webhook_signing_secret,
                slack_webhook_url,
            )
            .await?;

            if args.once || args.summary || !alerts.is_empty() {
                output_alert_report(summary, alerts, args.format, args.summary || args.once)?;
            }
        } else {
            let raw_finding_count = findings.len();
            let mut filtered_findings = Vec::new();

            for finding in findings {
                if state.has_alerted_finding(&finding) {
                    continue;
                }

                filtered_findings.push(finding);
            }

            let deduped_count = raw_finding_count.saturating_sub(filtered_findings.len());

            let summary = WatchCtSummary {
                log_url: base_url.clone(),
                state_path: args.state.display().to_string(),
                checkpoint_size: checkpoint.size,
                latest_tile_index: latest_path.index,
                latest_entry_index,
                scan_start_tile_index: Some(start_tile_index),
                scan_end_tile_index: Some(scan_end_tile_index),
                scanned_tile_count,
                scanned_entry_count,
                parse_error_count,
                finding_count: filtered_findings.len(),
                alert_count: 0,
                deduped_count,
                last_scanned_entry_index: state.last_scanned_entry_index,
                message: watch_message(0, filtered_findings.len(), deduped_count),
                scanned_tiles,
            };

            enqueue_outbox_payloads(
                &mut state,
                webhook_url,
                slack_webhook_url,
                WebhookPayload::findings(filtered_findings.clone()),
            )?;
            state.remember_alerted_findings(&filtered_findings);
            store.save(&state)?;
            deliver_pending_outbox(
                &store,
                &mut state,
                webhook_url,
                webhook_signing_secret,
                slack_webhook_url,
            )
            .await?;

            if args.once || args.summary || !filtered_findings.is_empty() {
                output_finding_report(
                    summary,
                    filtered_findings,
                    args.format,
                    args.summary || args.once,
                )?;
            }
        }

        if args.once {
            break;
        }

        first_iteration = false;
        sleep(Duration::from_millis(args.interval_ms)).await;
    }

    Ok(())
}

fn enqueue_outbox_payloads(
    state: &mut WatchCtState,
    webhook_url: Option<&str>,
    slack_webhook_url: Option<&str>,
    payload: WebhookPayload,
) -> Result<()> {
    if payload.is_empty() {
        return Ok(());
    }

    let payload = serde_json::to_value(payload)?;
    if webhook_url.is_some() {
        state.enqueue_outbox("webhook", payload.clone())?;
    }
    if slack_webhook_url.is_some() {
        state.enqueue_outbox("slack", payload)?;
    }

    Ok(())
}

async fn deliver_pending_outbox(
    store: &FileWatchStateStore,
    state: &mut WatchCtState,
    webhook_url: Option<&str>,
    webhook_signing_secret: Option<&str>,
    slack_webhook_url: Option<&str>,
) -> Result<()> {
    let pending = state.pending_outbox();

    for event in pending {
        if let Err(error) = deliver_outbox_event(
            &event,
            webhook_url,
            webhook_signing_secret,
            slack_webhook_url,
        )
        .await
        {
            state.mark_outbox_attempt_failed(&event.id, error.to_string());
            store.save(state)?;
            return Err(error);
        }

        state.mark_outbox_delivered(&event.id);
        store.save(state)?;
    }

    Ok(())
}

async fn deliver_outbox_event(
    event: &OutboxEvent,
    webhook_url: Option<&str>,
    webhook_signing_secret: Option<&str>,
    slack_webhook_url: Option<&str>,
) -> Result<()> {
    let payload: WebhookPayload = serde_json::from_value(event.payload.clone())?;

    match event.sink.as_str() {
        "webhook" => {
            if webhook_url.is_none() {
                return Err(anyhow!(
                    "pending webhook outbox event has no configured URL"
                ));
            }
            webhook::send_payload(webhook_url, webhook_signing_secret, &payload).await
        }
        "slack" => {
            if slack_webhook_url.is_none() {
                return Err(anyhow!("pending Slack outbox event has no configured URL"));
            }
            webhook::send_payload_to_slack(slack_webhook_url, &payload).await
        }
        sink => Err(anyhow!("unknown outbox sink `{sink}`")),
    }
}

fn load_state(
    store: &FileWatchStateStore,
    base_url: &str,
    reset_state: bool,
) -> Result<WatchCtState> {
    if reset_state {
        return Ok(WatchCtState::new(base_url.to_string()));
    }

    let state = store.load()?;

    Ok(match state {
        Some(state) if state.log_url == base_url => state,
        _ => WatchCtState::new(base_url.to_string()),
    })
}

fn validate_checkpoint_progress(
    state: &WatchCtState,
    _checkpoint_root_hash: &str,
    checkpoint_size: u64,
) -> Result<()> {
    if checkpoint_size < state.last_checkpoint_size {
        return Err(anyhow!(
            "checkpoint rollback detected: stored size {} is newer than fetched size {}",
            state.last_checkpoint_size,
            checkpoint_size
        ));
    }

    Ok(())
}

fn output_empty_report(
    summary: &WatchCtSummary,
    grouped: bool,
    format: OutputFormat,
) -> Result<()> {
    match format {
        OutputFormat::Human => print_watch_summary_human(summary),
        OutputFormat::Json => {
            if grouped {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&WatchCtAlertReport {
                        summary: summary.clone(),
                        alerts: Vec::new(),
                    })?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&WatchCtFindingReport {
                        summary: summary.clone(),
                        findings: Vec::new(),
                    })?
                );
            }
        }
    }

    Ok(())
}

fn output_alert_report(
    summary: WatchCtSummary,
    alerts: Vec<DomainAlert>,
    format: OutputFormat,
    _report_json: bool,
) -> Result<()> {
    match format {
        OutputFormat::Human => {
            print_watch_summary_human(&summary);
            display::print_alerts_human(&alerts);
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&WatchCtAlertReport { summary, alerts })?
            );
        }
    }

    Ok(())
}

fn output_finding_report(
    summary: WatchCtSummary,
    findings: Vec<Finding>,
    format: OutputFormat,
    _report_json: bool,
) -> Result<()> {
    match format {
        OutputFormat::Human => {
            print_watch_summary_human(&summary);
            display::print_findings_human(&findings);
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&WatchCtFindingReport { summary, findings })?
            );
        }
    }

    Ok(())
}

fn watch_message(alert_count: usize, finding_count: usize, deduped_count: usize) -> String {
    if alert_count > 0 {
        format!("{alert_count} new grouped alerts produced")
    } else if finding_count > 0 {
        format!("{finding_count} new findings produced")
    } else if deduped_count > 0 {
        format!("No new output because {deduped_count} results were already alerted")
    } else {
        "No matching alerts for current rules".to_string()
    }
}

fn print_watch_summary_human(summary: &WatchCtSummary) {
    println!("log_url: {}", summary.log_url);
    println!("state: {}", summary.state_path);
    println!("checkpoint_size: {}", summary.checkpoint_size);
    println!("latest_tile_index: {}", summary.latest_tile_index);
    println!("latest_entry_index: {}", summary.latest_entry_index);

    if let Some(index) = summary.scan_start_tile_index {
        println!("scan_start_tile_index: {index}");
    }

    if let Some(index) = summary.scan_end_tile_index {
        println!("scan_end_tile_index: {index}");
    }

    println!("scanned_tiles: {}", summary.scanned_tile_count);
    println!("scanned_entries: {}", summary.scanned_entry_count);
    println!("parse_errors: {}", summary.parse_error_count);
    println!("findings: {}", summary.finding_count);
    println!("alerts: {}", summary.alert_count);
    println!("deduped: {}", summary.deduped_count);
    println!("message: {}", summary.message);
}
