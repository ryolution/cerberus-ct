use anyhow::{Result, anyhow};
use cerberus_core::{
    DetectionEngine, DomainAlert, Finding, StaticCtClient, StaticCtTileMetadata, StaticCtTilePath,
    decode_static_ct_data_tile, decoded_entries_to_certificate_events, group_findings_by_domain,
    latest_data_tile_for_size,
};
use serde::Serialize;

use crate::cli::{OutputFormat, ScanCtArgs};
use crate::commands::{apply_rule_overrides, enrichment, load_config, webhook};
use crate::display;

#[derive(Debug, Clone, Serialize)]
struct ScanCtSummary {
    tile: StaticCtTileMetadata,
    entry_count: usize,
    event_count: usize,
    parse_error_count: usize,
    finding_count: usize,
    alert_count: usize,
    message: String,
}

#[derive(Debug, Serialize)]
struct ScanCtAlertReport {
    summary: ScanCtSummary,
    alerts: Vec<DomainAlert>,
}

#[derive(Debug, Serialize)]
struct ScanCtFindingReport {
    summary: ScanCtSummary,
    findings: Vec<Finding>,
}

pub async fn run(args: ScanCtArgs) -> Result<()> {
    tracing::info!(
        url = %args.url,
        index = ?args.index,
        latest_size = ?args.latest_size,
        latest = args.latest,
        width = ?args.width,
        grouped = args.grouped,
        min_score = ?args.min_score,
        allowlist_suffix_count = args.allowlist_suffixes.len(),
        summary = args.summary,
        dns = args.dns,
        takeover = args.takeover,
        webhook = args.webhook_url.is_some(),
        format = ?args.format,
        "running scan-ct command"
    );

    let mut config = load_config(args.config.as_deref())?;
    apply_rule_overrides(&mut config, args.min_score, &args.allowlist_suffixes);
    let client = StaticCtClient::new(args.url.clone());
    let path = build_data_tile_path(&args, &client).await?;
    let source_log = client.monitoring_base_url();
    let tile = client.fetch_tile(path).await?;
    let metadata = tile.metadata()?;
    let entries = decode_static_ct_data_tile(&tile)?;
    let decoded = decoded_entries_to_certificate_events(&entries, source_log);
    let engine = DetectionEngine::default();
    let mut findings = Vec::new();
    let mut observed_domains = Vec::new();

    for event in decoded.events {
        observed_domains.extend(
            event
                .domains
                .iter()
                .map(|domain| domain.as_str().to_string()),
        );
        findings.extend(engine.detect_event(event, &config)?);
    }

    enrichment::apply_enrichment(
        &mut findings,
        observed_domains,
        args.dns,
        args.takeover,
        &config,
    )
    .await?;

    if args.grouped {
        let finding_count = findings.len();
        let alerts = group_findings_by_domain(findings);
        let summary = ScanCtSummary {
            tile: metadata,
            entry_count: decoded.entry_count,
            event_count: decoded.event_count,
            parse_error_count: decoded.parse_error_count,
            finding_count,
            alert_count: alerts.len(),
            message: scan_message(alerts.len(), finding_count),
        };

        webhook::send_alerts(args.webhook_url.as_deref(), &alerts).await?;

        tracing::info!(
            entry_count = summary.entry_count,
            event_count = summary.event_count,
            parse_error_count = summary.parse_error_count,
            finding_count = summary.finding_count,
            alert_count = summary.alert_count,
            "Static CT scan completed"
        );

        match args.format {
            OutputFormat::Human => {
                print_summary_human(&summary);
                display::print_alerts_human(&alerts);
            }
            OutputFormat::Json => {
                if args.summary || alerts.is_empty() {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&ScanCtAlertReport { summary, alerts })?
                    );
                } else {
                    println!("{}", serde_json::to_string_pretty(&alerts)?);
                }
            }
        }
    } else {
        let summary = ScanCtSummary {
            tile: metadata,
            entry_count: decoded.entry_count,
            event_count: decoded.event_count,
            parse_error_count: decoded.parse_error_count,
            finding_count: findings.len(),
            alert_count: 0,
            message: scan_message(0, findings.len()),
        };

        webhook::send_findings(args.webhook_url.as_deref(), &findings).await?;

        tracing::info!(
            entry_count = summary.entry_count,
            event_count = summary.event_count,
            parse_error_count = summary.parse_error_count,
            finding_count = summary.finding_count,
            "Static CT scan completed"
        );

        match args.format {
            OutputFormat::Human => {
                print_summary_human(&summary);
                display::print_findings_human(&findings);
            }
            OutputFormat::Json => {
                if args.summary || findings.is_empty() {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&ScanCtFindingReport { summary, findings })?
                    );
                } else {
                    println!("{}", serde_json::to_string_pretty(&findings)?);
                }
            }
        }
    }

    Ok(())
}

async fn build_data_tile_path(
    args: &ScanCtArgs,
    client: &StaticCtClient,
) -> Result<StaticCtTilePath> {
    let selector_count = usize::from(args.index.is_some())
        + usize::from(args.latest_size.is_some())
        + usize::from(args.latest);

    if selector_count > 1 {
        return Err(anyhow!(
            "use only one of --index, --latest-size, or --latest"
        ));
    }

    if (args.latest || selector_count == 0) && args.width.is_some() {
        return Err(anyhow!("--width requires --index"));
    }

    if let Some(tree_size) = args.latest_size {
        if args.width.is_some() {
            return Err(anyhow!("--latest-size cannot be combined with --width"));
        }

        return latest_data_tile_for_size(tree_size)?
            .ok_or_else(|| anyhow!("tree size does not contain a data tile"));
    }

    if args.latest || selector_count == 0 {
        let checkpoint = client.fetch_checkpoint().await?;
        return latest_data_tile_for_size(checkpoint.size)?
            .ok_or_else(|| anyhow!("checkpoint tree size does not contain a data tile"));
    }

    let index = args
        .index
        .ok_or_else(|| anyhow!("--index is required when using --width"))?;
    Ok(StaticCtTilePath::data(index, args.width)?)
}

fn scan_message(alert_count: usize, finding_count: usize) -> String {
    if alert_count > 0 {
        format!("{alert_count} grouped alerts produced")
    } else if finding_count > 0 {
        format!("{finding_count} findings produced")
    } else {
        "No matching alerts for current rules".to_string()
    }
}

fn print_summary_human(summary: &ScanCtSummary) {
    println!("tile: {}", summary.tile.path);
    println!("url: {}", summary.tile.url);
    println!("byte_len: {}", summary.tile.byte_len);
    println!("entries: {}", summary.entry_count);
    println!("events: {}", summary.event_count);
    println!("parse_errors: {}", summary.parse_error_count);
    println!("findings: {}", summary.finding_count);
    println!("alerts: {}", summary.alert_count);
    println!("message: {}", summary.message);
}
