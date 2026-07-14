use anyhow::{Result, bail};
use cerberus_core::{DetectionEngine, MockCtSource, ct::CtSource, group_findings_by_domain};
use tokio::time::{Duration, sleep};

use crate::cli::{OutputFormat, WatchArgs};
use crate::commands::{apply_rule_overrides, enrichment, load_config, webhook};
use crate::display;

pub async fn run(args: WatchArgs) -> Result<()> {
    tracing::info!(mock = args.mock, once = args.once, grouped = args.grouped, min_score = ?args.min_score, allowlist_suffix_count = args.allowlist_suffixes.len(), dns = args.dns, takeover = args.takeover, webhook = args.webhook_url.is_some(), interval_ms = args.interval_ms, format = ?args.format, "running watch command");

    if !args.mock {
        bail!(
            "mock watch mode supports only --mock. Use watch-ct for persistent real Static CT monitoring or scan-ct for one-shot scanning."
        );
    }

    if args.interval_ms == 0 {
        bail!("--interval-ms must be greater than zero");
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
    let mut source = MockCtSource::demo()?;

    loop {
        let batch = source.next_batch().await?;
        tracing::debug!(event_count = batch.len(), "received CT event batch");

        if batch.is_empty() {
            if args.once {
                break;
            }
            sleep(Duration::from_millis(args.interval_ms)).await;
            continue;
        }

        let mut findings = Vec::new();
        let mut observed_domains = Vec::new();
        for event in batch {
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
            let alerts = group_findings_by_domain(findings)
                .into_iter()
                .filter(|alert| config.should_keep_alert(alert.score))
                .collect::<Vec<_>>();
            webhook::send_alerts(webhook_url, webhook_signing_secret, &alerts).await?;
            webhook::send_alerts_to_slack(slack_webhook_url, &alerts).await?;
            tracing::info!(alert_count = alerts.len(), "grouped watch batch completed");
            match args.format {
                OutputFormat::Human => display::print_alerts_human(&alerts),
                OutputFormat::Json => display::print_alerts_json(&alerts)?,
            }
        } else {
            webhook::send_findings(webhook_url, webhook_signing_secret, &findings).await?;
            webhook::send_findings_to_slack(slack_webhook_url, &findings).await?;
            tracing::info!(finding_count = findings.len(), "watch batch completed");
            match args.format {
                OutputFormat::Human => display::print_findings_human(&findings),
                OutputFormat::Json => display::print_findings_json(&findings)?,
            }
        }

        if args.once {
            break;
        }

        sleep(Duration::from_millis(args.interval_ms)).await;
    }

    Ok(())
}
