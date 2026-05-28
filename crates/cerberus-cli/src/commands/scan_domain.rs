use anyhow::Result;
use cerberus_core::{
    DetectionEngine, DomainAlert, DomainObservation, Finding, group_findings_by_domain,
};
use serde::Serialize;

use crate::cli::{OutputFormat, ScanDomainArgs};
use crate::commands::{apply_rule_overrides, enrichment, load_config, webhook};
use crate::display;

#[derive(Debug, Serialize)]
struct ScanDomainSummary {
    domain_count: usize,
    finding_count: usize,
    alert_count: usize,
    message: String,
}

#[derive(Debug, Serialize)]
struct ScanDomainAlertReport {
    summary: ScanDomainSummary,
    alerts: Vec<DomainAlert>,
}

#[derive(Debug, Serialize)]
struct ScanDomainFindingReport {
    summary: ScanDomainSummary,
    findings: Vec<Finding>,
}

pub async fn run(args: ScanDomainArgs) -> Result<()> {
    tracing::info!(
        domain_count = args.domains.len(),
        grouped = args.grouped,
        min_score = ?args.min_score,
        allowlist_suffix_count = args.allowlist_suffix.len(),
        dns = args.dns,
        takeover = args.takeover,
        webhook = args.webhook_url.is_some(),
        format = ?args.format,
        summary = args.summary,
        "running scan-domain command"
    );

    let mut config = load_config(args.config.as_deref())?;
    apply_rule_overrides(&mut config, args.min_score, &args.allowlist_suffix);

    let engine = DetectionEngine::default();
    let domain_count = args.domains.len();
    let observed_domains = args.domains.clone();
    let mut all_findings = Vec::new();

    for domain in &args.domains {
        tracing::debug!(domain = %domain, "scanning domain");

        let observation = DomainObservation::new(domain.clone())?;
        let findings = engine.detect_observation(&observation, &config)?;

        tracing::debug!(finding_count = findings.len(), "domain scan completed");
        all_findings.extend(findings);
    }

    enrichment::apply_enrichment(
        &mut all_findings,
        observed_domains,
        args.dns,
        args.takeover,
        &config,
    )
    .await?;

    if args.grouped {
        let alerts = group_findings_by_domain(all_findings);
        webhook::send_alerts(args.webhook_url.as_deref(), &alerts).await?;

        tracing::info!(alert_count = alerts.len(), "grouped scan completed");

        if args.summary && matches!(args.format, OutputFormat::Json) {
            let finding_count = alerts.iter().map(|alert| alert.findings.len()).sum();

            let report = ScanDomainAlertReport {
                summary: ScanDomainSummary {
                    domain_count,
                    finding_count,
                    alert_count: alerts.len(),
                    message: summary_message(alerts.len(), true),
                },
                alerts,
            };

            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            match args.format {
                OutputFormat::Human => display::print_alerts_human(&alerts),
                OutputFormat::Json => display::print_alerts_json(&alerts)?,
            }
        }
    } else {
        webhook::send_findings(args.webhook_url.as_deref(), &all_findings).await?;

        tracing::info!(finding_count = all_findings.len(), "scan completed");

        if args.summary && matches!(args.format, OutputFormat::Json) {
            let report = ScanDomainFindingReport {
                summary: ScanDomainSummary {
                    domain_count,
                    finding_count: all_findings.len(),
                    alert_count: 0,
                    message: summary_message(all_findings.len(), false),
                },
                findings: all_findings,
            };

            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            match args.format {
                OutputFormat::Human => display::print_findings_human(&all_findings),
                OutputFormat::Json => display::print_findings_json(&all_findings)?,
            }
        }
    }

    Ok(())
}

fn summary_message(count: usize, grouped: bool) -> String {
    match (count, grouped) {
        (0, true) => "No matching alerts for current rules".to_string(),
        (1, true) => "1 grouped alert produced".to_string(),
        (count, true) => format!("{count} grouped alerts produced"),
        (0, false) => "No matching findings for current rules".to_string(),
        (1, false) => "1 finding produced".to_string(),
        (count, false) => format!("{count} findings produced"),
    }
}
