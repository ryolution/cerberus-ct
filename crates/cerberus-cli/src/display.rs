use anyhow::Result;
use cerberus_core::{DomainAlert, Finding, StaticCtCheckpoint, StaticCtTileMetadata};

pub fn print_findings_json(findings: &[Finding]) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(findings)?);
    Ok(())
}

pub fn print_alerts_json(alerts: &[DomainAlert]) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(alerts)?);
    Ok(())
}

pub fn print_findings_human(findings: &[Finding]) {
    if findings.is_empty() {
        println!("No findings.");
        return;
    }

    for finding in findings {
        println!(
            "{} [{}] score={} detector={}",
            finding.domain,
            format!("{:?}", finding.severity).to_lowercase(),
            finding.score,
            finding.detector
        );

        for reason in &finding.reasons {
            println!("  - {reason}");
        }
    }
}

pub fn print_alerts_human(alerts: &[DomainAlert]) {
    if alerts.is_empty() {
        println!("No alerts.");
        return;
    }

    for alert in alerts {
        println!(
            "{} [{}] score={} detectors={}",
            alert.domain,
            format!("{:?}", alert.severity).to_lowercase(),
            alert.score,
            alert.detectors.join(",")
        );

        for reason in &alert.reasons {
            println!("  - {reason}");
        }
    }
}

pub fn print_checkpoint_json(checkpoint: &StaticCtCheckpoint) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(checkpoint)?);
    Ok(())
}

pub fn print_checkpoint_human(checkpoint: &StaticCtCheckpoint) {
    println!("origin: {}", checkpoint.origin);
    println!("size: {}", checkpoint.size);
    println!("root_hash: {}", checkpoint.root_hash);
    println!("signatures: {}", checkpoint.signatures.len());
}

pub fn print_tile_json(tile: &StaticCtTileMetadata) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(tile)?);
    Ok(())
}

pub fn print_tile_human(tile: &StaticCtTileMetadata) {
    println!("kind: {}", tile.kind);
    if let Some(level) = tile.level {
        println!("level: {}", level);
    }
    println!("index: {}", tile.index);
    if let Some(width) = tile.width {
        println!("width: {}", width);
    }
    println!("path: {}", tile.path);
    println!("url: {}", tile.url);
    println!("byte_len: {}", tile.byte_len);
}
