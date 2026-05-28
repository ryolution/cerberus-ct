use anyhow::{Result, anyhow};
use cerberus_core::{
    CertificateEvent, StaticCtClient, StaticCtEntryParseError, StaticCtTileMetadata,
    StaticCtTilePath, decode_static_ct_data_tile, decoded_entries_to_certificate_events,
    latest_data_tile_for_size,
};
use serde::Serialize;

use crate::cli::{FetchEventsArgs, OutputFormat};

#[derive(Debug, Serialize)]
struct FetchEventsReport {
    tile: StaticCtTileMetadata,
    entry_count: usize,
    event_count: usize,
    parse_error_count: usize,
    returned_event_count: usize,
    returned_parse_error_count: usize,
    events: Vec<CertificateEvent>,
    parse_errors: Vec<StaticCtEntryParseError>,
}

pub async fn run(args: FetchEventsArgs) -> Result<()> {
    tracing::info!(
        url = %args.url,
        index = ?args.index,
        latest_size = ?args.latest_size,
        width = ?args.width,
        limit = args.limit,
        format = ?args.format,
        "running fetch-events command"
    );

    let path = build_data_tile_path(&args)?;
    let client = StaticCtClient::new(args.url);
    let source_log = client.monitoring_base_url();
    let tile = client.fetch_tile(path).await?;
    let metadata = tile.metadata()?;
    let entries = decode_static_ct_data_tile(&tile)?;
    let decoded = decoded_entries_to_certificate_events(&entries, source_log);
    let entry_count = decoded.entry_count;
    let event_count = decoded.event_count;
    let parse_error_count = decoded.parse_error_count;

    let events: Vec<CertificateEvent> = decoded.events.into_iter().take(args.limit).collect();
    let parse_errors: Vec<StaticCtEntryParseError> =
        decoded.parse_errors.into_iter().take(args.limit).collect();

    let report = FetchEventsReport {
        tile: metadata,
        entry_count,
        event_count,
        parse_error_count,
        returned_event_count: events.len(),
        returned_parse_error_count: parse_errors.len(),
        events,
        parse_errors,
    };

    match args.format {
        OutputFormat::Human => print_report_human(&report),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }

    Ok(())
}

fn build_data_tile_path(args: &FetchEventsArgs) -> Result<StaticCtTilePath> {
    if let Some(tree_size) = args.latest_size {
        if args.index.is_some() || args.width.is_some() {
            return Err(anyhow!(
                "--latest-size cannot be combined with --index or --width"
            ));
        }

        return latest_data_tile_for_size(tree_size)?
            .ok_or_else(|| anyhow!("tree size does not contain a data tile"));
    }

    let index = args
        .index
        .ok_or_else(|| anyhow!("--index is required unless --latest-size is used"))?;

    Ok(StaticCtTilePath::data(index, args.width)?)
}

fn print_report_human(report: &FetchEventsReport) {
    println!("tile: {}", report.tile.path);
    println!("url: {}", report.tile.url);
    println!("byte_len: {}", report.tile.byte_len);
    println!("entries: {}", report.entry_count);
    println!("events: {}", report.event_count);
    println!("parse_errors: {}", report.parse_error_count);
    println!("returned_events: {}", report.returned_event_count);

    for event in &report.events {
        let domains = event
            .domains
            .iter()
            .map(|domain| domain.as_str())
            .collect::<Vec<_>>()
            .join(",");

        println!(
            "event index={} domains={}",
            event
                .index
                .map(|index| index.to_string())
                .unwrap_or_else(|| "none".to_string()),
            domains
        );
    }

    for error in &report.parse_errors {
        println!("parse_error index={} error={}", error.index, error.error);
    }
}
