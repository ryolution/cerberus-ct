use anyhow::Result;
use cerberus_core::StaticCtClient;

use crate::cli::{FetchCheckpointArgs, OutputFormat};
use crate::display;

pub async fn run(args: FetchCheckpointArgs) -> Result<()> {
    tracing::info!(url = %args.url, format = ?args.format, "running fetch-checkpoint command");

    let client = StaticCtClient::new(args.url);
    let checkpoint = client.fetch_checkpoint().await?;

    match args.format {
        OutputFormat::Human => display::print_checkpoint_human(&checkpoint),
        OutputFormat::Json => display::print_checkpoint_json(&checkpoint)?,
    }

    Ok(())
}
