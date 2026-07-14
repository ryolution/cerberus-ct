use anyhow::Result;
use cerberus_core::StaticCtClient;

use crate::cli::{FetchCheckpointArgs, OutputFormat};
use crate::display;

const UNVERIFIED_DIAGNOSTIC: &str = "unverified_diagnostic";

pub async fn run(args: FetchCheckpointArgs) -> Result<()> {
    tracing::info!(url = %args.url, format = ?args.format, "running fetch-checkpoint command");

    let client = StaticCtClient::try_new(args.url)?;
    let checkpoint = client.fetch_checkpoint().await?;

    match args.format {
        OutputFormat::Human => {
            println!("verification: {UNVERIFIED_DIAGNOSTIC}");
            display::print_checkpoint_human(&checkpoint);
        }
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "verification": UNVERIFIED_DIAGNOSTIC,
                "checkpoint": checkpoint,
            }))?
        ),
    }

    Ok(())
}
