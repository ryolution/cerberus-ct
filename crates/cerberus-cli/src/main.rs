mod cli;
mod commands;
mod display;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();

    match cli.command {
        Commands::ScanDomain(args) => commands::scan_domain::run(args).await,
        Commands::ValidateConfig(args) => commands::validate_config::run(args).await,
        Commands::Watch(args) => commands::watch::run(args).await,
        Commands::FetchCheckpoint(args) => commands::fetch_checkpoint::run(args).await,
        Commands::FetchTile(args) => commands::fetch_tile::run(args).await,
        Commands::FetchEvents(args) => commands::fetch_events::run(args).await,
        Commands::ScanCt(args) => commands::scan_ct::run(args).await,
        Commands::WatchCt(args) => commands::watch_ct::run(args).await,
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .compact()
        .init();
}
