use anyhow::Result;

use crate::cli::ValidateConfigArgs;
use crate::commands::load_config;

pub async fn run(args: ValidateConfigArgs) -> Result<()> {
    tracing::info!(config = %args.config.display(), "validating configuration");

    let config = load_config(Some(args.config.as_path()))?;

    println!("configuration is valid");
    println!("brands: {}", config.brands.len());
    println!("official domains: {}", config.official_domains.len());
    println!("keywords: {}", config.keywords.len());
    println!("allowlist entries: {}", config.allowlist.len());

    tracing::info!("configuration validation completed");

    Ok(())
}
