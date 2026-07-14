use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "cerberus")]
#[command(version, about = "Static CT phishing and brand-abuse detection engine")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    ScanDomain(ScanDomainArgs),

    ValidateConfig(ValidateConfigArgs),

    DemoWatch(WatchArgs),

    #[command(hide = true)]
    Watch(WatchArgs),

    FetchCheckpoint(FetchCheckpointArgs),

    FetchTile(FetchTileArgs),

    FetchEvents(FetchEventsArgs),

    ScanCt(ScanCtArgs),

    WatchCt(WatchCtArgs),
}

#[derive(Debug, Args)]
pub struct ScanDomainArgs {
    pub domains: Vec<String>,

    #[arg(long)]
    pub config: Option<PathBuf>,

    #[arg(long, default_value = "human")]
    pub format: OutputFormat,

    #[arg(long)]
    pub grouped: bool,

    #[arg(long)]
    pub summary: bool,

    #[arg(long)]
    pub dns: bool,

    #[arg(long)]
    pub takeover: bool,

    #[arg(long, env = "CERBERUS_WEBHOOK_URL")]
    pub webhook_url: Option<String>,

    #[arg(long)]
    pub min_score: Option<u8>,

    #[arg(long)]
    pub allowlist_suffix: Vec<String>,
}

#[derive(Debug, Args)]
pub struct ValidateConfigArgs {
    #[arg(short, long, env = "CERBERUS_CONFIG")]
    pub config: PathBuf,
}

#[derive(Debug, Args)]
pub struct FetchCheckpointArgs {
    pub url: String,

    #[arg(short, long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct FetchTileArgs {
    pub url: String,

    #[arg(long, value_enum, default_value_t = TileKindArg::Data)]
    pub kind: TileKindArg,

    #[arg(long)]
    pub level: Option<u8>,

    #[arg(long)]
    pub index: Option<u64>,

    #[arg(long)]
    pub latest_size: Option<u64>,

    #[arg(long)]
    pub width: Option<u8>,

    #[arg(short, long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct FetchEventsArgs {
    pub url: String,

    #[arg(long)]
    pub index: Option<u64>,

    #[arg(long)]
    pub latest_size: Option<u64>,

    #[arg(long)]
    pub width: Option<u8>,

    #[arg(long, default_value_t = 10)]
    pub limit: usize,

    #[arg(short, long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct ScanCtArgs {
    pub url: String,

    #[arg(short, long, env = "CERBERUS_CONFIG")]
    pub config: Option<PathBuf>,

    #[arg(long)]
    pub index: Option<u64>,

    #[arg(long)]
    pub latest_size: Option<u64>,

    #[arg(long)]
    pub latest: bool,

    #[arg(long)]
    pub width: Option<u8>,

    #[arg(short, long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    #[arg(long)]
    pub grouped: bool,

    #[arg(long)]
    pub min_score: Option<u8>,

    #[arg(long = "allowlist-suffix")]
    pub allowlist_suffixes: Vec<String>,

    #[arg(long)]
    pub summary: bool,

    #[arg(long)]
    pub dns: bool,

    #[arg(long)]
    pub takeover: bool,

    #[arg(long, env = "CERBERUS_WEBHOOK_URL")]
    pub webhook_url: Option<String>,
}

#[derive(Debug, Args)]
pub struct WatchCtArgs {
    pub url: String,

    #[arg(short, long, env = "CERBERUS_CONFIG")]
    pub config: Option<PathBuf>,

    #[arg(long, default_value = ".cerberus/state.json")]
    pub state: PathBuf,

    #[arg(long)]
    pub once: bool,

    #[arg(long, default_value_t = 30000)]
    pub interval_ms: u64,

    #[arg(long, default_value_t = 1)]
    pub max_tiles: u64,

    #[arg(long)]
    pub seed_index: Option<u64>,

    #[arg(long)]
    pub reset_state: bool,

    #[arg(short, long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    #[arg(long)]
    pub grouped: bool,

    #[arg(long)]
    pub min_score: Option<u8>,

    #[arg(long = "allowlist-suffix")]
    pub allowlist_suffixes: Vec<String>,

    #[arg(long)]
    pub summary: bool,

    #[arg(long)]
    pub dns: bool,

    #[arg(long)]
    pub takeover: bool,

    #[arg(long, env = "CERBERUS_WEBHOOK_URL")]
    pub webhook_url: Option<String>,
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    #[arg(short, long, env = "CERBERUS_CONFIG")]
    pub config: Option<PathBuf>,

    #[arg(long)]
    pub mock: bool,

    #[arg(long)]
    pub once: bool,

    #[arg(long, default_value_t = 1000)]
    pub interval_ms: u64,

    #[arg(short, long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    #[arg(long)]
    pub grouped: bool,

    #[arg(long)]
    pub min_score: Option<u8>,

    #[arg(long = "allowlist-suffix")]
    pub allowlist_suffixes: Vec<String>,

    #[arg(long)]
    pub dns: bool,

    #[arg(long)]
    pub takeover: bool,

    #[arg(long, env = "CERBERUS_WEBHOOK_URL")]
    pub webhook_url: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TileKindArg {
    Data,
    Tree,
}
