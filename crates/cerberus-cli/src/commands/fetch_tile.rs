use anyhow::{Result, anyhow};
use cerberus_core::{
    StaticCtClient, StaticCtTileKind, StaticCtTilePath, latest_data_tile_for_size,
    latest_tree_tile_for_size,
};

use crate::cli::{FetchTileArgs, OutputFormat, TileKindArg};
use crate::display;

const UNVERIFIED_DIAGNOSTIC: &str = "unverified_diagnostic";

pub async fn run(args: FetchTileArgs) -> Result<()> {
    tracing::info!(
        url = %args.url,
        kind = ?args.kind,
        level = ?args.level,
        index = ?args.index,
        latest_size = ?args.latest_size,
        width = ?args.width,
        format = ?args.format,
        "running fetch-tile command"
    );

    let path = build_tile_path(&args)?;

    let is_data = match &path.kind {
        StaticCtTileKind::Data => true,
        StaticCtTileKind::Tree { .. } => false,
    };

    if is_data && args.level.is_some() {
        return Err(anyhow!("--level can only be used with --kind tree"));
    }

    let client = StaticCtClient::try_new(args.url)?;
    let tile = client.fetch_tile(path).await?;
    let metadata = tile.metadata()?;

    match args.format {
        OutputFormat::Human => {
            println!("verification: {UNVERIFIED_DIAGNOSTIC}");
            display::print_tile_human(&metadata);
        }
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "verification": UNVERIFIED_DIAGNOSTIC,
                "tile": metadata,
            }))?
        ),
    }

    Ok(())
}

fn build_tile_path(args: &FetchTileArgs) -> Result<StaticCtTilePath> {
    if let Some(tree_size) = args.latest_size {
        if args.index.is_some() || args.width.is_some() {
            return Err(anyhow!(
                "--latest-size cannot be combined with --index or --width"
            ));
        }

        return match args.kind {
            TileKindArg::Data => latest_data_tile_for_size(tree_size)?
                .ok_or_else(|| anyhow!("tree size does not contain a data tile")),
            TileKindArg::Tree => {
                let level = args
                    .level
                    .ok_or_else(|| anyhow!("--level is required when --kind tree is used"))?;
                latest_tree_tile_for_size(tree_size, level)?
                    .ok_or_else(|| anyhow!("tree size does not contain a tile at level {level}"))
            }
        };
    }

    let index = args
        .index
        .ok_or_else(|| anyhow!("--index is required unless --latest-size is used"))?;

    match args.kind {
        TileKindArg::Data => Ok(StaticCtTilePath::data(index, args.width)?),
        TileKindArg::Tree => {
            let level = args
                .level
                .ok_or_else(|| anyhow!("--level is required when --kind tree is used"))?;
            Ok(StaticCtTilePath::tree(level, index, args.width)?)
        }
    }
}
