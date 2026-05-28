pub mod enrichment;
pub mod fetch_checkpoint;
pub mod fetch_events;
pub mod fetch_tile;
pub mod scan_ct;
pub mod scan_domain;
pub mod validate_config;
pub mod watch;
pub mod watch_ct;
pub mod webhook;

use std::path::Path;

use anyhow::Result;
use cerberus_core::CerberusConfig;

pub fn load_config(path: Option<&Path>) -> Result<CerberusConfig> {
    match path {
        Some(path) => Ok(CerberusConfig::from_yaml_file(path)?),
        None => Ok(CerberusConfig::default()),
    }
}

pub fn apply_rule_overrides(
    config: &mut CerberusConfig,
    min_score: Option<u8>,
    allowlist_suffixes: &[String],
) {
    config.apply_runtime_rule_overrides(min_score, allowlist_suffixes);
}
