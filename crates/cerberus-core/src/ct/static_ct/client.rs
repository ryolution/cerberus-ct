use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use reqwest::StatusCode;
use reqwest::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_TYPE, USER_AGENT};
use url::Url;

use crate::ct::static_ct::checkpoint::{
    StaticCtCheckpoint, TrustedCtLog, parse_static_ct_checkpoint,
};
use crate::ct::static_ct::decoder::decode_static_ct_hash_tile;
use crate::ct::static_ct::merkle::{
    MerkleHash, combine_compact_range_roots, combine_perfect_subtree_roots, empty_hash,
    highest_power_of_two_less_than_or_equal, power_subtree_level_and_count,
};
use crate::ct::static_ct::tiles::{StaticCtTile, StaticCtTilePath};
use crate::error::{CerberusError, Result};

const USER_AGENT_VALUE: &str = concat!("cerberus-ct/", env!("CARGO_PKG_VERSION"));
const CHECKPOINT_MAX_BYTES: usize = 64 * 1024;
const TILE_MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_RETRIES: usize = 2;

#[derive(Debug, Clone)]
pub struct StaticCtClient {
    base_url: String,
    client: reqwest::Client,
    trusted_log: Option<TrustedCtLog>,
}

impl StaticCtClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::try_new(base_url).expect("StaticCtClient base URL must be a valid HTTP(S) URL")
    }

    pub fn try_new(base_url: impl Into<String>) -> Result<Self> {
        Self::build(base_url.into(), None)
    }

    pub fn with_trusted_log(trusted_log: TrustedCtLog) -> Result<Self> {
        Self::build(trusted_log.base_url.as_str().to_string(), Some(trusted_log))
    }

    fn build(base_url: String, trusted_log: Option<TrustedCtLog>) -> Result<Self> {
        validate_http_url(&base_url)?;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            trusted_log,
        })
    }

    pub fn monitoring_base_url(&self) -> String {
        self.base_url
            .strip_suffix("/checkpoint")
            .unwrap_or(&self.base_url)
            .trim_end_matches('/')
            .to_string()
    }

    pub fn checkpoint_url(&self) -> String {
        if self.base_url.ends_with("/checkpoint") {
            self.base_url.clone()
        } else {
            format!("{}/checkpoint", self.monitoring_base_url())
        }
    }

    pub fn tile_url(&self, tile: &StaticCtTilePath) -> Result<String> {
        Ok(format!("{}/{}", self.monitoring_base_url(), tile.path()?))
    }

    pub async fn fetch_checkpoint_text(&self) -> Result<String> {
        let url = self.checkpoint_url();
        tracing::info!(url = %url, "fetching Static CT checkpoint");

        let response = self
            .get_with_retry(&url, "text/plain,*/*", false)
            .await?
            .error_for_status()?;
        validate_content_type(&response, &["text/plain"])?;
        let bytes = read_limited(response, CHECKPOINT_MAX_BYTES).await?;
        let text = String::from_utf8(bytes).map_err(|error| {
            CerberusError::CtSource(format!("checkpoint response is not UTF-8 text: {error}"))
        })?;

        Ok(text)
    }

    pub async fn fetch_checkpoint(&self) -> Result<StaticCtCheckpoint> {
        let text = self.fetch_checkpoint_text().await?;
        let checkpoint = parse_static_ct_checkpoint(&text)?;

        if let Some(trusted_log) = &self.trusted_log {
            trusted_log.verify_checkpoint(&checkpoint)?;
        }

        tracing::info!(
            origin = %checkpoint.origin,
            size = checkpoint.size,
            signature_count = checkpoint.signatures.len(),
            "Static CT checkpoint parsed"
        );

        Ok(checkpoint)
    }

    pub async fn fetch_tile(&self, path: StaticCtTilePath) -> Result<StaticCtTile> {
        let mut effective_path = path;
        let mut url = self.tile_url(&effective_path)?;
        tracing::info!(url = %url, "fetching Static CT tile");

        let mut response = self
            .get_with_retry(&url, "application/octet-stream,*/*", true)
            .await?;

        if response.status() == StatusCode::NOT_FOUND && effective_path.width.is_some() {
            tracing::info!(
                url = %url,
                "partial Static CT tile returned 404; retrying corresponding full tile"
            );
            effective_path.width = None;
            url = self.tile_url(&effective_path)?;
            response = self
                .get_with_retry(&url, "application/octet-stream,*/*", true)
                .await?;
        }

        let response = response.error_for_status()?;
        validate_content_type(&response, &["application/octet-stream"])?;
        let bytes = read_limited(response, TILE_MAX_BYTES).await?;

        tracing::info!(url = %url, byte_len = bytes.len(), "Static CT tile fetched");

        Ok(StaticCtTile {
            path: effective_path,
            url,
            bytes,
        })
    }

    pub async fn verify_checkpoint_tree(&self, checkpoint: &StaticCtCheckpoint) -> Result<()> {
        let expected_root = checkpoint.root_hash_bytes()?;
        let calculated_root = self.calculate_tree_root(checkpoint.size).await?;

        if calculated_root != expected_root {
            return Err(CerberusError::CtSource(format!(
                "Static CT Merkle root mismatch for checkpoint size {}",
                checkpoint.size
            )));
        }

        Ok(())
    }

    pub async fn verify_checkpoint_consistency(
        &self,
        previous_size: u64,
        previous_root_hash: Option<&str>,
        checkpoint: &StaticCtCheckpoint,
    ) -> Result<()> {
        if previous_size == 0 {
            return Ok(());
        }

        if checkpoint.size < previous_size {
            return Err(CerberusError::CtSource(format!(
                "checkpoint rollback detected: previous size {previous_size}, new size {}",
                checkpoint.size
            )));
        }

        let Some(previous_root_hash) = previous_root_hash else {
            return Ok(());
        };

        let previous_root = decode_stored_root_hash(previous_root_hash)?;

        let recalculated_previous_root = self.calculate_tree_root(previous_size).await?;
        if previous_root != recalculated_previous_root {
            return Err(CerberusError::CtSource(format!(
                "checkpoint consistency failed: previous tree size {previous_size} no longer has the stored root"
            )));
        }

        if checkpoint.size == previous_size && checkpoint.root_hash_bytes()? != previous_root {
            return Err(CerberusError::CtSource(format!(
                "checkpoint root conflict detected at tree size {previous_size}"
            )));
        }

        Ok(())
    }

    pub async fn fetch_level_zero_hashes_for_data_tile(
        &self,
        data_path: &StaticCtTilePath,
        checkpoint_size: u64,
    ) -> Result<Vec<MerkleHash>> {
        let tree_path = StaticCtTilePath::tree(
            0,
            data_path.index,
            tree_tile_width(checkpoint_size, 0, data_path.index)?,
        )?;
        let tile = self.fetch_tile(tree_path).await?;
        decode_static_ct_hash_tile(&tile)
    }

    pub async fn calculate_tree_root(&self, tree_size: u64) -> Result<MerkleHash> {
        if tree_size == 0 {
            return Ok(empty_hash());
        }

        let mut remaining = tree_size;
        let mut start = 0u64;
        let mut roots = Vec::new();

        while remaining > 0 {
            let subtree_size = highest_power_of_two_less_than_or_equal(remaining);
            roots.push(
                self.fetch_power_of_two_subtree_hash(start, subtree_size, tree_size)
                    .await?,
            );
            start = start.saturating_add(subtree_size);
            remaining -= subtree_size;
        }

        Ok(combine_compact_range_roots(&roots))
    }

    async fn fetch_power_of_two_subtree_hash(
        &self,
        start: u64,
        size: u64,
        checkpoint_size: u64,
    ) -> Result<MerkleHash> {
        let (level, count, block_size) = power_subtree_level_and_count(size)?;

        if start % block_size != 0 {
            return Err(CerberusError::CtSource(format!(
                "subtree start {start} is not aligned to level {level} block size {block_size}"
            )));
        }

        let first_hash_index = start / block_size;
        let hashes = self
            .fetch_hashes_at_level(level, first_hash_index, count, checkpoint_size)
            .await?;
        combine_perfect_subtree_roots(hashes)
    }

    async fn fetch_hashes_at_level(
        &self,
        level: u8,
        first_hash_index: u64,
        count: usize,
        checkpoint_size: u64,
    ) -> Result<Vec<MerkleHash>> {
        if count == 0 || count > 256 {
            return Err(CerberusError::CtSource(format!(
                "can only fetch 1..=256 hashes at a time, got {count}"
            )));
        }

        let tile_index = first_hash_index / 256;
        let offset = (first_hash_index % 256) as usize;
        let width = tree_tile_width(checkpoint_size, level, tile_index)?;
        let tile = self
            .fetch_tile(StaticCtTilePath::tree(level, tile_index, width)?)
            .await?;
        let hashes = decode_static_ct_hash_tile(&tile)?;

        let end = offset.checked_add(count).ok_or_else(|| {
            CerberusError::CtSource("Static CT tree tile offset overflow".to_string())
        })?;
        if end > hashes.len() {
            return Err(CerberusError::CtSource(format!(
                "Static CT tree tile level {level} index {tile_index} has {} hashes, need offset {offset} count {count}",
                hashes.len()
            )));
        }

        Ok(hashes[offset..end].to_vec())
    }

    async fn get_with_retry(
        &self,
        url: &str,
        accept: &'static str,
        accepts_gzip: bool,
    ) -> Result<reqwest::Response> {
        let mut attempt = 0usize;

        loop {
            let mut request = self
                .client
                .get(url)
                .header(USER_AGENT, USER_AGENT_VALUE)
                .header(ACCEPT, accept);

            if accepts_gzip {
                request = request.header(ACCEPT_ENCODING, "gzip, identity");
            }

            match request.send().await {
                Ok(response) if is_retryable_status(response.status()) && attempt < MAX_RETRIES => {
                    sleep_before_retry(attempt).await;
                }
                Ok(response) => return Ok(response),
                Err(error) if is_retryable_error(&error) && attempt < MAX_RETRIES => {
                    sleep_before_retry(attempt).await;
                }
                Err(error) => return Err(error.into()),
            }

            attempt += 1;
        }
    }
}

fn tree_tile_width(checkpoint_size: u64, level: u8, tile_index: u64) -> Result<Option<u8>> {
    if level > 5 {
        return Err(CerberusError::CtSource(format!(
            "Static CT tile level must be between 0 and 5: {level}"
        )));
    }

    let block_size = 256u64.pow(level as u32);
    let hash_count = checkpoint_size / block_size;

    if hash_count == 0 {
        return Err(CerberusError::CtSource(format!(
            "tree size {checkpoint_size} has no hashes at level {level}"
        )));
    }

    let partial_width = (hash_count % 256) as u8;
    let partial_tile_index = hash_count / 256;

    if partial_width != 0 && tile_index == partial_tile_index {
        Ok(Some(partial_width))
    } else {
        Ok(None)
    }
}

fn decode_stored_root_hash(input: &str) -> Result<MerkleHash> {
    if let Ok(bytes) = hex::decode(input) {
        if let Ok(hash) = bytes.try_into() {
            return Ok(hash);
        }
    }

    let bytes = STANDARD
        .decode(input)
        .or_else(|_| STANDARD_NO_PAD.decode(input))
        .map_err(|error| {
            CerberusError::CtSource(format!(
                "stored checkpoint root hash is neither 32-byte hex nor base64: {error}"
            ))
        })?;

    bytes.try_into().map_err(|bytes: Vec<u8>| {
        CerberusError::CtSource(format!(
            "stored checkpoint root hash must decode to 32 bytes, got {}",
            bytes.len()
        ))
    })
}

fn validate_http_url(url: &str) -> Result<()> {
    let url = Url::parse(url)
        .map_err(|error| CerberusError::CtSource(format!("invalid URL: {error}")))?;

    match url.scheme() {
        "http" | "https" => Ok(()),
        scheme => Err(CerberusError::CtSource(format!(
            "unsupported URL scheme `{scheme}`; expected http or https"
        ))),
    }
}

fn validate_content_type(response: &reqwest::Response, allowed: &[&str]) -> Result<()> {
    let Some(value) = response.headers().get(CONTENT_TYPE) else {
        return Ok(());
    };

    let value = value.to_str().map_err(|error| {
        CerberusError::CtSource(format!("response content-type is not valid ASCII: {error}"))
    })?;
    let media_type = value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase();

    if allowed.iter().any(|allowed| *allowed == media_type) {
        return Ok(());
    }

    Err(CerberusError::CtSource(format!(
        "unexpected response content-type `{value}`"
    )))
}

async fn read_limited(mut response: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>> {
    if let Some(content_length) = response.content_length() {
        if content_length > max_bytes as u64 {
            return Err(CerberusError::CtSource(format!(
                "response is too large: {content_length} bytes exceeds {max_bytes} byte limit"
            )));
        }
    }

    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let next_len = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| CerberusError::CtSource("response byte length overflow".to_string()))?;

        if next_len > max_bytes {
            return Err(CerberusError::CtSource(format!(
                "response is too large: {next_len} bytes exceeds {max_bytes} byte limit"
            )));
        }

        bytes.extend_from_slice(&chunk);
    }

    Ok(bytes)
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn is_retryable_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect()
}

async fn sleep_before_retry(attempt: usize) {
    let base_ms = 250u64;
    let delay_ms = base_ms.saturating_mul(1u64 << attempt.min(4));
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
}

#[cfg(test)]
mod tests {
    use super::StaticCtClient;
    use crate::ct::static_ct::tiles::StaticCtTilePath;

    #[test]
    fn builds_checkpoint_url_from_base_url() {
        let client = StaticCtClient::new("https://example.com/log/");
        assert_eq!(
            client.checkpoint_url(),
            "https://example.com/log/checkpoint"
        );
    }

    #[test]
    fn keeps_explicit_checkpoint_url() {
        let client = StaticCtClient::new("https://example.com/log/checkpoint");
        assert_eq!(
            client.checkpoint_url(),
            "https://example.com/log/checkpoint"
        );
    }

    #[test]
    fn strips_checkpoint_for_monitoring_base_url() {
        let client = StaticCtClient::new("https://example.com/log/checkpoint");
        assert_eq!(client.monitoring_base_url(), "https://example.com/log");
    }

    #[test]
    fn builds_data_tile_url() {
        let client = StaticCtClient::new("https://example.com/log/");
        let tile = StaticCtTilePath::data(1234067, None).unwrap();
        assert_eq!(
            client.tile_url(&tile).unwrap(),
            "https://example.com/log/tile/data/x001/x234/067"
        );
    }

    #[test]
    fn builds_partial_tree_tile_url() {
        let client = StaticCtClient::new("https://example.com/log/");
        let tile = StaticCtTilePath::tree(1, 273, Some(17)).unwrap();
        assert_eq!(
            client.tile_url(&tile).unwrap(),
            "https://example.com/log/tile/1/273.p/17"
        );
    }
}
