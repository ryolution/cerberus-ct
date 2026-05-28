use reqwest::header::{ACCEPT, ACCEPT_ENCODING, USER_AGENT};

use crate::ct::static_ct::checkpoint::{StaticCtCheckpoint, parse_static_ct_checkpoint};
use crate::ct::static_ct::tiles::{StaticCtTile, StaticCtTilePath};
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct StaticCtClient {
    base_url: String,
    client: reqwest::Client,
}

impl StaticCtClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
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

        let text = self
            .client
            .get(url)
            .header(USER_AGENT, "cerberus-ct/0.8")
            .header(ACCEPT, "text/plain,*/*")
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        Ok(text)
    }

    pub async fn fetch_checkpoint(&self) -> Result<StaticCtCheckpoint> {
        let text = self.fetch_checkpoint_text().await?;
        let checkpoint = parse_static_ct_checkpoint(&text)?;

        tracing::info!(
            origin = %checkpoint.origin,
            size = checkpoint.size,
            signature_count = checkpoint.signatures.len(),
            "Static CT checkpoint parsed"
        );

        Ok(checkpoint)
    }

    pub async fn fetch_tile(&self, path: StaticCtTilePath) -> Result<StaticCtTile> {
        let url = self.tile_url(&path)?;
        tracing::info!(url = %url, "fetching Static CT tile");

        let bytes = self
            .client
            .get(&url)
            .header(USER_AGENT, "cerberus-ct/0.8")
            .header(ACCEPT, "application/octet-stream,*/*")
            .header(ACCEPT_ENCODING, "gzip, identity")
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?
            .to_vec();

        tracing::info!(url = %url, byte_len = bytes.len(), "Static CT tile fetched");

        Ok(StaticCtTile { path, url, bytes })
    }
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
