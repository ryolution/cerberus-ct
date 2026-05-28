use async_trait::async_trait;

use crate::ct::source::CtSource;
use crate::ct::static_ct::checkpoint::StaticCtCheckpoint;
use crate::ct::static_ct::client::StaticCtClient;
use crate::ct::static_ct::decoder::{
    decode_static_ct_data_tile, decoded_entries_to_certificate_events,
};
use crate::ct::static_ct::tiles::latest_data_tile_for_size;
use crate::error::{CerberusError, Result};
use crate::event::CertificateEvent;

#[derive(Debug, Clone)]
pub struct StaticCtSource {
    pub client: StaticCtClient,
    last_checkpoint: Option<StaticCtCheckpoint>,
}

impl StaticCtSource {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: StaticCtClient::new(base_url),
            last_checkpoint: None,
        }
    }

    pub async fn fetch_checkpoint(&mut self) -> Result<StaticCtCheckpoint> {
        let checkpoint = self.client.fetch_checkpoint().await?;
        self.last_checkpoint = Some(checkpoint.clone());
        Ok(checkpoint)
    }

    pub fn last_checkpoint(&self) -> Option<&StaticCtCheckpoint> {
        self.last_checkpoint.as_ref()
    }
}

#[async_trait]
impl CtSource for StaticCtSource {
    async fn next_batch(&mut self) -> Result<Vec<CertificateEvent>> {
        let checkpoint = self.fetch_checkpoint().await?;
        let path = latest_data_tile_for_size(checkpoint.size)?.ok_or_else(|| {
            CerberusError::CtSource("Static CT checkpoint has no data tile".to_string())
        })?;
        let tile = self.client.fetch_tile(path).await?;
        let entries = decode_static_ct_data_tile(&tile)?;
        let decoded = decoded_entries_to_certificate_events(&entries, checkpoint.origin.clone());

        if decoded.event_count == 0 && decoded.parse_error_count > 0 {
            return Err(CerberusError::CtSource(format!(
                "Static CT decoded {} entries but no certificates parsed successfully",
                decoded.entry_count
            )));
        }

        Ok(decoded.events)
    }
}
