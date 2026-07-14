use async_trait::async_trait;

use crate::ct::source::CtSource;
use crate::ct::static_ct::checkpoint::{StaticCtCheckpoint, TrustedCtLog};
use crate::ct::static_ct::client::StaticCtClient;
use crate::ct::static_ct::decoder::{
    decode_static_ct_data_tile, decoded_entries_to_certificate_events,
    verify_entries_against_level_zero_hashes,
};
use crate::ct::static_ct::tiles::latest_data_tile_for_size;
use crate::error::{CerberusError, Result};
use crate::event::CertificateEvent;

#[derive(Debug, Clone)]
pub struct StaticCtSource {
    pub client: StaticCtClient,
    last_checkpoint: Option<StaticCtCheckpoint>,
    next_entry_index: Option<u64>,
}

impl StaticCtSource {
    pub fn with_trusted_log(trusted_log: TrustedCtLog) -> Result<Self> {
        Ok(Self {
            client: StaticCtClient::with_trusted_log(trusted_log)?,
            last_checkpoint: None,
            next_entry_index: None,
        })
    }

    pub fn try_new_untrusted(base_url: impl Into<String>) -> Result<Self> {
        Ok(Self {
            client: StaticCtClient::try_new(base_url)?,
            last_checkpoint: None,
            next_entry_index: None,
        })
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
        self.client.verify_checkpoint_tree(&checkpoint).await?;
        let path = latest_data_tile_for_size(checkpoint.size)?.ok_or_else(|| {
            CerberusError::CtSource("Static CT checkpoint has no data tile".to_string())
        })?;
        let tile = self.client.fetch_tile(path).await?;
        let entries = decode_static_ct_data_tile(&tile)?;
        let level_zero_hashes = self
            .client
            .fetch_level_zero_hashes_for_data_tile(&tile.path, checkpoint.size)
            .await?;
        verify_entries_against_level_zero_hashes(&entries, &level_zero_hashes)?;
        let first_entry_index = self
            .next_entry_index
            .unwrap_or_else(|| entries.first().map(|entry| entry.index).unwrap_or_default());
        let last_entry_index = entries.last().map(|entry| entry.index);
        let entries = entries
            .into_iter()
            .filter(|entry| entry.index >= first_entry_index)
            .collect::<Vec<_>>();
        let decoded = decoded_entries_to_certificate_events(&entries, checkpoint.origin.clone());

        if let Some(last_entry_index) = last_entry_index {
            self.next_entry_index = Some(last_entry_index.saturating_add(1));
        }

        if decoded.event_count == 0 && decoded.parse_error_count > 0 {
            return Err(CerberusError::CtSource(format!(
                "Static CT decoded {} entries but no certificates parsed successfully",
                decoded.entry_count
            )));
        }

        Ok(decoded.events)
    }
}
