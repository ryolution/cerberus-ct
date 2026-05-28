use async_trait::async_trait;
use serde::Serialize;

use crate::error::Result;
use crate::finding::Finding;
use crate::output::sink::AlertSink;

#[derive(Debug, Clone)]
pub struct SlackSink {
    pub webhook_url: String,
    client: reqwest::Client,
}

#[derive(Debug, Serialize)]
struct SlackPayload {
    text: String,
}

impl SlackSink {
    pub fn new(webhook_url: impl Into<String>) -> Self {
        Self {
            webhook_url: webhook_url.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl AlertSink for SlackSink {
    async fn send(&self, finding: &Finding) -> Result<()> {
        let payload = SlackPayload {
            text: format!(
                "Cerberus alert: {} severity={:?} score={} detector={}",
                finding.domain, finding.severity, finding.score, finding.detector
            ),
        };

        self.client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}
