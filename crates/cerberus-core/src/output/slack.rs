use async_trait::async_trait;
use serde::Serialize;
use std::fmt;
use std::time::Duration;

use crate::error::{CerberusError, Result};
use crate::finding::Finding;
use crate::output::sink::AlertSink;

#[derive(Clone)]
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
        Self::try_new(webhook_url).expect("Slack webhook URL must be a valid HTTP(S) URL")
    }

    pub fn try_new(webhook_url: impl Into<String>) -> Result<Self> {
        let webhook_url = webhook_url.into();
        validate_webhook_url(&webhook_url)?;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            webhook_url,
            client,
        })
    }
}

impl fmt::Debug for SlackSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlackSink")
            .field("webhook_url", &redact_url(&self.webhook_url))
            .finish_non_exhaustive()
    }
}

fn validate_webhook_url(value: &str) -> Result<()> {
    let url = url::Url::parse(value)
        .map_err(|error| CerberusError::Output(format!("Slack webhook URL is invalid: {error}")))?;
    match url.scheme() {
        "http" | "https" => Ok(()),
        scheme => Err(CerberusError::Output(format!(
            "Slack webhook URL uses unsupported scheme `{scheme}`"
        ))),
    }
}

fn redact_url(value: &str) -> String {
    match url::Url::parse(value) {
        Ok(url) => format!(
            "{}://{}/[redacted]",
            url.scheme(),
            url.host_str().unwrap_or("host")
        ),
        Err(_) => "[redacted]".to_string(),
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
