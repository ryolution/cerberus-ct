use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderValue};
use ring::hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

use crate::alert::DomainAlert;
use crate::error::{CerberusError, Result};
use crate::finding::Finding;
use crate::output::sink::AlertSink;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WebhookPayload {
    Findings {
        count: usize,
        findings: Vec<Finding>,
    },
    Alerts {
        count: usize,
        alerts: Vec<DomainAlert>,
    },
}

impl WebhookPayload {
    pub fn findings(findings: Vec<Finding>) -> Self {
        Self::Findings {
            count: findings.len(),
            findings,
        }
    }

    pub fn alerts(alerts: Vec<DomainAlert>) -> Self {
        Self::Alerts {
            count: alerts.len(),
            alerts,
        }
    }

    pub fn count(&self) -> usize {
        match self {
            Self::Findings { count, .. } => *count,
            Self::Alerts { count, .. } => *count,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }
}

#[derive(Clone)]
pub struct WebhookSink {
    pub url: String,
    client: reqwest::Client,
    signing_secret: Option<String>,
}

impl WebhookSink {
    pub fn new(url: impl Into<String>) -> Self {
        Self::try_new(url).expect("webhook URL must be a valid HTTP(S) URL")
    }

    pub fn try_new(url: impl Into<String>) -> Result<Self> {
        let url = url.into();
        validate_webhook_url(&url)?;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            url,
            client,
            signing_secret: None,
        })
    }

    pub fn with_signing_secret(mut self, signing_secret: Option<&str>) -> Self {
        self.signing_secret = signing_secret
            .map(str::trim)
            .filter(|secret| !secret.is_empty())
            .map(ToOwned::to_owned);
        self
    }

    pub async fn send_payload(&self, payload: &WebhookPayload) -> Result<()> {
        let payload_bytes = serde_json::to_vec(payload)?;
        let idempotency_key = hex::encode(Sha256::digest(&payload_bytes));
        let mut headers = HeaderMap::new();
        headers.insert(
            "Idempotency-Key",
            HeaderValue::from_str(&idempotency_key).map_err(|error| {
                CerberusError::Output(format!("failed to build idempotency header: {error}"))
            })?,
        );
        add_signature_headers(&mut headers, self.signing_secret.as_deref(), &payload_bytes)?;

        let mut attempt = 0usize;
        loop {
            let response = self
                .client
                .post(&self.url)
                .headers(headers.clone())
                .header("Content-Type", "application/json")
                .body(payload_bytes.clone())
                .send()
                .await;

            match response {
                Ok(response) if is_retryable_status(response.status()) && attempt < 2 => {
                    sleep(retry_delay(attempt)).await;
                }
                Ok(response) => {
                    response.error_for_status()?;
                    return Ok(());
                }
                Err(error) if is_retryable_error(&error) && attempt < 2 => {
                    sleep(retry_delay(attempt)).await;
                }
                Err(error) => return Err(error.into()),
            }

            attempt += 1;
        }
    }
}

impl fmt::Debug for WebhookSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookSink")
            .field("url", &redact_url(&self.url))
            .finish_non_exhaustive()
    }
}

fn validate_webhook_url(value: &str) -> Result<()> {
    let url = url::Url::parse(value)
        .map_err(|error| CerberusError::Output(format!("webhook URL is invalid: {error}")))?;
    match url.scheme() {
        "http" | "https" => Ok(()),
        scheme => Err(CerberusError::Output(format!(
            "webhook URL uses unsupported scheme `{scheme}`"
        ))),
    }
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn is_retryable_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect()
}

fn retry_delay(attempt: usize) -> Duration {
    Duration::from_millis(250u64.saturating_mul(1u64 << attempt.min(4)))
}

fn add_signature_headers(
    headers: &mut HeaderMap,
    signing_secret: Option<&str>,
    payload_bytes: &[u8],
) -> Result<()> {
    let Some(signing_secret) = signing_secret else {
        return Ok(());
    };

    let timestamp = unix_now().to_string();
    let signature = webhook_signature(signing_secret, &timestamp, payload_bytes);
    headers.insert(
        "X-Cerberus-Timestamp",
        HeaderValue::from_str(&timestamp).map_err(|error| {
            CerberusError::Output(format!("failed to build webhook timestamp header: {error}"))
        })?,
    );
    headers.insert(
        "X-Cerberus-Signature",
        HeaderValue::from_str(&signature).map_err(|error| {
            CerberusError::Output(format!("failed to build webhook signature header: {error}"))
        })?,
    );

    Ok(())
}

fn webhook_signature(signing_secret: &str, timestamp: &str, payload_bytes: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, signing_secret.as_bytes());
    let mut message = Vec::with_capacity(timestamp.len() + 1 + payload_bytes.len());
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b'.');
    message.extend_from_slice(payload_bytes);
    let signature = hmac::sign(&key, &message);
    format!("sha256={}", hex::encode(signature.as_ref()))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
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
impl AlertSink for WebhookSink {
    async fn send(&self, finding: &Finding) -> Result<()> {
        self.send_payload(&WebhookPayload::findings(vec![finding.clone()]))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};

    #[test]
    fn serializes_finding_payload() {
        let payload = WebhookPayload::findings(vec![Finding::new(
            "paypa1-login.com",
            "keyword",
            Severity::Low,
            30,
        )]);

        let value = serde_json::to_value(payload).unwrap();

        assert_eq!(value["kind"], "findings");
        assert_eq!(value["count"], 1);
        assert_eq!(value["findings"][0]["domain"], "paypa1-login.com");
    }

    #[test]
    fn serializes_alert_payload() {
        let finding = Finding::new("paypa1-login.com", "keyword", Severity::Low, 30);
        let alert = DomainAlert::from_findings("paypa1-login.com", vec![finding]).unwrap();
        let payload = WebhookPayload::alerts(vec![alert]);
        let value = serde_json::to_value(payload).unwrap();

        assert_eq!(value["kind"], "alerts");
        assert_eq!(value["count"], 1);
        assert_eq!(value["alerts"][0]["domain"], "paypa1-login.com");
    }

    #[test]
    fn signs_payload_with_timestamp() {
        let signature = webhook_signature("secret", "1700000000", br#"{"count":1}"#);

        assert!(signature.starts_with("sha256="));
        assert_eq!(signature.len(), "sha256=".len() + 64);
        assert_ne!(
            signature,
            webhook_signature("secret", "1700000001", br#"{"count":1}"#)
        );
    }
}
