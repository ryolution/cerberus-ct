use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::alert::DomainAlert;
use crate::error::Result;
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

#[derive(Debug, Clone)]
pub struct WebhookSink {
    pub url: String,
    client: reqwest::Client,
}

impl WebhookSink {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn send_payload(&self, payload: &WebhookPayload) -> Result<()> {
        self.client
            .post(&self.url)
            .json(payload)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
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
}
