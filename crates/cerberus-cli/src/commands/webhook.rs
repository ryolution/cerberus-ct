use anyhow::Result;
use cerberus_core::{DomainAlert, Finding, WebhookPayload, WebhookSink};

pub async fn send_findings(url: Option<&str>, findings: &[Finding]) -> Result<()> {
    let Some(url) = url else {
        return Ok(());
    };

    let payload = WebhookPayload::findings(findings.to_vec());
    if payload.is_empty() {
        return Ok(());
    }

    tracing::info!(url = %redact_url(url), count = payload.count(), "sending webhook findings payload");
    WebhookSink::new(url).send_payload(&payload).await?;
    Ok(())
}

pub async fn send_alerts(url: Option<&str>, alerts: &[DomainAlert]) -> Result<()> {
    let Some(url) = url else {
        return Ok(());
    };

    let payload = WebhookPayload::alerts(alerts.to_vec());
    if payload.is_empty() {
        return Ok(());
    }

    tracing::info!(url = %redact_url(url), count = payload.count(), "sending webhook alerts payload");
    WebhookSink::new(url).send_payload(&payload).await?;
    Ok(())
}

fn redact_url(url: &str) -> String {
    url.split('?').next().unwrap_or(url).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_query_string() {
        assert_eq!(
            redact_url("https://example.com/hook?token=secret"),
            "https://example.com/hook"
        );
    }
}
