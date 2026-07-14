use anyhow::Result;
use cerberus_core::{AlertSink, DomainAlert, Finding, SlackSink, WebhookPayload, WebhookSink};

pub async fn send_findings(
    url: Option<&str>,
    signing_secret: Option<&str>,
    findings: &[Finding],
) -> Result<()> {
    let Some(url) = url else {
        return Ok(());
    };

    let payload = WebhookPayload::findings(findings.to_vec());
    if payload.is_empty() {
        return Ok(());
    }

    tracing::info!(url = %redact_url(url), count = payload.count(), "sending webhook findings payload");
    WebhookSink::try_new(url)?
        .with_signing_secret(signing_secret)
        .send_payload(&payload)
        .await?;
    Ok(())
}

pub async fn send_payload(
    url: Option<&str>,
    signing_secret: Option<&str>,
    payload: &WebhookPayload,
) -> Result<()> {
    let Some(url) = url else {
        return Ok(());
    };

    if payload.is_empty() {
        return Ok(());
    }

    tracing::info!(url = %redact_url(url), count = payload.count(), "sending webhook outbox payload");
    WebhookSink::try_new(url)?
        .with_signing_secret(signing_secret)
        .send_payload(payload)
        .await?;
    Ok(())
}

pub async fn send_alerts(
    url: Option<&str>,
    signing_secret: Option<&str>,
    alerts: &[DomainAlert],
) -> Result<()> {
    let Some(url) = url else {
        return Ok(());
    };

    let payload = WebhookPayload::alerts(alerts.to_vec());
    if payload.is_empty() {
        return Ok(());
    }

    tracing::info!(url = %redact_url(url), count = payload.count(), "sending webhook alerts payload");
    WebhookSink::try_new(url)?
        .with_signing_secret(signing_secret)
        .send_payload(&payload)
        .await?;
    Ok(())
}

fn redact_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(url) => format!(
            "{}://{}/[redacted]",
            url.scheme(),
            url.host_str().unwrap_or("host")
        ),
        Err(_) => "[redacted]".to_string(),
    }
}

pub async fn send_findings_to_slack(url: Option<&str>, findings: &[Finding]) -> Result<()> {
    let Some(url) = url else {
        return Ok(());
    };

    if findings.is_empty() {
        return Ok(());
    }

    tracing::info!(url = %redact_url(url), count = findings.len(), "sending Slack findings payloads");
    let sink = SlackSink::try_new(url)?;
    for finding in findings {
        sink.send(finding).await?;
    }
    Ok(())
}

pub async fn send_alerts_to_slack(url: Option<&str>, alerts: &[DomainAlert]) -> Result<()> {
    let Some(url) = url else {
        return Ok(());
    };

    let findings = alerts
        .iter()
        .flat_map(|alert| alert.findings.iter())
        .collect::<Vec<_>>();

    if findings.is_empty() {
        return Ok(());
    }

    tracing::info!(url = %redact_url(url), count = findings.len(), "sending Slack alert findings");
    let sink = SlackSink::try_new(url)?;
    for finding in findings {
        sink.send(finding).await?;
    }
    Ok(())
}

pub async fn send_payload_to_slack(url: Option<&str>, payload: &WebhookPayload) -> Result<()> {
    match payload {
        WebhookPayload::Findings { findings, .. } => send_findings_to_slack(url, findings).await,
        WebhookPayload::Alerts { alerts, .. } => send_alerts_to_slack(url, alerts).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_query_string_and_secret_path() {
        assert_eq!(
            redact_url("https://example.com/hook?token=secret"),
            "https://example.com/[redacted]"
        );
    }
}
