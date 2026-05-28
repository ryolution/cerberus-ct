use anyhow::Result;
use cerberus_core::{
    CerberusConfig, Finding, enrich_findings_with_dns, enrich_findings_with_dns_and_takeover,
};

pub async fn apply_enrichment(
    findings: &mut Vec<Finding>,
    observed_domains: Vec<String>,
    dns: bool,
    takeover: bool,
    config: &CerberusConfig,
) -> Result<()> {
    let takeover_enabled = takeover || config.dns.takeover;
    let dns_enabled = dns || config.dns.enabled || takeover_enabled;
    let observed_domains = observed_domains
        .into_iter()
        .filter(|domain| !config.is_allowed(domain))
        .collect::<Vec<_>>();

    if takeover_enabled {
        let enrichments = enrich_findings_with_dns_and_takeover(findings, observed_domains).await?;
        tracing::info!(
            dns_enrichment_count = enrichments.len(),
            takeover = true,
            "DNS takeover enrichment completed"
        );
    } else if dns_enabled {
        let enrichments = enrich_findings_with_dns(findings).await?;
        tracing::info!(
            dns_enrichment_count = enrichments.len(),
            takeover = false,
            "DNS enrichment completed"
        );
    }

    findings.retain(|finding| config.should_keep_finding(finding.score));

    Ok(())
}
