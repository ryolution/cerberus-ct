use anyhow::Result;
use cerberus_core::{
    CerberusConfig, Finding, enrich_findings_with_dns_and_takeover_with_options,
    enrich_findings_with_dns_with_options,
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
        let enrichments = enrich_findings_with_dns_and_takeover_with_options(
            findings,
            observed_domains,
            config.dns_enrichment_options()?,
        )
        .await?;
        tracing::info!(
            dns_enrichment_count = enrichments.len(),
            takeover = true,
            "DNS takeover enrichment completed"
        );
    } else if dns_enabled {
        let enrichments =
            enrich_findings_with_dns_with_options(findings, config.dns_enrichment_options()?)
                .await?;
        tracing::info!(
            dns_enrichment_count = enrichments.len(),
            takeover = false,
            "DNS enrichment completed"
        );
    }

    findings.retain(|finding| config.should_keep_finding(finding.score));

    Ok(())
}
