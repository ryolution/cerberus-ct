use async_trait::async_trait;
use hickory_resolver::Resolver;
use hickory_resolver::proto::rr::{RData, RecordType};
use serde::{Deserialize, Serialize};

use crate::dns::fingerprints::default_takeover_fingerprints;
use crate::dns::takeover::takeover_findings_from_enrichment;
use crate::error::{CerberusError, Result};
use crate::finding::Finding;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsEnrichment {
    pub domain: String,
    pub resolved: bool,
    pub ips: Vec<String>,
    pub cname_chain: Vec<String>,
    pub errors: Vec<String>,
}

impl DnsEnrichment {
    pub fn unresolved(domain: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            resolved: false,
            ips: Vec::new(),
            cname_chain: Vec::new(),
            errors: vec![error.into()],
        }
    }

    pub fn resolved(domain: impl Into<String>, ips: Vec<String>) -> Self {
        Self {
            domain: domain.into(),
            resolved: !ips.is_empty(),
            ips,
            cname_chain: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn with_cname_chain(mut self, cname_chain: Vec<String>) -> Self {
        self.cname_chain = cname_chain;
        self
    }

    pub fn apply_to_finding(&self, finding: &mut Finding) {
        finding.evidence.push(crate::finding::Evidence {
            kind: "dns.resolved".to_string(),
            value: self.resolved.to_string(),
        });

        if self.resolved {
            let count = self.ips.len();
            let suffix = if count == 1 { "address" } else { "addresses" };
            finding
                .reasons
                .push(format!("DNS resolved to {count} IP {suffix}"));
        } else {
            finding
                .reasons
                .push("DNS lookup did not return IP addresses".to_string());
        }

        if !self.cname_chain.is_empty() {
            let count = self.cname_chain.len();
            let suffix = if count == 1 { "target" } else { "targets" };
            finding
                .reasons
                .push(format!("DNS CNAME chain contains {count} {suffix}"));
        }

        for ip in &self.ips {
            finding.evidence.push(crate::finding::Evidence {
                kind: "dns.ip".to_string(),
                value: ip.clone(),
            });
        }

        for cname in &self.cname_chain {
            finding.evidence.push(crate::finding::Evidence {
                kind: "dns.cname".to_string(),
                value: cname.clone(),
            });
        }

        for error in &self.errors {
            finding.evidence.push(crate::finding::Evidence {
                kind: "dns.error".to_string(),
                value: error.clone(),
            });
        }
    }
}

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn enrich(&self, domain: &str) -> Result<DnsEnrichment>;
}

#[derive(Debug, Default)]
pub struct SystemDnsResolver;

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn enrich(&self, domain: &str) -> Result<DnsEnrichment> {
        let resolver = Resolver::builder_tokio()
            .map_err(|error| {
                CerberusError::Dns(format!("failed to initialize DNS resolver: {error}"))
            })?
            .build()
            .map_err(|error| {
                CerberusError::Dns(format!("failed to build DNS resolver: {error}"))
            })?;

        let cname_chain = match resolver.lookup(domain, RecordType::CNAME).await {
            Ok(lookup) => {
                let mut cnames = lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::CNAME(cname) => {
                            Some(cname.to_string().trim_end_matches('.').to_string())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                cnames.sort();
                cnames.dedup();
                cnames
            }
            Err(_) => Vec::new(),
        };

        match resolver.lookup_ip(domain).await {
            Ok(lookup) => {
                let mut ips = lookup
                    .iter()
                    .map(|addr| addr.to_string())
                    .collect::<Vec<_>>();
                ips.sort();
                ips.dedup();
                Ok(DnsEnrichment::resolved(domain.to_string(), ips).with_cname_chain(cname_chain))
            }
            Err(error) => Ok(DnsEnrichment {
                domain: domain.to_string(),
                resolved: false,
                ips: Vec::new(),
                cname_chain,
                errors: vec![error.to_string()],
            }),
        }
    }
}

#[derive(Debug, Default)]
pub struct DisabledDnsResolver;

#[async_trait]
impl DnsResolver for DisabledDnsResolver {
    async fn enrich(&self, domain: &str) -> Result<DnsEnrichment> {
        Err(CerberusError::Dns(format!(
            "DNS enrichment is disabled; cannot resolve {domain}"
        )))
    }
}

pub async fn enrich_findings_with_dns(findings: &mut [Finding]) -> Result<Vec<DnsEnrichment>> {
    enrich_findings_with_resolver(findings, &SystemDnsResolver).await
}

pub async fn enrich_findings_with_resolver(
    findings: &mut [Finding],
    resolver: &dyn DnsResolver,
) -> Result<Vec<DnsEnrichment>> {
    let mut domains = findings
        .iter()
        .map(|finding| finding.domain.clone())
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();

    let mut enrichments = Vec::new();

    for domain in domains {
        let enrichment = resolver.enrich(&domain).await?;
        for finding in findings
            .iter_mut()
            .filter(|finding| finding.domain == domain)
        {
            enrichment.apply_to_finding(finding);
        }
        enrichments.push(enrichment);
    }

    Ok(enrichments)
}

pub async fn enrich_findings_with_dns_and_takeover(
    findings: &mut Vec<Finding>,
    observed_domains: impl IntoIterator<Item = String>,
) -> Result<Vec<DnsEnrichment>> {
    enrich_findings_with_dns_and_takeover_with_resolver(
        findings,
        observed_domains,
        &SystemDnsResolver,
    )
    .await
}

pub async fn enrich_findings_with_dns_and_takeover_with_resolver(
    findings: &mut Vec<Finding>,
    observed_domains: impl IntoIterator<Item = String>,
    resolver: &dyn DnsResolver,
) -> Result<Vec<DnsEnrichment>> {
    let mut domains = observed_domains.into_iter().collect::<Vec<_>>();
    domains.extend(findings.iter().map(|finding| finding.domain.clone()));
    domains.sort();
    domains.dedup();

    let fingerprints = default_takeover_fingerprints();
    let mut enrichments = Vec::new();

    for domain in domains {
        let enrichment = resolver.enrich(&domain).await?;
        for finding in findings
            .iter_mut()
            .filter(|finding| finding.domain == domain)
        {
            enrichment.apply_to_finding(finding);
        }

        let takeover_findings = takeover_findings_from_enrichment(&enrichment, &fingerprints);
        findings.extend(takeover_findings);
        enrichments.push(enrichment);
    }

    Ok(enrichments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};
    use std::collections::BTreeMap;

    #[test]
    fn applies_resolved_dns_enrichment_to_finding() {
        let enrichment = DnsEnrichment::resolved(
            "example.com",
            vec![
                "93.184.216.34".to_string(),
                "2606:2800:220:1:248:1893:25c8:1946".to_string(),
            ],
        );
        let mut finding = Finding::new("example.com", "keyword", Severity::Low, 30);

        enrichment.apply_to_finding(&mut finding);

        assert!(
            finding
                .reasons
                .iter()
                .any(|reason| reason == "DNS resolved to 2 IP addresses")
        );
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.kind == "dns.ip" && item.value == "93.184.216.34")
        );
    }

    #[test]
    fn applies_unresolved_dns_enrichment_to_finding() {
        let enrichment = DnsEnrichment::unresolved("missing.example", "not found");
        let mut finding = Finding::new("missing.example", "keyword", Severity::Low, 30);

        enrichment.apply_to_finding(&mut finding);

        assert!(
            finding
                .reasons
                .iter()
                .any(|reason| reason == "DNS lookup did not return IP addresses")
        );
        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.kind == "dns.error" && item.value == "not found")
        );
    }

    #[test]
    fn applies_cname_enrichment_to_finding() {
        let enrichment = DnsEnrichment::resolved("docs.example.com", vec![])
            .with_cname_chain(vec!["old-project.herokuapp.com".to_string()]);
        let mut finding = Finding::new("docs.example.com", "keyword", Severity::Low, 30);

        enrichment.apply_to_finding(&mut finding);

        assert!(
            finding
                .evidence
                .iter()
                .any(|item| item.kind == "dns.cname" && item.value == "old-project.herokuapp.com")
        );
    }

    #[tokio::test]
    async fn creates_takeover_finding_for_observed_domain_without_existing_findings() {
        let resolver = MockResolver::new(BTreeMap::from([(
            "docs.example.com".to_string(),
            DnsEnrichment {
                domain: "docs.example.com".to_string(),
                resolved: false,
                ips: Vec::new(),
                cname_chain: vec!["old-project.herokuapp.com".to_string()],
                errors: Vec::new(),
            },
        )]));
        let mut findings = Vec::new();

        let enrichments = enrich_findings_with_dns_and_takeover_with_resolver(
            &mut findings,
            vec!["docs.example.com".to_string()],
            &resolver,
        )
        .await
        .unwrap();

        assert_eq!(enrichments.len(), 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "takeover");
        assert!(
            findings[0]
                .evidence
                .iter()
                .any(|item| item.kind == "takeover.provider" && item.value == "Heroku")
        );
    }

    struct MockResolver {
        responses: BTreeMap<String, DnsEnrichment>,
    }

    impl MockResolver {
        fn new(responses: BTreeMap<String, DnsEnrichment>) -> Self {
            Self { responses }
        }
    }

    #[async_trait]
    impl DnsResolver for MockResolver {
        async fn enrich(&self, domain: &str) -> Result<DnsEnrichment> {
            self.responses
                .get(domain)
                .cloned()
                .ok_or_else(|| CerberusError::Dns(format!("missing mock response for {domain}")))
        }
    }
}
