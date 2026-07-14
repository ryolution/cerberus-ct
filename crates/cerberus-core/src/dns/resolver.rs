use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt, stream};
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};
use serde::{Deserialize, Serialize};
use tokio::time::{Duration, timeout};

use crate::dns::fingerprints::default_takeover_fingerprints;
use crate::dns::takeover::takeover_findings_from_enrichment;
use crate::error::{CerberusError, Result};
use crate::finding::Finding;

pub const DEFAULT_DNS_ENRICHMENT_CONCURRENCY: usize = 16;
pub const MAX_DNS_ENRICHMENT_CONCURRENCY: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsEnrichmentOptions {
    pub concurrency: usize,
}

impl Default for DnsEnrichmentOptions {
    fn default() -> Self {
        Self {
            concurrency: DEFAULT_DNS_ENRICHMENT_CONCURRENCY,
        }
    }
}

impl DnsEnrichmentOptions {
    pub fn new(concurrency: usize) -> Result<Self> {
        if !(1..=MAX_DNS_ENRICHMENT_CONCURRENCY).contains(&concurrency) {
            return Err(CerberusError::Config(format!(
                "dns.concurrency must be between 1 and {MAX_DNS_ENRICHMENT_CONCURRENCY}"
            )));
        }

        Ok(Self { concurrency })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    Resolved,
    NxDomain,
    NoData,
    Timeout,
    ServFail,
    Refused,
    TransportError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsEnrichment {
    pub domain: String,
    pub resolved: bool,
    #[serde(default = "default_resolution_status")]
    pub status: ResolutionStatus,
    pub ips: Vec<String>,
    pub cname_chain: Vec<String>,
    pub errors: Vec<String>,
}

impl DnsEnrichment {
    pub fn unresolved(domain: impl Into<String>, error: impl Into<String>) -> Self {
        let error = error.into();
        Self {
            domain: domain.into(),
            resolved: false,
            status: classify_dns_error(&error),
            ips: Vec::new(),
            cname_chain: Vec::new(),
            errors: vec![error],
        }
    }

    pub fn resolved(domain: impl Into<String>, ips: Vec<String>) -> Self {
        Self {
            domain: domain.into(),
            resolved: !ips.is_empty(),
            status: if ips.is_empty() {
                ResolutionStatus::NoData
            } else {
                ResolutionStatus::Resolved
            },
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

        finding.evidence.push(crate::finding::Evidence {
            kind: "dns.status".to_string(),
            value: format!("{:?}", self.status).to_ascii_lowercase(),
        });

        if self.resolved {
            let count = self.ips.len();
            let suffix = if count == 1 { "address" } else { "addresses" };
            finding
                .reasons
                .push(format!("DNS resolved to {count} IP {suffix}"));
        } else if matches!(
            self.status,
            ResolutionStatus::NxDomain | ResolutionStatus::NoData
        ) {
            finding
                .reasons
                .push("DNS lookup did not return IP addresses".to_string());
        } else {
            finding
                .reasons
                .push(format!("DNS lookup ended with status {:?}", self.status));
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

#[derive(Debug)]
pub struct SystemDnsResolver {
    resolver: TokioResolver,
    timeout: Duration,
    max_cname_depth: usize,
}

impl SystemDnsResolver {
    pub fn new() -> Result<Self> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|error| {
                CerberusError::Dns(format!("failed to initialize DNS resolver: {error}"))
            })?
            .build()
            .map_err(|error| {
                CerberusError::Dns(format!("failed to build DNS resolver: {error}"))
            })?;

        Ok(Self {
            resolver,
            timeout: Duration::from_secs(5),
            max_cname_depth: 8,
        })
    }
}

impl Default for SystemDnsResolver {
    fn default() -> Self {
        Self::new().expect("system DNS resolver must initialize")
    }
}

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn enrich(&self, domain: &str) -> Result<DnsEnrichment> {
        let cname_chain = self.lookup_cname_chain(domain).await;

        match timeout(self.timeout, self.resolver.lookup_ip(domain)).await {
            Err(_) => Ok(DnsEnrichment {
                domain: domain.to_string(),
                resolved: false,
                status: ResolutionStatus::Timeout,
                ips: Vec::new(),
                cname_chain,
                errors: vec!["DNS lookup timed out".to_string()],
            }),
            Ok(Ok(lookup)) => {
                let mut ips = lookup
                    .iter()
                    .map(|addr| addr.to_string())
                    .collect::<Vec<_>>();
                ips.sort();
                ips.dedup();
                Ok(DnsEnrichment::resolved(domain.to_string(), ips).with_cname_chain(cname_chain))
            }
            Ok(Err(error)) => Ok(DnsEnrichment {
                domain: domain.to_string(),
                resolved: false,
                status: classify_dns_error(&error.to_string()),
                ips: Vec::new(),
                cname_chain,
                errors: vec![error.to_string()],
            }),
        }
    }
}

impl SystemDnsResolver {
    async fn lookup_cname_chain(&self, domain: &str) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = domain.trim_end_matches('.').to_ascii_lowercase();

        for _ in 0..self.max_cname_depth {
            let lookup = match timeout(
                self.timeout,
                self.resolver.lookup(&current, RecordType::CNAME),
            )
            .await
            {
                Ok(Ok(lookup)) => lookup,
                _ => break,
            };

            let Some(next) = lookup
                .answers()
                .iter()
                .find_map(|record| match &record.data {
                    RData::CNAME(cname) => {
                        Some(cname.to_string().trim_end_matches('.').to_ascii_lowercase())
                    }
                    _ => None,
                })
            else {
                break;
            };

            if chain.iter().any(|seen| seen == &next) {
                chain.push(next);
                break;
            }

            current = next.clone();
            chain.push(next);
        }

        chain
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
    enrich_findings_with_dns_with_options(findings, DnsEnrichmentOptions::default()).await
}

pub async fn enrich_findings_with_dns_with_options(
    findings: &mut [Finding],
    options: DnsEnrichmentOptions,
) -> Result<Vec<DnsEnrichment>> {
    let resolver = SystemDnsResolver::new()?;
    enrich_findings_with_resolver_and_options(findings, &resolver, options).await
}

pub async fn enrich_findings_with_resolver(
    findings: &mut [Finding],
    resolver: &dyn DnsResolver,
) -> Result<Vec<DnsEnrichment>> {
    enrich_findings_with_resolver_and_options(findings, resolver, DnsEnrichmentOptions::default())
        .await
}

pub async fn enrich_findings_with_resolver_and_options(
    findings: &mut [Finding],
    resolver: &dyn DnsResolver,
    options: DnsEnrichmentOptions,
) -> Result<Vec<DnsEnrichment>> {
    let mut domains = findings
        .iter()
        .map(|finding| finding.domain.clone())
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();

    let enrichments = enrich_domains_with_resolver(domains, resolver, options).await?;

    for enrichment in &enrichments {
        for finding in findings
            .iter_mut()
            .filter(|finding| finding.domain == enrichment.domain)
        {
            enrichment.apply_to_finding(finding);
        }
    }

    Ok(enrichments)
}

pub async fn enrich_findings_with_dns_and_takeover(
    findings: &mut Vec<Finding>,
    observed_domains: impl IntoIterator<Item = String>,
) -> Result<Vec<DnsEnrichment>> {
    enrich_findings_with_dns_and_takeover_with_options(
        findings,
        observed_domains,
        DnsEnrichmentOptions::default(),
    )
    .await
}

pub async fn enrich_findings_with_dns_and_takeover_with_options(
    findings: &mut Vec<Finding>,
    observed_domains: impl IntoIterator<Item = String>,
    options: DnsEnrichmentOptions,
) -> Result<Vec<DnsEnrichment>> {
    let resolver = SystemDnsResolver::new()?;
    enrich_findings_with_dns_and_takeover_with_resolver_and_options(
        findings,
        observed_domains,
        &resolver,
        options,
    )
    .await
}

fn classify_dns_error(error: &str) -> ResolutionStatus {
    let error = error.to_ascii_lowercase();

    if error.contains("nxdomain")
        || error.contains("name does not exist")
        || error.contains("non-existent domain")
        || error.contains("non existent domain")
    {
        ResolutionStatus::NxDomain
    } else if error.contains("no records found")
        || error.contains("no error")
        || error.contains("not found")
    {
        ResolutionStatus::NoData
    } else if error.contains("servfail") || error.contains("server failure") {
        ResolutionStatus::ServFail
    } else if error.contains("refused") || error.contains("query refused") {
        ResolutionStatus::Refused
    } else if error.contains("timed out") || error.contains("timeout") {
        ResolutionStatus::Timeout
    } else {
        ResolutionStatus::TransportError
    }
}

fn default_resolution_status() -> ResolutionStatus {
    ResolutionStatus::TransportError
}

pub async fn enrich_findings_with_dns_and_takeover_with_resolver(
    findings: &mut Vec<Finding>,
    observed_domains: impl IntoIterator<Item = String>,
    resolver: &dyn DnsResolver,
) -> Result<Vec<DnsEnrichment>> {
    enrich_findings_with_dns_and_takeover_with_resolver_and_options(
        findings,
        observed_domains,
        resolver,
        DnsEnrichmentOptions::default(),
    )
    .await
}

pub async fn enrich_findings_with_dns_and_takeover_with_resolver_and_options(
    findings: &mut Vec<Finding>,
    observed_domains: impl IntoIterator<Item = String>,
    resolver: &dyn DnsResolver,
    options: DnsEnrichmentOptions,
) -> Result<Vec<DnsEnrichment>> {
    let mut domains = observed_domains.into_iter().collect::<Vec<_>>();
    domains.extend(findings.iter().map(|finding| finding.domain.clone()));
    domains.sort();
    domains.dedup();

    let fingerprints = default_takeover_fingerprints();
    let enrichments = enrich_domains_with_resolver(domains, resolver, options).await?;

    for enrichment in &enrichments {
        for finding in findings
            .iter_mut()
            .filter(|finding| finding.domain == enrichment.domain)
        {
            enrichment.apply_to_finding(finding);
        }

        let takeover_findings = takeover_findings_from_enrichment(enrichment, &fingerprints);
        findings.extend(takeover_findings);
    }

    Ok(enrichments)
}

async fn enrich_domains_with_resolver(
    domains: Vec<String>,
    resolver: &dyn DnsResolver,
    options: DnsEnrichmentOptions,
) -> Result<Vec<DnsEnrichment>> {
    stream::iter(domains)
        .map(|domain| async move { resolver.enrich(&domain).await })
        .buffer_unordered(options.concurrency)
        .try_collect()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};
    use std::collections::BTreeMap;

    #[test]
    fn validates_dns_enrichment_options() {
        assert_eq!(
            DnsEnrichmentOptions::default().concurrency,
            DEFAULT_DNS_ENRICHMENT_CONCURRENCY
        );
        assert!(DnsEnrichmentOptions::new(1).is_ok());
        assert!(DnsEnrichmentOptions::new(MAX_DNS_ENRICHMENT_CONCURRENCY).is_ok());
        assert!(DnsEnrichmentOptions::new(0).is_err());
        assert!(DnsEnrichmentOptions::new(MAX_DNS_ENRICHMENT_CONCURRENCY + 1).is_err());
    }

    #[test]
    fn classifies_common_dns_response_code_messages() {
        assert_eq!(
            classify_dns_error("response code: Non-Existent Domain"),
            ResolutionStatus::NxDomain
        );
        assert_eq!(
            classify_dns_error("response code: Server Failure"),
            ResolutionStatus::ServFail
        );
        assert_eq!(
            classify_dns_error("response code: Query Refused"),
            ResolutionStatus::Refused
        );
    }

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
                status: ResolutionStatus::NxDomain,
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
