use serde::{Deserialize, Serialize};

use crate::dns::fingerprints::TakeoverFingerprint;
use crate::dns::resolver::{DnsEnrichment, ResolutionStatus};
use crate::finding::{Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TakeoverStatus {
    Unknown,
    NotVulnerable,
    Candidate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakeoverCandidate {
    pub domain: String,
    pub provider: String,
    pub status: TakeoverStatus,
    pub cname: String,
    pub reason: String,
    pub documentation_url: Option<String>,
}

pub fn detect_takeover_candidates(
    enrichment: &DnsEnrichment,
    fingerprints: &[TakeoverFingerprint],
) -> Vec<TakeoverCandidate> {
    if enrichment.resolved
        || !matches!(
            enrichment.status,
            ResolutionStatus::NxDomain | ResolutionStatus::NoData
        )
    {
        return Vec::new();
    }

    let mut candidates = Vec::new();

    for cname in &enrichment.cname_chain {
        for fingerprint in fingerprints {
            if cname_matches_fingerprint(cname, fingerprint) {
                let candidate = TakeoverCandidate {
                    domain: enrichment.domain.clone(),
                    provider: fingerprint.provider.clone(),
                    status: TakeoverStatus::Candidate,
                    cname: cname.clone(),
                    reason: format!(
                        "unresolved domain has CNAME target `{cname}` matching takeover provider `{}`",
                        fingerprint.provider
                    ),
                    documentation_url: fingerprint.documentation_url.clone(),
                };

                if !candidates.iter().any(|existing: &TakeoverCandidate| {
                    existing.domain == candidate.domain
                        && existing.provider == candidate.provider
                        && existing.cname == candidate.cname
                }) {
                    candidates.push(candidate);
                }
            }
        }
    }

    candidates
}

pub fn takeover_findings_from_enrichment(
    enrichment: &DnsEnrichment,
    fingerprints: &[TakeoverFingerprint],
) -> Vec<Finding> {
    detect_takeover_candidates(enrichment, fingerprints)
        .into_iter()
        .map(takeover_candidate_to_finding)
        .collect()
}

fn takeover_candidate_to_finding(candidate: TakeoverCandidate) -> Finding {
    let mut finding = Finding::new(candidate.domain, "takeover", Severity::High, 70)
        .with_reason(candidate.reason)
        .with_evidence("takeover.status", "candidate")
        .with_evidence("takeover.provider", candidate.provider)
        .with_evidence("takeover.cname", candidate.cname);

    if let Some(url) = candidate.documentation_url {
        finding = finding.with_evidence("takeover.reference", url);
    }

    finding
}

fn cname_matches_fingerprint(cname: &str, fingerprint: &TakeoverFingerprint) -> bool {
    let normalized_cname = normalize_dns_name(cname);

    fingerprint.cname_suffixes.iter().any(|suffix| {
        let normalized_suffix = normalize_dns_name(suffix);
        normalized_cname == normalized_suffix
            || normalized_cname.ends_with(&format!(".{normalized_suffix}"))
    })
}

fn normalize_dns_name(input: &str) -> String {
    input.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::fingerprints::default_takeover_fingerprints;

    #[test]
    fn detects_takeover_candidate_from_cname_suffix() {
        let enrichment = DnsEnrichment {
            domain: "docs.example.com".to_string(),
            resolved: false,
            status: ResolutionStatus::NxDomain,
            ips: Vec::new(),
            cname_chain: vec!["old-project.herokuapp.com".to_string()],
            errors: Vec::new(),
        };

        let candidates = detect_takeover_candidates(&enrichment, &default_takeover_fingerprints());

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].provider, "Heroku");
        assert_eq!(candidates[0].status, TakeoverStatus::Candidate);
    }

    #[test]
    fn creates_takeover_finding() {
        let enrichment = DnsEnrichment {
            domain: "docs.example.com".to_string(),
            resolved: false,
            status: ResolutionStatus::NxDomain,
            ips: Vec::new(),
            cname_chain: vec!["user.github.io".to_string()],
            errors: Vec::new(),
        };

        let findings =
            takeover_findings_from_enrichment(&enrichment, &default_takeover_fingerprints());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "takeover");
        assert!(
            findings[0]
                .evidence
                .iter()
                .any(|item| item.kind == "takeover.provider" && item.value == "GitHub Pages")
        );
    }

    #[test]
    fn does_not_create_takeover_candidate_when_domain_resolves() {
        let enrichment = DnsEnrichment {
            domain: "r.bing.com".to_string(),
            resolved: true,
            status: ResolutionStatus::Resolved,
            ips: vec!["192.0.2.10".to_string()],
            cname_chain: vec!["p-static.bing.trafficmanager.net".to_string()],
            errors: Vec::new(),
        };

        let candidates = detect_takeover_candidates(&enrichment, &default_takeover_fingerprints());

        assert!(candidates.is_empty());
    }

    #[test]
    fn does_not_create_takeover_candidate_on_timeout() {
        let enrichment = DnsEnrichment {
            domain: "docs.example.com".to_string(),
            resolved: false,
            status: ResolutionStatus::Timeout,
            ips: Vec::new(),
            cname_chain: vec!["old-project.herokuapp.com".to_string()],
            errors: vec!["timeout".to_string()],
        };

        let candidates = detect_takeover_candidates(&enrichment, &default_takeover_fingerprints());

        assert!(candidates.is_empty());
    }
}
