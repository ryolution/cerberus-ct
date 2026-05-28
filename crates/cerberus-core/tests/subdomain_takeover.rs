use async_trait::async_trait;
use cerberus_core::{
    CerberusError, DnsEnrichment, DnsResolver, Result,
    enrich_findings_with_dns_and_takeover_with_resolver,
};
use std::collections::BTreeMap;

struct MockResolver {
    responses: BTreeMap<String, DnsEnrichment>,
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

#[tokio::test]
async fn detects_takeover_candidate_from_observed_domain() {
    let resolver = MockResolver {
        responses: BTreeMap::from([(
            "docs.example.com".to_string(),
            DnsEnrichment {
                domain: "docs.example.com".to_string(),
                resolved: false,
                ips: Vec::new(),
                cname_chain: vec!["abandoned-project.herokuapp.com".to_string()],
                errors: Vec::new(),
            },
        )]),
    };
    let mut findings = Vec::new();

    enrich_findings_with_dns_and_takeover_with_resolver(
        &mut findings,
        vec!["docs.example.com".to_string()],
        &resolver,
    )
    .await
    .unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].domain, "docs.example.com");
    assert_eq!(findings[0].detector, "takeover");
    assert!(
        findings[0]
            .evidence
            .iter()
            .any(|item| item.kind == "takeover.provider" && item.value == "Heroku")
    );
}
