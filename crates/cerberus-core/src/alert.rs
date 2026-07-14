use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::finding::{Evidence, Finding, Severity};
use crate::score::severity_from_score;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainAlert {
    pub domain: String,
    pub severity: Severity,
    pub score: u8,
    pub detectors: Vec<String>,
    pub reasons: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub findings: Vec<Finding>,
}

impl DomainAlert {
    pub fn from_findings(domain: impl Into<String>, findings: Vec<Finding>) -> Option<Self> {
        if findings.is_empty() {
            return None;
        }

        let domain = domain.into();
        let mut detectors = Vec::new();
        let mut reasons = Vec::new();
        let mut evidence = Vec::new();
        let mut max_score = 0u8;
        let mut max_severity = Severity::Info;

        for finding in &findings {
            push_unique(&mut detectors, finding.detector.clone());

            for reason in &finding.reasons {
                push_unique(&mut reasons, reason.clone());
            }

            for item in &finding.evidence {
                push_unique(&mut evidence, item.clone());
            }

            max_score = max_score.max(finding.score);
            max_severity = max_severity.max(finding.severity);
        }

        let score = calculate_combined_score(max_score, detectors.len());
        let severity = severity_from_score(score).max(max_severity);

        Some(Self {
            domain,
            severity,
            score,
            detectors,
            reasons,
            evidence,
            findings,
        })
    }
}

pub fn group_findings_by_domain(findings: Vec<Finding>) -> Vec<DomainAlert> {
    let mut grouped: BTreeMap<String, Vec<Finding>> = BTreeMap::new();

    for finding in findings {
        grouped
            .entry(finding.domain.clone())
            .or_default()
            .push(finding);
    }

    let mut alerts: Vec<DomainAlert> = grouped
        .into_iter()
        .filter_map(|(domain, findings)| DomainAlert::from_findings(domain, findings))
        .collect();

    alerts.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.domain.cmp(&b.domain)));
    alerts
}

fn calculate_combined_score(max_score: u8, detector_count: usize) -> u8 {
    let detector_bonus = detector_count.saturating_sub(1) as u16 * 10;
    let raw_score = u16::from(max_score).saturating_add(detector_bonus);

    raw_score.min(100) as u8
}

fn push_unique<T>(items: &mut Vec<T>, value: T)
where
    T: PartialEq,
{
    if !items.contains(&value) {
        items.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;

    #[test]
    fn groups_findings_for_same_domain() {
        let findings = vec![
            Finding::new("paypa1-login.com", "keyword", Severity::Low, 30)
                .with_reason("domain contains suspicious keyword `login`"),
            Finding::new("paypa1-login.com", "typosquat", Severity::High, 85)
                .with_reason("domain label candidate `paypa1` is edit-distance 1 from `paypal`"),
        ];

        let alerts = group_findings_by_domain(findings);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].domain, "paypa1-login.com");
        assert_eq!(alerts[0].detectors, vec!["keyword", "typosquat"]);
        assert!(alerts[0].score > 85);
        assert_eq!(alerts[0].severity, Severity::Critical);
    }
}
