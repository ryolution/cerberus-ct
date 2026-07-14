use std::collections::BTreeMap;

use crate::finding::Finding;

pub fn merge_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut merged: BTreeMap<(String, String), Finding> = BTreeMap::new();

    for finding in findings {
        let key = (finding.domain.clone(), finding.detector.clone());
        merged
            .entry(key)
            .and_modify(|existing| {
                if finding.score > existing.score {
                    existing.score = finding.score;
                    existing.severity = finding.severity;
                }

                for reason in &finding.reasons {
                    push_unique(&mut existing.reasons, reason.clone());
                }

                for evidence in &finding.evidence {
                    push_unique(&mut existing.evidence, evidence.clone());
                }
            })
            .or_insert(finding);
    }

    merged.into_values().collect()
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
    use super::merge_findings;
    use crate::finding::{Finding, Severity};

    #[test]
    fn duplicate_detector_uses_max_score_not_sum() {
        let findings = vec![
            Finding::new("example.com", "keyword", Severity::Low, 30)
                .with_reason("keyword login")
                .with_evidence("keyword", "login"),
            Finding::new("example.com", "keyword", Severity::Low, 30)
                .with_reason("keyword login")
                .with_evidence("keyword", "login"),
        ];

        let merged = merge_findings(findings);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].score, 30);
        assert_eq!(merged[0].reasons.len(), 1);
        assert_eq!(merged[0].evidence.len(), 1);
    }
}
