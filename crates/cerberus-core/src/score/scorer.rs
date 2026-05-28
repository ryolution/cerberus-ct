use std::collections::BTreeMap;

use crate::finding::Finding;
use crate::score::severity_from_score;

pub fn merge_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut merged: BTreeMap<(String, String), Finding> = BTreeMap::new();

    for finding in findings {
        let key = (finding.domain.clone(), finding.detector.clone());
        merged
            .entry(key)
            .and_modify(|existing| {
                existing.score = existing.score.saturating_add(finding.score).min(100);
                existing.severity = severity_from_score(existing.score);
                existing.reasons.extend(finding.reasons.clone());
                existing.evidence.extend(finding.evidence.clone());
            })
            .or_insert(finding);
    }

    merged.into_values().collect()
}
