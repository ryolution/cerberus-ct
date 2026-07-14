use std::collections::HashSet;

use crate::detect::detector::{DetectionContext, Detector};
use crate::domain::DomainName;
use crate::error::Result;
use crate::event::DomainObservation;
use crate::finding::Finding;
use crate::score::severity_from_score;

#[derive(Debug, Clone)]
pub struct TyposquatDetector {
    max_distance: usize,
}

impl Default for TyposquatDetector {
    fn default() -> Self {
        Self { max_distance: 2 }
    }
}

impl TyposquatDetector {
    pub fn new(max_distance: usize) -> Self {
        Self { max_distance }
    }
}

impl Detector for TyposquatDetector {
    fn name(&self) -> &'static str {
        "typosquat"
    }

    fn detect(
        &self,
        observation: &DomainObservation,
        ctx: &DetectionContext<'_>,
    ) -> Result<Vec<Finding>> {
        let domain = observation.domain.as_str();
        let suspicious_label = observation.domain.registrable_label_guess();
        let candidate_labels = candidate_typosquat_labels(suspicious_label, &ctx.config().keywords);
        let mut findings = Vec::new();

        for official in &ctx.config().official_domains {
            let official = DomainName::parse(official.clone())?;
            let official_domain = official.as_str();

            if domain == official_domain {
                continue;
            }

            let official_label = official.registrable_label_guess();

            for candidate_label in &candidate_labels {
                if candidate_label == official_label {
                    continue;
                }

                let distance = damerau_levenshtein(candidate_label, official_label);
                let max_distance = max_distance_for_label(official_label.len(), self.max_distance);
                if distance == 0 || distance > max_distance {
                    continue;
                }

                let score = match distance {
                    1 => 85,
                    2 => 70,
                    _ => 55,
                };

                let finding = Finding::new(domain, self.name(), severity_from_score(score), score)
                    .with_reason(format!(
                        "domain label candidate `{candidate_label}` is edit-distance {distance} from `{official_label}`"
                    ))
                    .with_evidence("official_domain", official_domain)
                    .with_evidence("suspicious_label", suspicious_label)
                    .with_evidence("candidate_label", candidate_label)
                    .with_evidence("distance_algorithm", "damerau_levenshtein")
                    .with_evidence("distance", distance.to_string());

                findings.push(finding);

                break;
            }
        }

        Ok(findings)
    }
}

fn candidate_typosquat_labels(label: &str, keywords: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    push_candidate(label, &mut seen, &mut candidates);

    for token in label.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        push_candidate(token, &mut seen, &mut candidates);
    }

    for keyword in keywords {
        let keyword = keyword.trim().to_ascii_lowercase();
        if keyword.is_empty() {
            continue;
        }

        let variants = [
            format!("-{keyword}"),
            format!("{keyword}-"),
            format!("_{keyword}"),
            format!("{keyword}_"),
        ];

        for variant in variants {
            if label.contains(&variant) {
                let stripped = label.replace(&variant, "");
                push_candidate(&stripped, &mut seen, &mut candidates);
            }
        }
    }

    candidates
}

fn push_candidate(candidate: &str, seen: &mut HashSet<String>, candidates: &mut Vec<String>) {
    let candidate = candidate.trim().to_ascii_lowercase();

    if candidate.len() < 3 {
        return;
    }

    if seen.insert(candidate.clone()) {
        candidates.push(candidate);
    }
}

pub fn levenshtein(a: &str, b: &str) -> usize {
    if a == b {
        return 0;
    }

    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();

    if a_chars.is_empty() {
        return b_chars.len();
    }

    if b_chars.is_empty() {
        return a_chars.len();
    }

    let mut prev: Vec<usize> = (0..=b_chars.len()).collect();
    let mut curr = vec![0; b_chars.len() + 1];

    for (i, ca) in a_chars.iter().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b_chars.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (curr[j] + 1).min(prev[j + 1] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_chars.len()]
}

pub fn damerau_levenshtein(a: &str, b: &str) -> usize {
    if a == b {
        return 0;
    }

    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let rows = a_chars.len() + 1;
    let cols = b_chars.len() + 1;
    let mut distances = vec![vec![0usize; cols]; rows];

    for (i, row) in distances.iter_mut().enumerate() {
        row[0] = i;
    }

    for (j, cell) in distances[0].iter_mut().enumerate() {
        *cell = j;
    }

    for i in 1..rows {
        for j in 1..cols {
            let cost = usize::from(a_chars[i - 1] != b_chars[j - 1]);
            let mut distance = (distances[i - 1][j] + 1)
                .min(distances[i][j - 1] + 1)
                .min(distances[i - 1][j - 1] + cost);

            if i > 1
                && j > 1
                && a_chars[i - 1] == b_chars[j - 2]
                && a_chars[i - 2] == b_chars[j - 1]
            {
                distance = distance.min(distances[i - 2][j - 2] + 1);
            }

            distances[i][j] = distance;
        }
    }

    distances[a_chars.len()][b_chars.len()]
}

fn max_distance_for_label(label_len: usize, configured_max: usize) -> usize {
    let length_based = match label_len {
        0..=4 => 1,
        5..=10 => 2,
        _ => 3,
    };

    configured_max.min(length_based)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CerberusConfig;

    #[test]
    fn calculates_levenshtein_distance() {
        assert_eq!(levenshtein("paypal", "paypa1"), 1);
        assert_eq!(levenshtein("github", "githab"), 1);
    }

    #[test]
    fn calculates_damerau_transposition_distance() {
        assert_eq!(damerau_levenshtein("payapl", "paypal"), 1);
    }

    #[test]
    fn detects_typosquat() {
        let mut config = CerberusConfig::default();
        config.official_domains.push("paypal.com".to_string());
        let ctx = DetectionContext::new(&config);
        let observation = DomainObservation::new("paypa1.com").unwrap();

        let findings = TyposquatDetector::default()
            .detect(&observation, &ctx)
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "typosquat");
    }

    #[test]
    fn detects_hyphenated_typosquat_with_keyword() {
        let mut config = CerberusConfig::default();
        config.official_domains.push("paypal.com".to_string());
        let ctx = DetectionContext::new(&config);
        let observation = DomainObservation::new("paypa1-login.com").unwrap();

        let findings = TyposquatDetector::default()
            .detect(&observation, &ctx)
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "typosquat");
        assert!(
            findings[0]
                .evidence
                .iter()
                .any(|evidence| evidence.kind == "candidate_label" && evidence.value == "paypa1")
        );
    }
}
