use crate::detect::detector::{DetectionContext, Detector};
use crate::error::Result;
use crate::event::DomainObservation;
use crate::finding::Finding;
use crate::score::severity_from_score;

#[derive(Debug, Default)]
pub struct KeywordDetector;

impl Detector for KeywordDetector {
    fn name(&self) -> &'static str {
        "keyword"
    }

    fn detect(
        &self,
        observation: &DomainObservation,
        ctx: &DetectionContext<'_>,
    ) -> Result<Vec<Finding>> {
        let domain = observation.domain.as_str();

        let matched_keywords: Vec<String> = ctx
            .config()
            .keywords
            .iter()
            .map(|keyword| keyword.trim().to_ascii_lowercase())
            .filter(|keyword| !keyword.is_empty())
            .filter(|keyword| domain.contains(keyword))
            .collect();

        if matched_keywords.is_empty() {
            return Ok(Vec::new());
        }

        let score = calculate_keyword_score(matched_keywords.len());
        let mut finding = Finding::new(domain, self.name(), severity_from_score(score), score);

        for keyword in matched_keywords {
            finding = finding
                .with_reason(format!("domain contains suspicious keyword `{keyword}`"))
                .with_evidence("keyword", keyword);
        }

        Ok(vec![finding])
    }
}

fn calculate_keyword_score(match_count: usize) -> u8 {
    let base_score = 30;
    let extra_score = match_count.saturating_sub(1) as u8 * 10;
    base_score + extra_score.min(30)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CerberusConfig;

    #[test]
    fn detects_keyword_in_domain() {
        let detector = KeywordDetector;
        let config = CerberusConfig::default();
        let ctx = DetectionContext::new(&config);
        let observation = DomainObservation::new("paypal-login.com").unwrap();
        let findings = detector.detect(&observation, &ctx).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "keyword");
    }
}
