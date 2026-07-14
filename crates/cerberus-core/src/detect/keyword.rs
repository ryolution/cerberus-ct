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
        let tokens = domain_tokens(domain);

        let matched_keywords: Vec<String> = ctx
            .config()
            .keywords
            .iter()
            .map(|keyword| keyword.trim().to_ascii_lowercase())
            .filter(|keyword| !keyword.is_empty())
            .filter(|keyword| tokens.iter().any(|token| token == keyword))
            .fold(Vec::new(), |mut keywords, keyword| {
                if !keywords.contains(&keyword) {
                    keywords.push(keyword);
                }
                keywords
            });

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
    let base_score = 30u16;
    let extra_score = match_count.saturating_sub(1) as u16 * 10;
    base_score.saturating_add(extra_score.min(30)).min(100) as u8
}

fn domain_tokens(domain: &str) -> Vec<String> {
    let mut tokens = Vec::new();

    for label in domain.split('.') {
        push_token(label, &mut tokens);
        for token in label.split(|ch: char| !ch.is_ascii_alphanumeric()) {
            push_token(token, &mut tokens);
        }
    }

    tokens
}

fn push_token(token: &str, tokens: &mut Vec<String>) {
    let token = token.trim().to_ascii_lowercase();
    if !token.is_empty() && !tokens.contains(&token) {
        tokens.push(token);
    }
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
