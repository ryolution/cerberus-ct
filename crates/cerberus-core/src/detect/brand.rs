use crate::detect::detector::{DetectionContext, Detector};
use crate::error::Result;
use crate::event::DomainObservation;
use crate::finding::Finding;
use crate::score::severity_from_score;

#[derive(Debug, Default)]
pub struct BrandDetector;

impl Detector for BrandDetector {
    fn name(&self) -> &'static str {
        "brand"
    }

    fn detect(
        &self,
        observation: &DomainObservation,
        ctx: &DetectionContext<'_>,
    ) -> Result<Vec<Finding>> {
        let domain = observation.domain.as_str();
        let tokens = domain_tokens(domain);
        let mut matches = Vec::new();

        for brand in &ctx.config().brands {
            let brand = brand.trim().to_ascii_lowercase();
            if !brand.is_empty()
                && !matches.contains(&brand)
                && tokens.iter().any(|token| token == &brand)
            {
                matches.push(brand);
            }
        }

        if matches.is_empty() {
            return Ok(Vec::new());
        }

        let score = 50u16
            .saturating_add(matches.len().saturating_sub(1) as u16 * 10)
            .min(80) as u8;
        let mut finding = Finding::new(domain, self.name(), severity_from_score(score), score);

        for brand in matches {
            finding = finding
                .with_reason(format!("domain contains protected brand `{brand}`"))
                .with_evidence("brand", brand);
        }

        Ok(vec![finding])
    }
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
    fn detects_brand() {
        let mut config = CerberusConfig::default();
        config.brands.push("paypal".to_string());
        let ctx = DetectionContext::new(&config);
        let observation = DomainObservation::new("paypal-login.com").unwrap();

        let findings = BrandDetector.detect(&observation, &ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "brand");
    }
}
