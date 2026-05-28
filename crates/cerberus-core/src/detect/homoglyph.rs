use crate::detect::detector::{DetectionContext, Detector};
use crate::error::Result;
use crate::event::DomainObservation;
use crate::finding::Finding;
use crate::score::severity_from_score;

#[derive(Debug, Default)]
pub struct HomoglyphDetector;

impl Detector for HomoglyphDetector {
    fn name(&self) -> &'static str {
        "homoglyph"
    }

    fn detect(
        &self,
        observation: &DomainObservation,
        _ctx: &DetectionContext<'_>,
    ) -> Result<Vec<Finding>> {
        let domain = observation.domain.as_str();
        let mut reasons = Vec::new();
        let mut evidence = Vec::new();

        if observation.domain.is_idn {
            reasons.push("domain contains IDN/punycode or non-ASCII characters".to_string());
            evidence.push(("idn", domain.to_string()));
        }

        for (glyph, replacement) in suspicious_glyphs(domain) {
            reasons.push(format!(
                "domain contains lookalike character `{glyph}` that may resemble `{replacement}`"
            ));
            evidence.push(("glyph", format!("{glyph}->{replacement}")));
        }

        if reasons.is_empty() {
            return Ok(Vec::new());
        }

        let score = if observation.domain.is_idn { 70 } else { 45 };
        let mut finding = Finding::new(domain, self.name(), severity_from_score(score), score);

        for reason in reasons {
            finding = finding.with_reason(reason);
        }

        for (kind, value) in evidence {
            finding = finding.with_evidence(kind, value);
        }

        Ok(vec![finding])
    }
}

fn suspicious_glyphs(domain: &str) -> Vec<(char, char)> {
    domain
        .chars()
        .filter_map(|c| match c {
            'а' => Some((c, 'a')),
            'е' => Some((c, 'e')),
            'о' => Some((c, 'o')),
            'р' => Some((c, 'p')),
            'с' => Some((c, 'c')),
            'х' => Some((c, 'x')),
            'і' => Some((c, 'i')),
            'ӏ' => Some((c, 'l')),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CerberusConfig;

    #[test]
    fn detects_punycode() {
        let config = CerberusConfig::default();
        let ctx = DetectionContext::new(&config);
        let observation = DomainObservation::new("xn--paypa1-4ve.com").unwrap();
        let findings = HomoglyphDetector.detect(&observation, &ctx).unwrap();

        assert_eq!(findings.len(), 1);
    }
}
