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
        let mut matches = Vec::new();

        for brand in &ctx.config().brands {
            let brand = brand.trim().to_ascii_lowercase();
            if !brand.is_empty() && domain.contains(&brand) {
                matches.push(brand);
            }
        }

        if matches.is_empty() {
            return Ok(Vec::new());
        }

        let score = 50u8
            .saturating_add((matches.len() as u8).saturating_sub(1) * 10)
            .min(80);
        let mut finding = Finding::new(domain, self.name(), severity_from_score(score), score);

        for brand in matches {
            finding = finding
                .with_reason(format!("domain contains protected brand `{brand}`"))
                .with_evidence("brand", brand);
        }

        Ok(vec![finding])
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
