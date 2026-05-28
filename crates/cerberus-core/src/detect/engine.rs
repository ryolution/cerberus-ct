use crate::config::CerberusConfig;
use crate::detect::brand::BrandDetector;
use crate::detect::detector::{DetectionContext, Detector};
use crate::detect::homoglyph::HomoglyphDetector;
use crate::detect::keyword::KeywordDetector;
use crate::detect::typosquat::TyposquatDetector;
use crate::error::Result;
use crate::event::{CertificateEvent, DomainObservation};
use crate::finding::Finding;
use crate::score::merge_findings;

pub struct DetectionEngine {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    pub fn with_detector(mut self, detector: impl Detector + 'static) -> Self {
        self.detectors.push(Box::new(detector));
        self
    }

    pub fn add_detector(&mut self, detector: impl Detector + 'static) {
        self.detectors.push(Box::new(detector));
    }

    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    pub fn detect_observation(
        &self,
        observation: &DomainObservation,
        config: &CerberusConfig,
    ) -> Result<Vec<Finding>> {
        tracing::debug!(domain = %observation.domain, "detecting domain observation");

        let domain = observation.domain.as_str();

        if config.is_allowed(domain) {
            tracing::info!(domain = %domain, "domain skipped because it is allowlisted");
            return Ok(Vec::new());
        }

        let ctx = DetectionContext::new(config);
        let mut findings = Vec::new();

        for detector in &self.detectors {
            findings.extend(detector.detect(observation, &ctx)?);
        }

        let findings = merge_findings(findings)
            .into_iter()
            .filter(|finding| config.should_keep_finding(finding.score))
            .collect::<Vec<_>>();
        tracing::debug!(domain = %domain, finding_count = findings.len(), min_score = config.rules.min_score, "detection completed");

        Ok(findings)
    }

    pub fn detect_event(
        &self,
        event: CertificateEvent,
        config: &CerberusConfig,
    ) -> Result<Vec<Finding>> {
        tracing::debug!(source_log = %event.source_log, domain_count = event.domains.len(), "detecting certificate event");

        let mut findings = Vec::new();

        for observation in event.into_domain_observations() {
            findings.extend(self.detect_observation(&observation, config)?);
        }

        let findings = merge_findings(findings)
            .into_iter()
            .filter(|finding| config.should_keep_finding(finding.score))
            .collect::<Vec<_>>();
        tracing::debug!(
            finding_count = findings.len(),
            min_score = config.rules.min_score,
            "certificate event detection completed"
        );

        Ok(findings)
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
            .with_detector(KeywordDetector)
            .with_detector(BrandDetector)
            .with_detector(TyposquatDetector::default())
            .with_detector(HomoglyphDetector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::DomainObservation;

    #[test]
    fn default_engine_has_builtin_detectors() {
        let engine = DetectionEngine::default();
        assert_eq!(engine.detector_count(), 4);
    }

    #[test]
    fn engine_detects_keyword_finding() {
        let engine = DetectionEngine::default();
        let config = CerberusConfig::default();
        let observation = DomainObservation::new("paypal-login.com").unwrap();
        let findings = engine.detect_observation(&observation, &config).unwrap();

        assert!(findings.iter().any(|finding| finding.detector == "keyword"));
    }

    #[test]
    fn engine_skips_allowlisted_domain() {
        let engine = DetectionEngine::default();
        let mut config = CerberusConfig::default();
        config.allowlist.push("paypal-login.com".to_string());

        let observation = DomainObservation::new("paypal-login.com").unwrap();
        let findings = engine.detect_observation(&observation, &config).unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn engine_applies_min_score_filter() {
        let engine = DetectionEngine::default();
        let mut config = CerberusConfig::default();
        config.rules.min_score = 50;
        let observation = DomainObservation::new("support.example.com").unwrap();
        let findings = engine.detect_observation(&observation, &config).unwrap();

        assert!(findings.is_empty());
    }
}
