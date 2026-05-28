use cerberus_core::{CerberusConfig, DetectionEngine, DomainObservation};

#[test]
fn detects_multiple_signals_for_suspicious_domain() {
    let mut config = CerberusConfig::default();
    config.brands.push("paypal".to_string());
    config.official_domains.push("paypal.com".to_string());

    let engine = DetectionEngine::default();
    let observation = DomainObservation::new("paypa1-login.com").unwrap();
    let findings = engine.detect_observation(&observation, &config).unwrap();

    assert!(findings.iter().any(|finding| finding.detector == "keyword"));
    assert!(
        findings
            .iter()
            .any(|finding| finding.detector == "typosquat")
    );
}
