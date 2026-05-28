use cerberus_core::{CerberusConfig, DetectionEngine, DomainObservation};

#[test]
fn min_score_filters_low_signal_keyword_findings() {
    let engine = DetectionEngine::default();
    let mut config = CerberusConfig::default();
    config.rules.min_score = 50;

    let observation = DomainObservation::new("support.example.com").unwrap();
    let findings = engine.detect_observation(&observation, &config).unwrap();

    assert!(findings.is_empty());
}

#[test]
fn allowlist_suffix_skips_matching_subdomains() {
    let engine = DetectionEngine::default();
    let mut config = CerberusConfig::default();
    config
        .rules
        .allowlist_suffixes
        .push("console.aws.amazon.com".to_string());

    let observation = DomainObservation::new("support.console.aws.amazon.com").unwrap();
    let findings = engine.detect_observation(&observation, &config).unwrap();

    assert!(findings.is_empty());
}
