use cerberus_core::{CerberusConfig, DetectionEngine, DomainObservation};

fn main() -> cerberus_core::Result<()> {
    let mut config = CerberusConfig::default();
    config.brands.push("paypal".to_string());
    config.official_domains.push("paypal.com".to_string());

    let engine = DetectionEngine::default();
    let observation = DomainObservation::new("paypa1-login.com")?;
    let findings = engine.detect_observation(&observation, &config)?;

    for finding in findings {
        println!("{}", serde_json::to_string_pretty(&finding)?);
    }

    Ok(())
}
