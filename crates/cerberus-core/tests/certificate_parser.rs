use cerberus_core::cert::{
    parse_der_certificate, parse_pem_certificate, parse_pem_certificate_event,
};

#[test]
fn parses_pem_certificate_and_extracts_san_domains() {
    let cert = parse_pem_certificate(include_bytes!("fixtures/san_cert.pem")).unwrap();

    assert!(cert.domains.contains(&"paypa1-login.com".to_string()));
    assert!(cert.domains.contains(&"www.example.test".to_string()));
    assert!(cert.domains.contains(&"*.wild.example.test".to_string()));
    assert!(cert.issuer.contains("Cerberus Test Certificate"));
    assert!(!cert.not_before.is_empty());
    assert!(!cert.not_after.is_empty());
}

#[test]
fn parses_der_certificate_and_extracts_san_domains() {
    let cert = parse_der_certificate(include_bytes!("fixtures/san_cert.der")).unwrap();

    assert_eq!(cert.domains.len(), 3);
    assert!(cert.domains.contains(&"paypa1-login.com".to_string()));
}

#[test]
fn converts_pem_certificate_into_certificate_event() {
    let event = parse_pem_certificate_event(
        include_bytes!("fixtures/san_cert.pem"),
        "fixture-log",
        Some(42),
        "2026-05-28T00:00:00Z",
    )
    .unwrap();

    assert_eq!(event.source_log, "fixture-log");
    assert_eq!(event.index, Some(42));
    assert_eq!(event.observed_at, "2026-05-28T00:00:00Z");
    assert!(event.issuer.is_some());
    assert!(event.not_before.is_some());
    assert!(event.not_after.is_some());
    assert!(
        event
            .domains
            .iter()
            .any(|domain| domain.as_str() == "paypa1-login.com")
    );
    assert!(
        event
            .domains
            .iter()
            .any(|domain| domain.as_str() == "wild.example.test" && domain.is_wildcard)
    );
}

#[test]
fn rejects_invalid_certificate_bytes() {
    let result = parse_der_certificate(b"not a certificate");

    assert!(result.is_err());
}
