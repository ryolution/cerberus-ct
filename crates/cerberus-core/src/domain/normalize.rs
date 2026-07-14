use crate::error::{CerberusError, Result};

pub fn normalize_domain(input: &str) -> Result<String> {
    let mut domain = input.trim().trim_end_matches('.').to_string();

    if domain.is_empty() {
        return Err(CerberusError::DomainNormalization(
            "domain is empty".to_string(),
        ));
    }

    if domain.starts_with("*.") {
        domain = domain.trim_start_matches("*.").to_string();
    } else if domain.contains('*') {
        return Err(CerberusError::DomainNormalization(format!(
            "domain contains an embedded wildcard: {domain}"
        )));
    }

    let domain = idna::domain_to_ascii(&domain).map_err(|error| {
        CerberusError::DomainNormalization(format!("domain is not valid IDNA: {error:?}"))
    })?;
    let domain = domain.to_ascii_lowercase();

    validate_domain_shape(&domain)?;
    Ok(domain)
}

fn validate_domain_shape(domain: &str) -> Result<()> {
    if domain.is_empty() {
        return Err(CerberusError::DomainNormalization(
            "domain is empty after normalization".to_string(),
        ));
    }

    if domain.len() > 253 {
        return Err(CerberusError::DomainNormalization(format!(
            "domain is too long: {domain}"
        )));
    }

    if !domain.contains('.') {
        return Err(CerberusError::DomainNormalization(format!(
            "domain does not contain a dot: {domain}"
        )));
    }

    if domain.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(CerberusError::DomainNormalization(format!(
            "domain contains whitespace/control characters: {domain}"
        )));
    }

    for forbidden in ['/', '\\', ':', '@', '#', '?'] {
        if domain.contains(forbidden) {
            return Err(CerberusError::DomainNormalization(format!(
                "domain contains forbidden character `{forbidden}`: {domain}"
            )));
        }
    }

    for label in domain.split('.') {
        validate_label(label, domain)?;
    }

    Ok(())
}

fn validate_label(label: &str, domain: &str) -> Result<()> {
    if label.is_empty() {
        return Err(CerberusError::DomainNormalization(format!(
            "domain contains an empty label: {domain}"
        )));
    }

    if label.len() > 63 {
        return Err(CerberusError::DomainNormalization(format!(
            "domain label is too long in: {domain}"
        )));
    }

    if !label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(CerberusError::DomainNormalization(format!(
            "domain label contains invalid DNS characters in: {domain}"
        )));
    }

    if label.starts_with('-') || label.ends_with('-') {
        return Err(CerberusError::DomainNormalization(format!(
            "domain label starts or ends with hyphen: {domain}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::normalize_domain;

    #[test]
    fn normalizes_case() {
        assert_eq!(normalize_domain("PayPal.COM").unwrap(), "paypal.com");
    }

    #[test]
    fn removes_wildcard_prefix() {
        assert_eq!(normalize_domain("*.example.com").unwrap(), "example.com");
    }

    #[test]
    fn removes_trailing_dot() {
        assert_eq!(normalize_domain("example.com.").unwrap(), "example.com");
    }

    #[test]
    fn converts_idn_to_a_label() {
        assert_eq!(
            normalize_domain("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn rejects_empty_domain() {
        assert!(normalize_domain("").is_err());
    }

    #[test]
    fn rejects_domain_without_dot() {
        assert!(normalize_domain("localhost").is_err());
    }

    #[test]
    fn rejects_empty_label() {
        assert!(normalize_domain("example..com").is_err());
    }

    #[test]
    fn rejects_embedded_wildcard() {
        assert!(normalize_domain("api.*.example.com").is_err());
    }
}
