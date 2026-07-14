use x509_parser::extensions::GeneralName;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

use sha2::{Digest, Sha256};

use crate::cert::types::{ParsedCertificate, SanParseError};
use crate::domain::DomainName;
use crate::error::{CerberusError, Result};
use crate::event::CertificateEvent;

pub fn parse_der_certificate(input: &[u8]) -> Result<ParsedCertificate> {
    let (remaining, cert) = X509Certificate::from_der(input)
        .map_err(|err| CerberusError::CertificateParsing(err.to_string()))?;

    if !remaining.is_empty() {
        return Err(CerberusError::CertificateParsing(format!(
            "certificate parser left {} trailing bytes",
            remaining.len()
        )));
    }

    parsed_from_x509(&cert, input)
}

pub fn parse_pem_certificate(input: &[u8]) -> Result<ParsedCertificate> {
    let (_, pem) =
        parse_x509_pem(input).map_err(|err| CerberusError::CertificateParsing(err.to_string()))?;
    parse_der_certificate(pem.contents.as_ref())
}

pub fn parse_der_certificate_event(
    input: &[u8],
    source_log: impl Into<String>,
    index: Option<u64>,
    observed_at: impl Into<String>,
) -> Result<CertificateEvent> {
    let parsed = parse_der_certificate(input)?;
    parsed_certificate_to_event(parsed, source_log, index, observed_at)
}

pub fn parse_pem_certificate_event(
    input: &[u8],
    source_log: impl Into<String>,
    index: Option<u64>,
    observed_at: impl Into<String>,
) -> Result<CertificateEvent> {
    let parsed = parse_pem_certificate(input)?;
    parsed_certificate_to_event(parsed, source_log, index, observed_at)
}

pub fn parsed_certificate_to_event(
    parsed: ParsedCertificate,
    source_log: impl Into<String>,
    index: Option<u64>,
    observed_at: impl Into<String>,
) -> Result<CertificateEvent> {
    let mut domains = Vec::new();
    let mut rejected_domains = parsed.rejected_domains;

    for domain in parsed.domains {
        match DomainName::parse(domain.clone()) {
            Ok(domain)
                if !domains
                    .iter()
                    .any(|seen: &DomainName| seen.normalized == domain.normalized) =>
            {
                domains.push(domain);
            }
            Ok(_) => {}
            Err(error) => rejected_domains.push(SanParseError {
                value: domain,
                error: error.to_string(),
            }),
        }
    }

    if !rejected_domains.is_empty() {
        tracing::debug!(
            rejected_san_count = rejected_domains.len(),
            "certificate contained SAN DNS names rejected during normalization"
        );
    }

    Ok(CertificateEvent {
        source_log: source_log.into(),
        index,
        domains,
        san_dns_names: parsed.san_dns_names,
        certificate_sha256: Some(parsed.sha256_fingerprint),
        serial_number: Some(parsed.serial_number),
        issuer: Some(parsed.issuer),
        not_before: Some(parsed.not_before),
        not_after: Some(parsed.not_after),
        observed_at: observed_at.into(),
        source_type: "ct".to_string(),
    })
}

fn parsed_from_x509(cert: &X509Certificate<'_>, der: &[u8]) -> Result<ParsedCertificate> {
    let mut san_dns_names = Vec::new();

    if let Some(san) = cert
        .subject_alternative_name()
        .map_err(|err| CerberusError::CertificateParsing(err.to_string()))?
    {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns_name) = name {
                san_dns_names.push(dns_name.to_string());
            }
        }
    }

    san_dns_names.sort();
    san_dns_names.dedup();

    Ok(ParsedCertificate {
        domains: san_dns_names.clone(),
        rejected_domains: Vec::new(),
        san_dns_names,
        sha256_fingerprint: hex::encode(Sha256::digest(der)),
        serial_number: cert.tbs_certificate.raw_serial_as_string(),
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
    })
}
