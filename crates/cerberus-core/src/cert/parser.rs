use x509_parser::extensions::GeneralName;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;

use crate::cert::types::ParsedCertificate;
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

    parsed_from_x509(&cert)
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
    let domains = parsed
        .domains
        .into_iter()
        .map(DomainName::parse)
        .collect::<Result<Vec<_>>>()?;

    Ok(CertificateEvent {
        source_log: source_log.into(),
        index,
        domains,
        issuer: Some(parsed.issuer),
        not_before: Some(parsed.not_before),
        not_after: Some(parsed.not_after),
        observed_at: observed_at.into(),
    })
}

fn parsed_from_x509(cert: &X509Certificate<'_>) -> Result<ParsedCertificate> {
    let mut domains = Vec::new();

    if let Some(san) = cert
        .subject_alternative_name()
        .map_err(|err| CerberusError::CertificateParsing(err.to_string()))?
    {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns_name) = name {
                domains.push(dns_name.to_string());
            }
        }
    }

    domains.sort();
    domains.dedup();

    Ok(ParsedCertificate {
        domains,
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
    })
}
