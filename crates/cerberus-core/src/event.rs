use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::domain::DomainName;
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateEvent {
    pub source_log: String,
    pub index: Option<u64>,
    pub domains: Vec<DomainName>,
    #[serde(default)]
    pub san_dns_names: Vec<String>,
    #[serde(default)]
    pub certificate_sha256: Option<String>,
    #[serde(default)]
    pub serial_number: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub observed_at: String,
    #[serde(default = "default_source_type")]
    pub source_type: String,
}

impl CertificateEvent {
    pub fn new(
        source_log: impl Into<String>,
        domains: impl IntoIterator<Item = impl Into<String>>,
        observed_at: impl Into<String>,
    ) -> Result<Self> {
        let domains = domains
            .into_iter()
            .map(|domain| DomainName::parse(domain.into()))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            source_log: source_log.into(),
            index: None,
            domains,
            san_dns_names: Vec::new(),
            certificate_sha256: None,
            serial_number: None,
            issuer: None,
            not_before: None,
            not_after: None,
            observed_at: observed_at.into(),
            source_type: "manual".to_string(),
        })
    }

    pub fn with_index(mut self, index: u64) -> Self {
        self.index = Some(index);
        self
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    pub fn into_domain_observations(self) -> Vec<DomainObservation> {
        self.domains
            .into_iter()
            .map(|domain| DomainObservation {
                domain,
                source_log: self.source_log.clone(),
                certificate_index: self.index,
                certificate_sha256: self.certificate_sha256.clone(),
                serial_number: self.serial_number.clone(),
                issuer: self.issuer.clone(),
                not_before: self.not_before.clone(),
                not_after: self.not_after.clone(),
                san_dns_names: self.san_dns_names.clone(),
                observed_at: self.observed_at.clone(),
                source_type: self.source_type.clone(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainObservation {
    pub domain: DomainName,
    pub source_log: String,
    pub certificate_index: Option<u64>,
    #[serde(default)]
    pub certificate_sha256: Option<String>,
    #[serde(default)]
    pub serial_number: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
    #[serde(default)]
    pub san_dns_names: Vec<String>,
    pub observed_at: String,
    #[serde(default = "default_source_type")]
    pub source_type: String,
}

impl DomainObservation {
    pub fn new(domain: impl Into<String>) -> Result<Self> {
        Ok(Self {
            domain: DomainName::parse(domain.into())?,
            source_log: "manual".to_string(),
            certificate_index: None,
            certificate_sha256: None,
            serial_number: None,
            issuer: None,
            not_before: None,
            not_after: None,
            san_dns_names: Vec::new(),
            observed_at: now_rfc3339(),
            source_type: "manual".to_string(),
        })
    }
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn default_source_type() -> String {
    "ct".to_string()
}
