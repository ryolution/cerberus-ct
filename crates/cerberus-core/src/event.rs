use serde::{Deserialize, Serialize};

use crate::domain::DomainName;
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateEvent {
    pub source_log: String,
    pub index: Option<u64>,
    pub domains: Vec<DomainName>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub observed_at: String,
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
            issuer: None,
            not_before: None,
            not_after: None,
            observed_at: observed_at.into(),
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
                observed_at: self.observed_at.clone(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainObservation {
    pub domain: DomainName,
    pub source_log: String,
    pub certificate_index: Option<u64>,
    pub observed_at: String,
}

impl DomainObservation {
    pub fn new(domain: impl Into<String>) -> Result<Self> {
        Ok(Self {
            domain: DomainName::parse(domain.into())?,
            source_log: "manual".to_string(),
            certificate_index: None,
            observed_at: "manual".to_string(),
        })
    }
}
