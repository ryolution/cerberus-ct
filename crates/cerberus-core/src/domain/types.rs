use serde::{Deserialize, Serialize};
use std::fmt;

use crate::domain::normalize::normalize_domain;
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DomainName {
    pub original: String,
    pub normalized: String,
    pub is_wildcard: bool,
    pub is_idn: bool,
}

impl DomainName {
    pub fn parse(input: impl Into<String>) -> Result<Self> {
        let original = input.into();
        let is_wildcard = original.trim().starts_with("*.");
        let normalized = normalize_domain(&original)?;
        let is_idn = normalized.starts_with("xn--")
            || normalized.contains(".xn--")
            || !normalized.is_ascii();

        Ok(Self {
            original,
            normalized,
            is_wildcard,
            is_idn,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.normalized.split('.')
    }

    pub fn registrable_label_guess(&self) -> &str {
        let labels: Vec<&str> = self.normalized.split('.').collect();
        if labels.len() >= 2 {
            labels[labels.len() - 2]
        } else {
            self.normalized.as_str()
        }
    }
}

impl TryFrom<&str> for DomainName {
    type Error = crate::error::CerberusError;

    fn try_from(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl TryFrom<String> for DomainName {
    type Error = crate::error::CerberusError;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(value)
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.normalized)
    }
}
