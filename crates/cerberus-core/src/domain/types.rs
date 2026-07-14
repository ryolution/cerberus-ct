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

    pub fn registrable_domain(&self) -> &str {
        psl::domain_str(&self.normalized).unwrap_or(self.normalized.as_str())
    }

    pub fn registrable_label_guess(&self) -> &str {
        self.registrable_domain()
            .split('.')
            .next()
            .unwrap_or(self.normalized.as_str())
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

#[cfg(test)]
mod tests {
    use super::DomainName;

    #[test]
    fn extracts_registrable_domain_with_public_suffix_list() {
        let domain = DomainName::parse("secure.example.co.uk").unwrap();

        assert_eq!(domain.registrable_domain(), "example.co.uk");
        assert_eq!(domain.registrable_label_guess(), "example");
    }
}
