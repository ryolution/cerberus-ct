use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedCertificate {
    pub domains: Vec<String>,
    pub rejected_domains: Vec<SanParseError>,
    pub san_dns_names: Vec<String>,
    pub sha256_fingerprint: String,
    pub serial_number: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanParseError {
    pub value: String,
    pub error: String,
}
