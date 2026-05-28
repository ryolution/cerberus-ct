use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedCertificate {
    pub domains: Vec<String>,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
}
