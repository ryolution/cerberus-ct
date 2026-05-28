use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnameChain {
    pub domain: String,
    pub chain: Vec<String>,
}
