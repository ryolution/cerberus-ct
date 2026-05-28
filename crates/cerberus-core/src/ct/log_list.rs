use serde::{Deserialize, Serialize};

use crate::ct::types::CtSourceKind;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CtLogInfo {
    pub name: String,
    pub url: String,
    pub kind: CtSourceKind,
}
