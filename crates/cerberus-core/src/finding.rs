use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub domain: String,
    pub detector: String,
    pub severity: Severity,
    pub score: u8,
    pub reasons: Vec<String>,
    pub evidence: Vec<Evidence>,
}

impl Finding {
    pub fn new(
        domain: impl Into<String>,
        detector: impl Into<String>,
        severity: Severity,
        score: u8,
    ) -> Self {
        Self {
            domain: domain.into(),
            detector: detector.into(),
            severity,
            score,
            reasons: Vec::new(),
            evidence: Vec::new(),
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reasons.push(reason.into());
        self
    }

    pub fn with_evidence(mut self, kind: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.push(Evidence {
            kind: kind.into(),
            value: value.into(),
        });
        self
    }
}
