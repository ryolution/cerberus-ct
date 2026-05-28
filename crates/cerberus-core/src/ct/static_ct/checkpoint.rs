use serde::{Deserialize, Serialize};

use crate::error::{CerberusError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticCtCheckpoint {
    pub origin: String,
    pub size: u64,
    pub root_hash: String,
    pub signatures: Vec<String>,
    pub raw: String,
}

pub fn parse_static_ct_checkpoint(input: &str) -> Result<StaticCtCheckpoint> {
    let mut lines = input.lines();

    let origin = lines
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .ok_or_else(|| CerberusError::CtSource("checkpoint is missing origin".to_string()))?
        .to_string();

    let size_line = lines
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .ok_or_else(|| CerberusError::CtSource("checkpoint is missing tree size".to_string()))?;

    let size = size_line.parse::<u64>().map_err(|_| {
        CerberusError::CtSource(format!("checkpoint has invalid tree size: {size_line}"))
    })?;

    let root_hash = lines
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .ok_or_else(|| CerberusError::CtSource("checkpoint is missing root hash".to_string()))?
        .to_string();

    let signatures = lines
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    Ok(StaticCtCheckpoint {
        origin,
        size,
        root_hash,
        signatures,
        raw: input.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::parse_static_ct_checkpoint;

    #[test]
    fn parses_checkpoint() {
        let input = "example.com/log\n42\nZmFrZS1yb290LWhhc2g=\n\nexample.com/log+key abcdef\n";
        let checkpoint = parse_static_ct_checkpoint(input).unwrap();

        assert_eq!(checkpoint.origin, "example.com/log");
        assert_eq!(checkpoint.size, 42);
        assert_eq!(checkpoint.root_hash, "ZmFrZS1yb290LWhhc2g=");
        assert_eq!(checkpoint.signatures.len(), 1);
    }

    #[test]
    fn rejects_missing_origin() {
        assert!(parse_static_ct_checkpoint("").is_err());
    }

    #[test]
    fn rejects_invalid_size() {
        let input = "example.com/log\nnot-a-number\nZmFrZS1yb290LWhhc2g=\n";
        assert!(parse_static_ct_checkpoint(input).is_err());
    }
}
