use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CerberusConfig {
    #[serde(default)]
    pub brands: Vec<String>,

    #[serde(default)]
    pub official_domains: Vec<String>,

    #[serde(default = "default_keywords")]
    pub keywords: Vec<String>,

    #[serde(default)]
    pub allowlist: Vec<String>,

    #[serde(default)]
    pub outputs: OutputConfig,

    #[serde(default)]
    pub dns: DnsConfig,

    #[serde(default)]
    pub rules: RuleConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputConfig {
    pub jsonl: bool,
    pub webhook_url: Option<String>,
    pub slack_webhook_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DnsConfig {
    pub enabled: bool,
    pub takeover: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RuleConfig {
    pub min_score: u8,
    pub allowlist_suffixes: Vec<String>,
}

impl CerberusConfig {
    pub fn from_yaml_str(input: &str) -> Result<Self> {
        Ok(serde_yaml::from_str(input)?)
    }

    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self> {
        let input = fs::read_to_string(path)?;
        Self::from_yaml_str(&input)
    }

    pub fn is_allowed(&self, domain: &str) -> bool {
        self.allowlist
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(domain))
            || self
                .official_domains
                .iter()
                .any(|official| official.eq_ignore_ascii_case(domain))
            || self
                .rules
                .allowlist_suffixes
                .iter()
                .any(|suffix| domain_matches_suffix(domain, suffix))
    }

    pub fn should_keep_finding(&self, score: u8) -> bool {
        score >= self.rules.min_score
    }

    pub fn apply_runtime_rule_overrides(
        &mut self,
        min_score: Option<u8>,
        allowlist_suffixes: &[String],
    ) {
        if let Some(min_score) = min_score {
            self.rules.min_score = min_score;
        }

        for suffix in allowlist_suffixes {
            let suffix = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
            if !suffix.is_empty()
                && !self
                    .rules
                    .allowlist_suffixes
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(&suffix))
            {
                self.rules.allowlist_suffixes.push(suffix);
            }
        }
    }
}

impl Default for CerberusConfig {
    fn default() -> Self {
        Self {
            brands: Vec::new(),
            official_domains: Vec::new(),
            keywords: default_keywords(),
            allowlist: Vec::new(),
            outputs: OutputConfig::default(),
            dns: DnsConfig::default(),
            rules: RuleConfig::default(),
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            jsonl: true,
            webhook_url: None,
            slack_webhook_url: None,
        }
    }
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let suffix = suffix
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();

    !suffix.is_empty() && (domain == suffix || domain.ends_with(&format!(".{suffix}")))
}

fn default_keywords() -> Vec<String> {
    [
        "login", "verify", "secure", "account", "reset", "support", "wallet", "password",
        "billing", "invoice", "auth", "signin",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::CerberusConfig;

    #[test]
    fn parses_minimal_config() {
        let config = CerberusConfig::from_yaml_str(
            r#"
brands:
  - paypal
official_domains:
  - paypal.com
"#,
        )
        .unwrap();

        assert_eq!(config.brands, vec!["paypal"]);
        assert!(!config.keywords.is_empty());
    }

    #[test]
    fn official_domains_are_allowed() {
        let mut config = CerberusConfig::default();
        config.official_domains.push("example.com".to_string());

        assert!(config.is_allowed("example.com"));
    }

    #[test]
    fn allowlist_suffix_matches_subdomains() {
        let mut config = CerberusConfig::default();
        config
            .rules
            .allowlist_suffixes
            .push("console.aws.amazon.com".to_string());

        assert!(config.is_allowed("support.console.aws.amazon.com"));
        assert!(config.is_allowed("console.aws.amazon.com"));
        assert!(!config.is_allowed("evilconsole.aws.amazon.com"));
    }

    #[test]
    fn runtime_rule_overrides_are_applied() {
        let mut config = CerberusConfig::default();
        config.apply_runtime_rule_overrides(Some(50), &["aws.amazon.com".to_string()]);

        assert_eq!(config.rules.min_score, 50);
        assert!(config.is_allowed("support.aws.amazon.com"));
    }
}
