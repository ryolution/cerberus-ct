use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::ct::TrustedCtLog;
use crate::dns::{
    DEFAULT_DNS_ENRICHMENT_CONCURRENCY, DnsEnrichmentOptions, MAX_DNS_ENRICHMENT_CONCURRENCY,
};
use crate::domain::normalize_domain;
use crate::error::CerberusError;
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    pub ct: CtConfig,

    #[serde(default)]
    pub rules: RuleConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub webhook_signing_secret: Option<String>,
    #[serde(default)]
    pub slack_webhook_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub takeover: bool,
    #[serde(default = "default_dns_concurrency")]
    pub concurrency: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            takeover: false,
            concurrency: default_dns_concurrency(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CtConfig {
    #[serde(default)]
    pub trusted_logs: Vec<TrustedCtLogConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedCtLogConfig {
    pub origin: String,
    pub base_url: String,
    pub public_key: String,
    #[serde(default)]
    pub log_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    #[serde(default)]
    pub min_score: u8,
    #[serde(default)]
    pub min_alert_score: u8,
    #[serde(default)]
    pub allowlist_suffixes: Vec<String>,
}

impl CerberusConfig {
    pub fn from_yaml_str(input: &str) -> Result<Self> {
        let mut config: Self = yaml_serde::from_str(input)?;
        config.validate_and_normalize()?;
        Ok(config)
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

    pub fn should_keep_alert(&self, score: u8) -> bool {
        score >= self.rules.min_alert_score
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

    pub fn trusted_log_for_url(&self, url: &str) -> Result<Option<TrustedCtLog>> {
        let requested = normalize_ct_base_url(url)?;

        for trusted_log in &self.ct.trusted_logs {
            let trusted_base = normalize_ct_base_url(&trusted_log.base_url)?;
            if trusted_base == requested {
                return TrustedCtLog::from_base64_public_key_and_log_id(
                    trusted_log.origin.clone(),
                    trusted_log.base_url.as_str(),
                    trusted_log.public_key.as_str(),
                    trusted_log.log_id.as_deref(),
                )
                .map(Some);
            }
        }

        Ok(None)
    }

    pub fn dns_enrichment_options(&self) -> Result<DnsEnrichmentOptions> {
        DnsEnrichmentOptions::new(self.dns.concurrency)
    }

    pub fn validate_and_normalize(&mut self) -> Result<()> {
        self.brands = normalize_text_list("brand", std::mem::take(&mut self.brands), false)?;
        self.keywords = normalize_text_list("keyword", std::mem::take(&mut self.keywords), false)?;
        self.official_domains = normalize_domain_list(
            "official domain",
            std::mem::take(&mut self.official_domains),
        )?;
        self.allowlist =
            normalize_domain_list("allowlist domain", std::mem::take(&mut self.allowlist))?;
        self.rules.allowlist_suffixes = normalize_domain_list(
            "allowlist suffix",
            std::mem::take(&mut self.rules.allowlist_suffixes),
        )?;

        validate_score("rules.min_score", self.rules.min_score)?;
        validate_score("rules.min_alert_score", self.rules.min_alert_score)?;
        validate_dns_concurrency(self.dns.concurrency)?;
        validate_output_url("outputs.webhook_url", self.outputs.webhook_url.as_deref())?;
        validate_optional_secret(
            "outputs.webhook_signing_secret",
            self.outputs.webhook_signing_secret.as_deref(),
        )?;
        validate_output_url(
            "outputs.slack_webhook_url",
            self.outputs.slack_webhook_url.as_deref(),
        )?;

        for trusted_log in &self.ct.trusted_logs {
            if trusted_log.origin.trim().is_empty() {
                return Err(CerberusError::Config(
                    "ct.trusted_logs.origin cannot be empty".to_string(),
                ));
            }
            normalize_ct_base_url(&trusted_log.base_url)?;
            TrustedCtLog::from_base64_public_key_and_log_id(
                trusted_log.origin.clone(),
                trusted_log.base_url.as_str(),
                trusted_log.public_key.as_str(),
                trusted_log.log_id.as_deref(),
            )?;
        }

        Ok(())
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
            ct: CtConfig::default(),
            rules: RuleConfig::default(),
        }
    }
}

fn normalize_text_list(kind: &str, values: Vec<String>, allow_empty: bool) -> Result<Vec<String>> {
    let mut normalized = Vec::new();

    for value in values {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() && !allow_empty {
            return Err(CerberusError::Config(format!("{kind} cannot be empty")));
        }

        if !value.is_empty() && !normalized.contains(&value) {
            normalized.push(value);
        }
    }

    Ok(normalized)
}

fn normalize_domain_list(kind: &str, values: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = Vec::new();

    for value in values {
        let domain = normalize_domain(&value)
            .map_err(|error| CerberusError::Config(format!("invalid {kind} `{value}`: {error}")))?;

        if !normalized.contains(&domain) {
            normalized.push(domain);
        }
    }

    Ok(normalized)
}

fn validate_score(field: &str, score: u8) -> Result<()> {
    if score > 100 {
        return Err(CerberusError::Config(format!(
            "{field} must be between 0 and 100"
        )));
    }

    Ok(())
}

fn validate_dns_concurrency(concurrency: usize) -> Result<()> {
    if !(1..=MAX_DNS_ENRICHMENT_CONCURRENCY).contains(&concurrency) {
        return Err(CerberusError::Config(format!(
            "dns.concurrency must be between 1 and {MAX_DNS_ENRICHMENT_CONCURRENCY}"
        )));
    }

    Ok(())
}

fn validate_output_url(field: &str, value: Option<&str>) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };

    let url = url::Url::parse(value)
        .map_err(|error| CerberusError::Config(format!("{field} is not a valid URL: {error}")))?;
    match url.scheme() {
        "http" | "https" => Ok(()),
        scheme => Err(CerberusError::Config(format!(
            "{field} uses unsupported URL scheme `{scheme}`"
        ))),
    }
}

fn validate_optional_secret(field: &str, value: Option<&str>) -> Result<()> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        return Err(CerberusError::Config(format!("{field} cannot be empty")));
    }

    Ok(())
}

fn normalize_ct_base_url(value: &str) -> Result<String> {
    let mut url = url::Url::parse(value)
        .map_err(|error| CerberusError::Config(format!("invalid CT URL `{value}`: {error}")))?;

    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(CerberusError::Config(format!(
                "CT URL uses unsupported scheme `{scheme}`"
            )));
        }
    }

    if url.path().ends_with("/checkpoint") {
        let path = url.path().trim_end_matches("/checkpoint").to_string();
        url.set_path(path.trim_end_matches('/'));
    } else {
        let path = url.path().trim_end_matches('/').to_string();
        url.set_path(&path);
    }

    Ok(url.to_string().trim_end_matches('/').to_string())
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

fn default_dns_concurrency() -> usize {
    DEFAULT_DNS_ENRICHMENT_CONCURRENCY
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

    #[test]
    fn rejects_unknown_fields() {
        let err = CerberusConfig::from_yaml_str(
            r#"
min_socre: 80
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_invalid_dns_concurrency() {
        let err = CerberusConfig::from_yaml_str(
            r#"
brands:
  - paypal
official_domains:
  - paypal.com
dns:
  concurrency: 0
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("dns.concurrency"));
    }
}
