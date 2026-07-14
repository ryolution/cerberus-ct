use std::collections::HashSet;

use crate::detect::detector::{DetectionContext, Detector};
use crate::domain::DomainName;
use crate::error::Result;
use crate::event::DomainObservation;
use crate::finding::Finding;
use crate::score::severity_from_score;

#[derive(Debug, Default)]
pub struct CompositionDetector;

impl Detector for CompositionDetector {
    fn name(&self) -> &'static str {
        "composition"
    }

    fn detect(
        &self,
        observation: &DomainObservation,
        ctx: &DetectionContext<'_>,
    ) -> Result<Vec<Finding>> {
        let domain = observation.domain.as_str();
        let labels = observation.domain.labels().collect::<Vec<_>>();
        let registrable_label = observation.domain.registrable_label_guess();
        let tokens = domain_tokens(domain);
        let action_terms = matched_action_terms(&tokens, &ctx.config().keywords);
        let protected_names = protected_names(ctx);

        let mut reasons = Vec::new();
        let mut evidence = Vec::new();
        let mut score = 0u8;

        if action_terms.len() >= 2 {
            score = score.max(if action_terms.len() >= 3 { 55 } else { 45 });
            reasons.push(format!(
                "domain combines multiple security-action terms: {}",
                action_terms.join(", ")
            ));
            for term in &action_terms {
                evidence.push(("composition.action_term", term.clone()));
            }
        }

        if let Some(tld) = labels
            .last()
            .copied()
            .filter(|tld| RISKY_TLDS.contains(tld))
        {
            score = score.max(30);
            reasons.push(format!(
                "domain uses high-abuse or campaign-friendly TLD `{tld}`"
            ));
            evidence.push(("composition.risky_tld", tld.to_string()));
        }

        let hyphen_count = registrable_label.matches('-').count();
        if hyphen_count >= 2 {
            score = score.max(if hyphen_count >= 3 { 45 } else { 35 });
            reasons.push(format!(
                "registrable label contains {hyphen_count} hyphens, a common phishing composition pattern"
            ));
            evidence.push(("composition.hyphen_count", hyphen_count.to_string()));
        }

        if labels.len() >= 4 {
            score = score.max(30);
            reasons.push(format!(
                "domain uses deep label nesting with {} DNS labels",
                labels.len()
            ));
            evidence.push(("composition.label_count", labels.len().to_string()));
        }

        for protected in protected_names {
            if registrable_label != protected
                && registrable_label.contains(&protected)
                && !action_terms.is_empty()
            {
                score = score.max(75);
                reasons.push(format!(
                    "domain combines protected name `{protected}` with security-action term(s)"
                ));
                evidence.push(("composition.protected_name", protected.clone()));
            }

            let substituted = normalize_digit_substitutions(registrable_label);
            if registrable_label != protected && substituted == protected {
                score = score.max(80);
                reasons.push(format!(
                    "registrable label `{registrable_label}` normalizes to protected name `{protected}` after digit substitution"
                ));
                evidence.push(("composition.protected_name", protected.clone()));
                evidence.push(("composition.digit_substitution", substituted));
            }

            for token in &tokens {
                let substituted = normalize_digit_substitutions(token);
                if token != &protected && substituted == protected {
                    score = score.max(80);
                    reasons.push(format!(
                        "domain token `{token}` normalizes to protected name `{protected}` after digit substitution"
                    ));
                    evidence.push(("composition.protected_name", protected.clone()));
                    evidence.push(("composition.digit_substitution", substituted));
                    break;
                }
            }
        }

        if reasons.is_empty() {
            return Ok(Vec::new());
        }

        let mut finding = Finding::new(domain, self.name(), severity_from_score(score), score);

        for reason in reasons {
            finding = finding.with_reason(reason);
        }

        for (kind, value) in evidence {
            finding = finding.with_evidence(kind, value);
        }

        Ok(vec![finding])
    }
}

const RISKY_TLDS: &[&str] = &[
    "best", "cam", "click", "cyou", "icu", "monster", "mov", "quest", "sbs", "support", "top",
    "wallet", "win", "xyz", "zip",
];

const BUILTIN_ACTION_TERMS: &[&str] = &[
    "account", "auth", "billing", "invoice", "login", "password", "reset", "secure", "signin",
    "support", "verify", "wallet",
];

fn matched_action_terms(tokens: &[String], configured_keywords: &[String]) -> Vec<String> {
    let mut terms = Vec::new();
    let configured = configured_keywords
        .iter()
        .map(|keyword| keyword.trim().to_ascii_lowercase())
        .filter(|keyword| !keyword.is_empty())
        .collect::<HashSet<_>>();

    for token in tokens {
        if BUILTIN_ACTION_TERMS.contains(&token.as_str()) || configured.contains(token) {
            push_unique(token.clone(), &mut terms);
        }
    }

    terms
}

fn protected_names(ctx: &DetectionContext<'_>) -> Vec<String> {
    let mut names = Vec::new();

    for brand in &ctx.config().brands {
        push_name(brand, &mut names);
    }

    for official in &ctx.config().official_domains {
        if let Ok(domain) = DomainName::parse(official.clone()) {
            push_name(domain.registrable_label_guess(), &mut names);
        }
    }

    names
}

fn push_name(name: &str, names: &mut Vec<String>) {
    let name = name.trim().to_ascii_lowercase();
    if name.len() >= 3 {
        push_unique(name, names);
    }
}

fn domain_tokens(domain: &str) -> Vec<String> {
    let mut tokens = Vec::new();

    for label in domain.split('.') {
        push_token(label, &mut tokens);
        for token in label.split(|ch: char| !ch.is_ascii_alphanumeric()) {
            push_token(token, &mut tokens);
        }
    }

    tokens
}

fn push_token(token: &str, tokens: &mut Vec<String>) {
    let token = token.trim().to_ascii_lowercase();
    if !token.is_empty() {
        push_unique(token, tokens);
    }
}

fn normalize_digit_substitutions(input: &str) -> String {
    input
        .chars()
        .map(|ch| match ch {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            _ => ch,
        })
        .collect()
}

fn push_unique<T>(value: T, items: &mut Vec<T>)
where
    T: PartialEq,
{
    if !items.contains(&value) {
        items.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CerberusConfig;

    #[test]
    fn detects_brand_action_composition() {
        let mut config = CerberusConfig::default();
        config.brands.push("paypal".to_string());
        let ctx = DetectionContext::new(&config);
        let observation = DomainObservation::new("paypal-secure-login.com").unwrap();

        let findings = CompositionDetector.detect(&observation, &ctx).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "composition");
        assert!(findings[0].score >= 75);
    }

    #[test]
    fn detects_digit_substitution_for_protected_name() {
        let mut config = CerberusConfig::default();
        config.brands.push("paypal".to_string());
        let ctx = DetectionContext::new(&config);
        let observation = DomainObservation::new("paypa1.com").unwrap();

        let findings = CompositionDetector.detect(&observation, &ctx).unwrap();

        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .evidence
                .iter()
                .any(|item| item.kind == "composition.digit_substitution")
        );
    }

    #[test]
    fn ignores_plain_low_context_domains() {
        let config = CerberusConfig::default();
        let ctx = DetectionContext::new(&config);
        let observation = DomainObservation::new("example.com").unwrap();

        let findings = CompositionDetector.detect(&observation, &ctx).unwrap();

        assert!(findings.is_empty());
    }
}
