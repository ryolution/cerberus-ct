use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::detect::detector::{DetectionContext, Detector};
use crate::domain::DomainName;
use crate::error::Result;
use crate::event::DomainObservation;
use crate::finding::Finding;
use crate::score::severity_from_score;

#[derive(Debug, Default)]
pub struct HomoglyphDetector;

impl Detector for HomoglyphDetector {
    fn name(&self) -> &'static str {
        "homoglyph"
    }

    fn detect(
        &self,
        observation: &DomainObservation,
        ctx: &DetectionContext<'_>,
    ) -> Result<Vec<Finding>> {
        let domain = observation.domain.as_str();
        let unicode_domain = decode_domain_to_unicode(domain);
        let skeleton = confusable_skeleton(&unicode_domain);
        let mut reasons = Vec::new();
        let mut evidence = Vec::new();
        let mut score = 0u8;

        let protected_names = protected_names(ctx);
        let skeleton_labels = skeleton_labels(&skeleton);

        for protected in protected_names {
            if skeleton_labels.iter().any(|label| label == &protected) {
                score = score.max(85);
                reasons.push(format!(
                    "decoded domain skeleton matches protected name `{protected}`"
                ));
                evidence.push(("homoglyph.skeleton", skeleton.clone()));
                evidence.push(("homoglyph.protected_name", protected));
            }
        }

        if unicode_domain != domain {
            evidence.push(("idn.decoded", unicode_domain.clone()));
        }

        for (glyph, replacement) in suspicious_glyphs(&unicode_domain) {
            reasons.push(format!(
                "domain contains lookalike character `{glyph}` that may resemble `{replacement}`"
            ));
            evidence.push(("glyph", format!("{glyph}->{replacement}")));
            score = score.max(45);
        }

        if has_mixed_ascii_and_non_ascii_letters(&unicode_domain) {
            reasons.push("domain mixes ASCII and non-ASCII letters".to_string());
            evidence.push(("idn.script_mixing", "ascii+non_ascii".to_string()));
            score = score.max(45);
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

fn decode_domain_to_unicode(domain: &str) -> String {
    let (decoded, result) = idna::domain_to_unicode(domain);
    if result.is_ok() {
        decoded.to_ascii_lowercase()
    } else {
        domain.to_ascii_lowercase()
    }
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
    if name.len() >= 3 && !names.contains(&name) {
        names.push(name);
    }
}

fn skeleton_labels(skeleton: &str) -> Vec<String> {
    let mut labels = Vec::new();

    for label in skeleton.split('.') {
        push_name(label, &mut labels);
        for token in label.split(|ch: char| !ch.is_ascii_alphanumeric()) {
            push_name(token, &mut labels);
        }
    }

    labels
}

fn confusable_skeleton(input: &str) -> String {
    unicode_security::skeleton(input)
        .flat_map(char::to_lowercase)
        .collect()
}

fn has_mixed_ascii_and_non_ascii_letters(input: &str) -> bool {
    let has_ascii = input.chars().any(|c| c.is_ascii_alphabetic());
    let has_non_ascii = input.chars().any(|c| c.is_alphabetic() && !c.is_ascii());

    has_ascii && has_non_ascii
}

fn suspicious_glyphs(domain: &str) -> Vec<(char, char)> {
    domain
        .chars()
        .filter_map(|c| {
            homoglyph_map()
                .get(&c)
                .copied()
                .map(|replacement| (c, replacement))
        })
        .collect()
}

fn homoglyph_map() -> &'static BTreeMap<char, char> {
    static HOMOGLYPHS: OnceLock<BTreeMap<char, char>> = OnceLock::new();

    HOMOGLYPHS.get_or_init(|| {
        parse_homoglyphs_json(include_str!("../../data/homoglyphs.json"))
            .unwrap_or_else(fallback_homoglyphs)
    })
}

fn parse_homoglyphs_json(input: &str) -> Option<BTreeMap<char, char>> {
    let raw: BTreeMap<String, String> = serde_json::from_str(input).ok()?;
    let mut parsed = BTreeMap::new();

    for (glyph, replacement) in raw {
        let mut glyph_chars = glyph.chars();
        let glyph = glyph_chars.next()?;
        if glyph_chars.next().is_some() {
            return None;
        }

        let mut replacement_chars = replacement.chars();
        let replacement = replacement_chars.next()?;
        if replacement_chars.next().is_some() {
            return None;
        }

        parsed.insert(glyph, replacement);
    }

    Some(parsed)
}

fn fallback_homoglyphs() -> BTreeMap<char, char> {
    BTreeMap::from([
        ('а', 'a'),
        ('е', 'e'),
        ('о', 'o'),
        ('р', 'p'),
        ('с', 'c'),
        ('х', 'x'),
        ('і', 'i'),
        ('ӏ', 'l'),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CerberusConfig;

    #[test]
    fn detects_punycode_when_skeleton_matches_protected_name() {
        let mut config = CerberusConfig::default();
        config.brands.push("paypal".to_string());
        let ctx = DetectionContext::new(&config);
        let observation = DomainObservation::new("xn--pypal-4ve.com").unwrap();
        let findings = HomoglyphDetector.detect(&observation, &ctx).unwrap();

        assert_eq!(findings.len(), 1);
    }
}
