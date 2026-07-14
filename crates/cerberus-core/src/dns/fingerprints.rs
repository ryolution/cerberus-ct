use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakeoverFingerprint {
    pub provider: String,
    pub cname_suffixes: Vec<String>,
    pub documentation_url: Option<String>,
    #[serde(default)]
    pub source_url: Option<String>,
}

pub fn default_takeover_fingerprints() -> Vec<TakeoverFingerprint> {
    serde_json::from_str(include_str!("../../data/takeover_fingerprints.json"))
        .unwrap_or_else(|_| builtin_takeover_fingerprints())
}

fn builtin_takeover_fingerprints() -> Vec<TakeoverFingerprint> {
    vec![
        fingerprint(
            "GitHub Pages",
            &["github.io"],
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ),
        fingerprint(
            "Heroku",
            &["herokuapp.com", "herokudns.com"],
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ),
        fingerprint(
            "Netlify",
            &["netlify.app"],
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ),
        fingerprint(
            "Vercel",
            &["vercel-dns.com", "vercel.app"],
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ),
        fingerprint(
            "Shopify",
            &["myshopify.com"],
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ),
        fingerprint(
            "Zendesk",
            &["zendesk.com"],
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ),
        fingerprint(
            "Fastly",
            &["fastly.net"],
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ),
        fingerprint(
            "AWS S3 Website",
            &[
                "s3.amazonaws.com",
                "s3-website",
                "s3-website-us-east-1.amazonaws.com",
                "s3-website-us-west-2.amazonaws.com",
            ],
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ),
        fingerprint(
            "Azure App Service",
            &[
                "azurewebsites.net",
                "cloudapp.net",
                "trafficmanager.net",
                "azurefd.net",
            ],
            "https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
        ),
        fingerprint(
            "ReadMe",
            &["readme.io"],
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ),
        fingerprint(
            "Canny",
            &["canny.io"],
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ),
        fingerprint(
            "LaunchRock",
            &["launchrock.com"],
            "https://github.com/EdOverflow/can-i-take-over-xyz",
        ),
    ]
}

fn fingerprint(provider: &str, suffixes: &[&str], url: &str) -> TakeoverFingerprint {
    TakeoverFingerprint {
        provider: provider.to_string(),
        cname_suffixes: suffixes.iter().map(|suffix| suffix.to_string()).collect(),
        documentation_url: Some(url.to_string()),
        source_url: Some("https://github.com/EdOverflow/can-i-take-over-xyz".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::default_takeover_fingerprints;

    #[test]
    fn loads_checked_in_takeover_fingerprints() {
        let fingerprints = default_takeover_fingerprints();

        assert!(
            fingerprints
                .iter()
                .any(|item| item.provider == "GitHub Pages")
        );
        assert!(fingerprints.iter().any(|item| item.provider == "Heroku"));
        assert!(fingerprints.len() >= 30);
        assert!(fingerprints.iter().all(|item| item.source_url.is_some()));
    }
}
