# Detection Model

Cerberus CT uses multiple detectors and enrichment layers. Each detector produces a `Finding`. Findings for the same domain can be grouped into a `DomainAlert`.

## Finding fields

```text
domain      normalized domain
detector    detector name
severity    info, low, medium, high, or critical
score       numeric score from 0 to 100
reasons     human-readable reasons
evidence    structured evidence values
```

## Detectors

### Keyword detector

Looks for configured suspicious words such as:

```text
login
verify
secure
account
reset
support
wallet
password
billing
invoice
auth
signin
```

### Brand detector

Looks for configured brand names in observed domains.

### Typosquat detector

Compares domain labels and useful hyphenated tokens to configured official domains.

Example:

```text
paypa1-login.com → paypal.com
```

### Homoglyph detector

Flags IDN/punycode and non-ASCII risk.

Example:

```text
xn--example.com
```

## DNS enrichment

When enabled, Cerberus adds DNS evidence:

```text
dns.resolved
dns.ip
dns.cname
dns.error
```

## Takeover candidate detection

When enabled, Cerberus checks CNAMEs against known third-party provider fingerprints. It only reports candidate risk conservatively and avoids flagging resolved CNAME targets as takeover candidates.

## Rule quality controls

`rules.min_score` suppresses low-score alerts.

`rules.allowlist_suffixes` suppresses trusted suffixes and helps reduce noise from known infrastructure.
