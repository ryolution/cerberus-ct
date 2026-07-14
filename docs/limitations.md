# Limitations

Cerberus CT is an early-warning system. It does not prove abuse by itself.

## CT limitations

- CT logs show certificate issuance, not domain registration.
- A domain may exist long before a certificate appears.
- Not every suspicious domain will obtain a public TLS certificate immediately.
- Some certificates contain many SAN domains, which can create repeated signals.

## Detection limitations

- Keyword findings can be noisy.
- Brand matches can be noisy for generic brand terms.
- Edit-distance typosquat checks are useful but not a complete phishing classifier.
- Homoglyph and IDN alerts require manual review.
- Composition findings are heuristics. They improve ranking, but they do not prove phishing intent.

## DNS and takeover limitations

- DNS state changes quickly.
- NXDOMAIN or no-answer results may be temporary.
- Subdomain takeover depends on provider-specific behavior.
- Takeover findings are candidates and require verification.
- A CNAME to a third-party provider is not enough to prove takeover risk.
- The provider fingerprint list is maintained from a community dataset and should be reviewed regularly.

## Operational limitations

- Watch webhook output uses a local durable outbox with at-least-once delivery. Receivers should deduplicate repeated payloads.
- Watch mode uses a local JSON state file, not a shared database.
- The project is not packaged as a Windows service or systemd unit yet.
