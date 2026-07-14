<p align="center">
  <img src="docs/assets/cerberus-logo.png" alt="Cerberus CT logo" width="320" />
</p>

<h1 align="center">Cerberus CT</h1>

<p align="center">
  <strong>Static CT phishing, brand abuse, and DNS exposure monitoring for Rust-first security workflows.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-workspace-black?style=for-the-badge&logo=rust" alt="Rust workspace" />
  <img src="https://img.shields.io/badge/Static_CT-ready-00c2d1?style=for-the-badge" alt="Static CT ready" />
  <img src="https://img.shields.io/badge/Async-Tokio-1f6feb?style=for-the-badge" alt="Tokio async" />
  <img src="https://img.shields.io/badge/CLI-Clap-7c3aed?style=for-the-badge" alt="Clap CLI" />
  <img src="https://img.shields.io/badge/Output-JSON%20%7C%20Webhook-0f766e?style=for-the-badge" alt="JSON and webhook output" />
</p>

<p align="center">
  Cerberus CT watches Static Certificate Transparency logs, extracts certificate domains,
  scores suspicious names, enriches findings with DNS evidence, and emits structured alerts
  that can feed research, monitoring, and incident response workflows.
</p>

![Cerberus CT terminal demo](docs/assets/demo-terminal.gif)

## Why It Exists

Certificate Transparency is one of the earliest public places where phishing domains,
brand abuse, fake login portals, and exposed DNS patterns can appear. The useful signal is
there, but raw CT data is noisy and Static CT changes how monitoring tools need to ingest it.

Cerberus CT is built for that newer model: checkpoints, tiles, decoded certificate entries,
domain extraction, explainable detection, optional DNS enrichment, dedupe, and machine-readable
output.

## What It Does

| Area | Capability |
| --- | --- |
| Static CT ingestion | Fetches checkpoints, calculates tile paths, downloads data tiles, and decodes entries |
| Certificate parsing | Extracts SAN domains and certificate metadata from PEM or DER payloads |
| Detection | Flags keyword, brand, typosquat, homoglyph, punycode, and composition signals |
| DNS enrichment | Adds IP, CNAME, resolver error, and conservative takeover candidate evidence |
| Alerting | Produces human output, JSON, grouped summaries, Slack payloads, and signed webhooks |
| Monitoring | Persists watch state, resumes from known positions, and deduplicates repeated alerts |

## 30-Second Start

Run the demo scan and look for grouped alerts with detector reasons and scores:

```bash
cargo run -q -p cerberus-cli -- scan-domain paypa1-login.com paypal-secure-login.com --config examples/demo_config.yaml --format json --grouped --summary
```

The GIF above is rendered from a real local CLI run. The source cast, sample JSON, and demo notes
live in [`docs/demo/`](docs/demo/README.md).

## Common Workflows

| Goal | Use this | Notes |
| --- | --- | --- |
| Check a suspicious domain | `scan-domain <domain>` | Fastest way to test a single indicator |
| Scan a Static CT tile | `scan-ct <log-url> --index <n>` | Useful for research and repeatable demos |
| Run one monitoring cycle | `watch-ct <log-url> --once` | Uses local state so repeated runs do not spam alerts |
| Add resolver context | `--dns` | Includes IP, CNAME, and resolver error evidence |
| Check DNS exposure | `--takeover` | Conservative candidate detection only, not proof of takeover |
| Integrate with tools | `--format json`, `--webhook-url` | JSON output and webhook delivery are automation friendly |

<details>
<summary>Copy/paste command recipes</summary>

```bash
# Validate a config file
cargo run -p cerberus-cli -- validate-config --config examples/basic_config.yaml

# Scan manual domains with grouped JSON output
cargo run -p cerberus-cli -- scan-domain paypa1-login.com --config examples/basic_config.yaml --format json --grouped --summary

# Scan one real Static CT data tile with demo rules
cargo run -p cerberus-cli -- scan-ct https://mon.sycamore.ct.letsencrypt.org/2026h2/ --index 0 --config examples/demo_config.yaml --format json --grouped --summary

# Run one watch cycle from a seeded tile
cargo run -p cerberus-cli -- watch-ct https://mon.sycamore.ct.letsencrypt.org/2026h2/ --config examples/demo_config.yaml --state .cerberus/demo-state.json --reset-state --seed-index 0 --once --format json --grouped --summary

# Enable DNS enrichment
cargo run -p cerberus-cli -- scan-domain paypa1-login.com --config examples/basic_config.yaml --format json --grouped --summary --dns

# Enable conservative takeover candidate checks
cargo run -p cerberus-cli -- scan-ct https://mon.sycamore.ct.letsencrypt.org/2026h2/ --index 0 --config examples/basic_config.yaml --format json --grouped --summary --takeover

# Suppress low-signal findings
cargo run -p cerberus-cli -- scan-ct https://mon.sycamore.ct.letsencrypt.org/2026h2/ --index 0 --config examples/demo_config.yaml --format json --grouped --summary --min-score 50
```

</details>

## Pipeline

```text
Static CT checkpoint -> data tile -> certificate event -> domain observation
  -> detection finding -> DNS enrichment -> grouped alert -> JSON/webhook output
```

<p align="center">
  <img src="docs/assets/cerberus-architecture.png" alt="Cerberus CT architecture diagram" width="100%" />
</p>

## Detection Model

Cerberus CT produces explainable findings. Each finding includes a detector name, severity,
score, reasons, and supporting evidence. Grouped alerts combine multiple findings for the same
domain, so a domain that matches keyword and typosquat logic ranks higher than a domain with one
weak signal.

| Signal | Example evidence |
| --- | --- |
| Keyword | Domain contains words such as `login`, `secure`, `verify`, or `wallet` |
| Brand | Label contains a protected brand token outside its official domains |
| Typosquat | Candidate label is close to a configured brand by edit distance |
| Homoglyph | Unicode or punycode patterns resemble protected names |
| Composition | Multiple low-level signals combine into a stronger alert |
| Takeover candidate | CNAME evidence points at a known external provider with inactive target evidence |

## Configuration

Use the checked-in configs as profiles rather than starting from scratch.

| Config | Purpose |
| --- | --- |
| [`examples/basic_config.yaml`](examples/basic_config.yaml) | Realistic, lower-noise monitoring defaults |
| [`examples/demo_config.yaml`](examples/demo_config.yaml) | Predictable demo output with visible low-signal alerts |
| [`examples/rules_config.yaml`](examples/rules_config.yaml) | Rule-focused example for tuning detectors |

<details>
<summary>Minimal config shape</summary>

```yaml
brands:
  - paypal
  - microsoft
  - github

official_domains:
  - paypal.com
  - microsoft.com
  - github.com

keywords:
  - login
  - secure
  - support
  - wallet
  - verify
  - reset

outputs:
  webhook_url: null
  webhook_signing_secret: null
  slack_webhook_url: null

dns:
  enabled: false
  takeover: false
  concurrency: 16

rules:
  min_score: 0
  allowlist_suffixes: []
```

</details>

## Webhooks

Webhook delivery is designed for automation. Set `--webhook-url` or `CERBERUS_WEBHOOK_URL`,
and optionally set `outputs.webhook_signing_secret` to add `X-Cerberus-Timestamp` and
`X-Cerberus-Signature` headers. The signature is HMAC-SHA256 over `timestamp.payload`.

<details>
<summary>Local webhook smoke test</summary>

```bash
python examples/webhook_receiver.py
cargo run -p cerberus-cli -- scan-domain paypa1-login.com --config examples/basic_config.yaml --format json --grouped --webhook-url http://127.0.0.1:8787/webhook
```

```powershell
$env:CERBERUS_WEBHOOK_URL="http://127.0.0.1:8787/webhook"
cargo run -p cerberus-cli -- scan-domain paypa1-login.com --config examples/basic_config.yaml --format json --grouped
Remove-Item Env:CERBERUS_WEBHOOK_URL
```

</details>

## Output Example

```json
{
  "summary": {
    "domain_count": 1,
    "finding_count": 2,
    "alert_count": 1,
    "message": "1 grouped alert produced"
  },
  "alerts": [
    {
      "domain": "paypa1-login.com",
      "severity": "critical",
      "score": 97,
      "detectors": ["keyword", "typosquat"],
      "reasons": [
        "domain contains suspicious keyword `login`",
        "domain label candidate `paypa1` is edit-distance 1 from `paypal`"
      ]
    }
  ]
}
```

## Commands

| Command | Purpose |
| --- | --- |
| `scan-domain` | Scan one or more manual domains |
| `scan-ct` | Scan one Static CT data tile |
| `watch-ct` | Run persistent Static CT monitoring |
| `fetch-checkpoint` | Fetch and parse a Static CT checkpoint |
| `fetch-tile` | Fetch a Static CT tile |
| `fetch-events` | Decode certificate events from a data tile |
| `validate-config` | Validate a YAML config file |
| `demo-watch` | Run the mock CT source |

Run `cargo run -p cerberus-cli -- --help` or open [`docs/usage.md`](docs/usage.md)
for the full CLI reference.

## Releases

Tagged releases build precompiled `cerberus` binaries for Linux x86_64, Windows x86_64,
macOS x86_64, and macOS ARM64 through the GitHub release workflow. Source builds remain
available through Cargo.

For an existing tag, run the `Release Binaries` workflow manually and pass the tag name.

## Project Layout

```text
cerberus-ct/
  crates/
    cerberus-core/    reusable detection, CT, DNS, output, and state logic
    cerberus-cli/     command line interface
  docs/               architecture, usage, demo, and model notes
  examples/           configs, mock events, state sample, webhook receiver
  scripts/            demo rendering and fingerprint maintenance helpers
  tests/              workspace-level integration coverage
```

## Quality Gates

<details>
<summary>Maintainer checks</summary>

```bash
cargo fmt --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
cargo deny check
```

</details>

## Limitations

| Limitation | Notes |
| --- | --- |
| Heuristic detection | Findings are signals, not final verdicts |
| DNS dependency | DNS output can change over time |
| Provider fingerprints | Takeover rules need ongoing maintenance |
| CT freshness | Latest tiles may return no matching alerts |
| Webhook delivery | Watch mode uses a durable local outbox with at-least-once delivery, so receivers should dedupe |
| Live services | Resolved third-party CNAMEs are treated as enrichment, not takeover evidence |

## Documentation

| File | Content |
| --- | --- |
| [`docs/architecture.md`](docs/architecture.md) | Core architecture and pipeline |
| [`docs/usage.md`](docs/usage.md) | Full command examples and CLI reference |
| [`docs/detection_model.md`](docs/detection_model.md) | Detection and scoring model |
| [`docs/limitations.md`](docs/limitations.md) | Known limitations and operating notes |
| [`docs/demo/README.md`](docs/demo/README.md) | Demo assets and sample output |

## Status

Cerberus CT is at MVP stage. It is suitable for learning, demonstrations, research workflows,
and early security monitoring experiments.

## License

This project is licensed under the repository license.
