# Usage Guide

## Scan one suspicious domain

```powershell
cargo run -p cerberus-cli -- scan-domain paypa1-login.com --config examples/basic_config.yaml --format json --grouped
```

## Run the 30-second demo

```powershell
cargo run -q -p cerberus-cli -- scan-domain paypa1-login.com paypal-secure-login.com --config examples/demo_config.yaml --format json --grouped --summary
```

See `docs/demo/` for a condensed sample output and asciinema cast source.

## Scan with DNS enrichment

```powershell
cargo run -p cerberus-cli -- scan-domain paypa1-login.com --config examples/basic_config.yaml --format json --grouped --dns
```

## Scan a real Static CT tile

```powershell
cargo run -p cerberus-cli -- scan-ct https://mon.sycamore.ct.letsencrypt.org/2026h2/ --index 0 --config examples/basic_config.yaml --format json --grouped
```

## Scan latest tile with summary

```powershell
cargo run -p cerberus-cli -- scan-ct https://mon.sycamore.ct.letsencrypt.org/2026h2/ --latest --config examples/basic_config.yaml --format json --grouped --summary
```

## Run persistent watch mode once

```powershell
cargo run -p cerberus-cli -- watch-ct https://mon.sycamore.ct.letsencrypt.org/2026h2/ --config examples/basic_config.yaml --state .cerberus/state.json --once --format json --grouped
```

## Run deterministic demo watch

```powershell
cargo run -p cerberus-cli -- watch-ct https://mon.sycamore.ct.letsencrypt.org/2026h2/ --config examples/basic_config.yaml --state .cerberus/demo-state.json --reset-state --seed-index 0 --once --format json --grouped
```

## Send alerts to a webhook

```powershell
cargo run -p cerberus-cli -- scan-domain paypa1-login.com --config examples/basic_config.yaml --format json --grouped --webhook-url http://127.0.0.1:8787/webhook
```

## Suppress noisy low-score alerts

```powershell
cargo run -p cerberus-cli -- scan-ct https://mon.sycamore.ct.letsencrypt.org/2026h2/ --index 0 --config examples/basic_config.yaml --format json --grouped --min-score 50
```

## Suppress a trusted suffix

```powershell
cargo run -p cerberus-cli -- scan-ct https://mon.sycamore.ct.letsencrypt.org/2026h2/ --index 0 --config examples/basic_config.yaml --format json --grouped --allowlist-suffix console.aws.amazon.com
```
