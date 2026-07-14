# 30-second demo

This demo is meant for the first GitHub scroll: one command, two suspicious domains, multiple explainable signals.

![Cerberus CT terminal demo](../assets/demo-terminal.gif)

Run the same scenario locally:

```bash
cargo run -q -p cerberus-cli -- scan-domain paypa1-login.com paypal-secure-login.com --config examples/demo_config.yaml --format json --grouped --summary
```

Artifacts:

| File | Purpose |
| --- | --- |
| `../assets/demo-terminal.gif` | Animated GIF rendered from a real CLI run |
| `sample-alert-summary.json` | Condensed JSON output for quick inspection |
| `cerberus-demo.cast` | Asciinema v2 cast source |
| `../assets/demo-terminal.svg` | Static terminal illustration fallback |

Regenerate the GIF from the real CLI command:

```bash
python -m pip install --user pillow
python scripts/render_demo_gif.py
```

To turn the cast source into a separate asciinema GIF, install a renderer such as `agg` and run:

```bash
agg docs/demo/cerberus-demo.cast docs/demo/cerberus-demo.gif
```
