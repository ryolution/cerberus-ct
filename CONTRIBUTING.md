# Contributing

Thanks for helping improve Cerberus CT.

## Development checks

Run these before opening a pull request:

```powershell
cargo fmt --check
cargo check
cargo test
```

## Design rules

- Keep detection logic in `cerberus-core`.
- Keep CLI parsing and printing in `cerberus-cli`.
- Keep JSON stdout clean; logs should go to stderr.
- Prefer typed errors in the core library.
- Prefer explainable findings with evidence over opaque scoring.
- Treat phishing and takeover results as candidates, not confirmed abuse.
- Add tests for every detector, parser, state, or output behavior change.

## Release process

- Update `Cargo.toml` workspace version.
- Run all checks.
- Test at least one real Static CT command.
- Tag the release only after tests and example commands pass locally.
