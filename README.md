# SecretSentry 🛡️

**Privacy-first secret detection for source trees and CI.**

SecretSentry finds credential-like material before it becomes a security incident — without printing the secret itself.

**Maintainer:** Pavan Kumar BN

[![CI](https://github.com/pavankumarhfl-hub/secretsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/pavankumarhfl-hub/secretsentry/actions/workflows/ci.yml)

## Why SecretSentry?

Secret scanners need to balance detection quality, false positives, and the risk of exposing credentials in their own output. SecretSentry is designed around safe-by-default scanning:

- **Never echo matched secret values.** Findings expose only redacted context.
- **Fail safely in automation.** Findings return a non-zero exit code by default.
- **Dependency-free runtime.** The scanner uses Python's standard library.
- **Automation-ready.** JSON and SARIF support CI and code-scanning workflows.
- **Review-friendly.** Baselines suppress reviewed findings without storing secret values.

## Detects

- AWS access-key identifiers
- GitHub token families
- Google API-key patterns
- Slack token patterns
- PEM private-key headers
- Generic API key / password / token / secret assignments

The engine is intentionally conservative: it is a high-signal guardrail, not proof that a repository is secret-free.

## Install and use

```bash
python -m pip install .
secretsentry .
secretsentry . --format json
secretsentry . --format sarif
secretsentry . --exclude examples --exclude fixtures
secretsentry . --max-size 500000
```

Exit codes:

- `0` — no unsuppressed findings, or `--no-fail`
- `1` — one or more findings
- `2` — invalid CLI/path usage

## Baselines

Reviewed findings can be suppressed with fingerprints:

```json
{"fingerprints": ["0123456789abcdef"]}
```

Then run:

```bash
secretsentry . --baseline .secretsentry-baseline.json
```

A baseline stores fingerprints, not secret values.

## GitHub Action

```yaml
name: Secret scan

on:
  push:
  pull_request:

jobs:
  secretsentry:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pavankumarhfl-hub/secretsentry@main
        with:
          format: sarif
```

Keep the default failing behavior for a security gate; use `no-fail: true` for informational scans.

## Architecture

```text
Repository
    ↓
Safe file walker → exclusions / binary checks / size cap
    ↓
Detection engine → provider rules + generic rules
    ↓
Findings → redaction + fingerprint + severity
    ↓
Text / JSON / SARIF
```

## Security model

SecretSentry does not print full matches. It skips common generated/vendor directories, ignores binary and invalid UTF-8 content, and caps scanned file size. Use it alongside credential rotation, least privilege, repository controls, and provider-side detection.

See `SECURITY.md` for reporting guidance.

## Development

```bash
python -m pip install pytest
python -m pytest -q
```

CI covers Python 3.10, 3.11 and 3.12, package installation, CLI smoke tests, and Action validation.

## Roadmap

### v0.2 — deeper detection
- [ ] Git-history scanning with explicit opt-in
- [ ] Configurable rules and severity policy
- [ ] Higher-confidence entropy detection
- [ ] Pre-commit integration
- [ ] Performance benchmark suite

### v0.3 — team workflow
- [ ] Baseline management commands
- [ ] Finding deduplication across revisions
- [ ] PR-focused diff scanning
- [ ] Optional signed release artifacts

## License

MIT — Copyright (c) 2026 Pavan Kumar BN
