# SecretSentry

**Privacy-first secret detection for source trees and CI.**

SecretSentry finds credential-like material before it becomes a security incident—without printing the secret itself.

[![CI](https://github.com/pavankumarhfl-hub/secretsentry/actions/workflows/ci.yml/badge.svg)](https://github.com/pavankumarhfl-hub/secretsentry/actions/workflows/ci.yml)

## Why SecretSentry?

Secret scanners often create a bad trade-off: noisy false positives or dangerous output that exposes the very credential being investigated. SecretSentry is designed around three principles:

- **Never echo matched secret values.** Findings contain only a short redaction.
- **Fail safely in automation.** A finding returns a non-zero exit code by default.
- **Stay dependency-free at runtime.** The scanner uses Python's standard library.

## Detects

- AWS access-key identifiers
- GitHub token families
- Google API-key patterns
- Slack token patterns
- PEM private-key headers
- Generic API key / password / token / secret assignments

The detection engine is deliberately conservative and should be treated as a high-signal guardrail, not proof that a repository is secret-free.

## Install

```bash
python -m pip install .
```

Or run directly from a checkout:

```bash
PYTHONPATH=src python src/secretsentry.py .
```

## Usage

```bash
secretsentry .
secretsentry . --format json
secretsentry . --format sarif
secretsentry . --exclude examples --exclude fixtures
secretsentry . --max-size 500000
```

Exit codes:

- `0` — no unsuppressed findings (or `--no-fail`)
- `1` — one or more findings
- `2` — invalid CLI/path usage

### Baselines

Existing, reviewed findings can be suppressed with a small JSON baseline containing fingerprints:

```json
{"fingerprints": ["0123456789abcdef"]}
```

Then:

```bash
secretsentry . --baseline .secretsentry-baseline.json
```

Baselines suppress fingerprints; they do not store secret values.

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

For a security gate, keep the default failing behavior. For an informational scan, use `no-fail: true`.

## Architecture

```text
Repository
    │
    ▼
File walker ── ignores generated/vendor/binary/large files
    │
    ▼
Detection rules
    │
    ├── Provider-specific patterns
    └── Generic credential assignments
    │
    ▼
Findings ── path / line / rule / severity / redaction / fingerprint
    │
    ├── Text
    ├── JSON
    └── SARIF
```

## Security model

SecretSentry intentionally does **not** print full matches. It skips common generated/vendor directories, ignores binary and invalid UTF-8 content, and caps scanned file size. A scanner cannot guarantee absence of secrets; use it alongside secret rotation, least privilege, repository controls and provider-side detection.

See [`SECURITY.md`](SECURITY.md) for reporting guidance.

## Development

```bash
python -m pip install pytest
python -m pytest -q
```

CI tests Python 3.10, 3.11 and 3.12, builds the package, installs the CLI, and performs a smoke scan.

## Roadmap

### v0.1 — foundation

- [x] Provider and generic detection
- [x] Safe redaction
- [x] JSON and SARIF
- [x] Baseline suppression
- [x] GitHub Action
- [x] Multi-version CI

### v0.2 — deeper repository intelligence

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

MIT
