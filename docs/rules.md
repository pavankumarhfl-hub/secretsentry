# Detection rules

| Rule | Severity | Detects |
|---|---|---|
| `aws.access-key` | high | AWS access-key identifier pattern |
| `github.token` | critical | GitHub token families |
| `private-key` | critical | PEM private-key headers |
| `google.api-key` | high | Google API-key pattern |
| `slack.token` | high | Slack token pattern |
| `generic.secret-assignment` | medium | Credential-like assignment with a literal value |

## False positives

Generic rules are intentionally broader and can match placeholders, tests, or configuration examples. Use `--exclude` for known non-production paths or a reviewed baseline for stable findings.

## Secret handling

Finding output contains only a short redaction and a fingerprint. SecretSentry never intentionally prints the complete matched value.
