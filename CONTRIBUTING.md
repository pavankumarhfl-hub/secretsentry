# Contributing

Thanks for helping improve SecretSentry.

## Development

1. Fork the repository.
2. Create a focused branch.
3. Add or update tests for behavior changes.
4. Run `python -m pytest -q`.
5. Keep runtime dependencies in the standard library unless there is a strong reason otherwise.
6. Never commit real credentials to reproduce a test. Use obviously fake fixtures.

## Pull requests

Explain the problem, the detection behavior changed, false-positive considerations, and how the change was tested. Keep changes focused and avoid unrelated formatting churn.
