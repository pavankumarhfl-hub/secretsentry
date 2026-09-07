# Security Policy

## Reporting a vulnerability

Please do not open a public issue containing a live credential, exploit details that enable abuse, or other sensitive material.

Report security issues privately through the repository owner's available GitHub contact mechanisms. Include a safe reproduction, affected component, impact, and suggested mitigation where possible.

## Scanner limitations

SecretSentry is a defensive detection tool. It can miss secrets, produce false positives, or be bypassed by transformations and encodings. A finding should trigger investigation and credential rotation where appropriate; a clean scan is not a guarantee that no secret exists.
