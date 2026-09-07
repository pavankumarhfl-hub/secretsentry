from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

VERSION = "0.1.0"
DEFAULT_MAX_SIZE = 1_000_000
DEFAULT_IGNORES = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", "dist", "build",
    ".next", ".nuxt", "coverage", "vendor",
}

@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    pattern: re.Pattern[str]
    description: str

@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    path: str
    line: int
    column: int
    fingerprint: str
    redacted: str
    description: str


def rules() -> tuple[Rule, ...]:
    return (
        Rule("aws.access-key", "AWS access key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access-key identifier."),
        Rule("github.token", "GitHub token", "critical", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"), "GitHub authentication token pattern."),
        Rule("private-key", "Private key", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Private-key material header."),
        Rule("google.api-key", "Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API-key pattern."),
        Rule("slack.token", "Slack token", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "Slack token pattern."),
        Rule("generic.secret-assignment", "Generic secret assignment", "medium", re.compile(r"(?i)\b(?:api[_-]?key|secret|password|passwd|token|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*[\"']([^\"'\n]{8,})[\"']"), "Credential-like value assigned in source."),
    )


def iter_files(root: Path, ignores: set[str], max_size: int) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in ignores for part in path.parts):
            continue
        try:
            if path.stat().st_size > max_size:
                continue
        except OSError:
            continue
        yield path


def is_text(data: bytes) -> bool:
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def redact(value: str) -> str:
    if len(value) <= 8:
        return "[REDACTED]"
    return value[:4] + "…" + value[-4:]


def fingerprint(rule_id: str, path: str, line: int, value: str) -> str:
    raw = f"{rule_id}\0{path}\0{line}\0{value}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def scan(root: Path, ignores: set[str] | None = None, max_size: int = DEFAULT_MAX_SIZE) -> list[Finding]:
    ignores = DEFAULT_IGNORES | (ignores or set())
    found: list[Finding] = []
    compiled = rules()
    for path in iter_files(root, ignores, max_size):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if not is_text(data):
            continue
        text = data.decode("utf-8")
        display_path = str(path if root.is_file() else path.relative_to(root))
        for line_no, line in enumerate(text.splitlines(), 1):
            for rule in compiled:
                for match in rule.pattern.finditer(line):
                    value = match.group(0)
                    if rule.id == "generic.secret-assignment" and match.lastindex:
                        value = match.group(1)
                    found.append(Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        path=display_path,
                        line=line_no,
                        column=match.start() + 1,
                        fingerprint=fingerprint(rule.id, display_path, line_no, value),
                        redacted=redact(value),
                        description=rule.description,
                    ))
    return found


def apply_baseline(findings: list[Finding], baseline_path: Path | None) -> tuple[list[Finding], int]:
    if baseline_path is None or not baseline_path.exists():
        return findings, 0
    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
        ignored = set(data.get("fingerprints", []))
    except (OSError, ValueError):
        return findings, 0
    remaining = [f for f in findings if f.fingerprint not in ignored]
    return remaining, len(findings) - len(remaining)


def to_json(findings: list[Finding], root: Path, suppressed: int) -> str:
    return json.dumps({
        "version": VERSION,
        "path": str(root),
        "summary": {"findings": len(findings), "suppressed": suppressed},
        "findings": [asdict(f) for f in findings],
    }, indent=2)


def to_sarif(findings: list[Finding]) -> str:
    rules_data = [{"id": f.rule_id, "name": f.rule_name, "shortDescription": {"text": f.description}} for f in rules()]
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": "error" if f.severity in {"critical", "high"} else "warning",
            "message": {"text": f"{f.rule_name} detected ({f.redacted})"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path}, "region": {"startLine": f.line, "startColumn": f.column}}}],
        })
    return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "SecretSentry", "version": VERSION, "rules": rules_data}}, "results": results}]}, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SecretSentry: privacy-first secret scanner for source trees.")
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--exclude", action="append", default=[], help="Directory/file name to exclude; repeatable")
    parser.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE, help="Skip files larger than this many bytes")
    parser.add_argument("--baseline", type=Path, help="JSON baseline containing fingerprints to suppress")
    parser.add_argument("--no-fail", action="store_true", help="Always exit successfully")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"error: path does not exist: {args.path}", file=sys.stderr)
        return 2
    if args.max_size < 1:
        print("error: --max-size must be positive", file=sys.stderr)
        return 2
    findings = scan(root, set(args.exclude), args.max_size)
    findings, suppressed = apply_baseline(findings, args.baseline)
    if args.format == "json":
        print(to_json(findings, root, suppressed))
    elif args.format == "sarif":
        print(to_sarif(findings))
    else:
        if findings:
            print(f"SecretSentry {VERSION}: {len(findings)} finding(s)")
            for f in findings:
                print(f"{f.severity.upper():8} {f.path}:{f.line}:{f.column} {f.rule_name} [{f.redacted}]")
        else:
            print(f"SecretSentry {VERSION}: no secrets detected")
        if suppressed:
            print(f"suppressed by baseline: {suppressed}")
    return 1 if findings and not args.no_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
