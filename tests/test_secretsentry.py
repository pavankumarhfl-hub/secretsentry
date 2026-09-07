from pathlib import Path

from secretsentry import scan, to_sarif, main


def write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_detects_provider_tokens_and_generic_secret(tmp_path):
    write(tmp_path, "app.py", 'AWS="AKIA1234567890ABCDEF"\napi_key = "super-secret-value-123"\n')
    findings = scan(tmp_path)
    assert {f.rule_id for f in findings} >= {"aws.access-key", "generic.secret-assignment"}
    assert all("super-secret-value-123" not in f.redacted for f in findings)


def test_detects_github_and_private_key(tmp_path):
    write(tmp_path, "config.txt", "ghp_abcdefghijklmnopqrstuvwxyz123456\n-----BEGIN RSA PRIVATE KEY-----\n")
    findings = scan(tmp_path)
    assert any(f.rule_id == "github.token" for f in findings)
    assert any(f.rule_id == "private-key" for f in findings)


def test_skips_ignored_directories_and_binary(tmp_path):
    write(tmp_path, ".git/config", 'token = "hidden-secret-123"')
    write(tmp_path, "node_modules/pkg.js", 'token = "hidden-secret-123"')
    (tmp_path / "image.bin").write_bytes(b"token=secret\x00binary")
    assert scan(tmp_path) == []


def test_skips_large_files(tmp_path):
    write(tmp_path, "large.txt", "api_key = 'secret-123456789'\n")
    assert scan(tmp_path, max_size=5) == []


def test_baseline_suppresses_finding(tmp_path):
    write(tmp_path, "app.py", 'token = "secret-123456789"')
    findings = scan(tmp_path)
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"fingerprints": ["%s"]}' % findings[0].fingerprint, encoding="utf-8")
    assert main([str(tmp_path), "--baseline", str(baseline)]) == 0


def test_json_and_sarif_are_machine_readable(tmp_path, capsys):
    write(tmp_path, "app.py", 'token = "secret-123456789"')
    assert main([str(tmp_path), "--format", "json"]) == 1
    output = capsys.readouterr().out
    assert '"findings"' in output
    assert 'secret-123456789' not in output
    findings = scan(tmp_path)
    sarif = to_sarif(findings)
    assert '"version": "2.1.0"' in sarif
    assert 'secret-123456789' not in sarif


def test_no_fail_mode_returns_zero(tmp_path):
    write(tmp_path, "app.py", 'token = "secret-123456789"')
    assert main([str(tmp_path), "--no-fail"]) == 0
