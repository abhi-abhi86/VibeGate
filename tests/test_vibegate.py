"""Tests for VibeGate core behavior: normalization, staged-only scanning, patching, suppression, AI fallback, CI."""

from __future__ import annotations

import json
import os
import subprocess

from vibegate import git
from vibegate.ai import _redact_secret_lines, run_ai_review
from vibegate.cli import main as cli_main
from vibegate.config import Config
from vibegate.engine import scan_remote_repo, scan_staged, scan_working_tree
from vibegate.models import Finding
from vibegate.patcher import apply_patch, propose_patch
from vibegate.scanners.base import ScanTarget
from vibegate.scanners.gitleaks import GitleaksScanner, mask
from vibegate.scanners.osv import OSVScanner
from vibegate.scanners.semgrep import SemgrepScanner
from vibegate.suppress import apply_suppressions, load_suppressions, save_suppression


def _init_git_repo(tmp_path) -> str:
    root = str(tmp_path)
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "dev@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Dev"], cwd=root, check=True)
    return root


def test_gitleaks_masks_secret(tmp_path):
    f = tmp_path / "cfg.py"
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    f.write_text(f'TOKEN = "{secret}"\n')
    target = ScanTarget(root=str(tmp_path), files=["cfg.py"], version="working tree")
    raw = [{"File": "cfg.py", "RuleID": "github-pat", "Secret": secret, "StartLine": 1, "EndLine": 1, "Description": "GitHub PAT"}]
    findings = GitleaksScanner().normalize(raw, target)
    assert len(findings) == 1
    assert secret not in findings[0].evidence
    assert mask(secret) in findings[0].evidence
    assert findings[0].severity == "critical"


def test_semgrep_normalizes_finding(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('cur.execute(f"SELECT * FROM t WHERE x = {x}")\n')
    target = ScanTarget(root=str(tmp_path), files=["app.py"], version="staged")
    data = {
        "results": [
            {
                "check_id": "vibegate.rules.python-sql-injection-fstring",
                "path": "app.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {
                    "severity": "ERROR",
                    "message": "SQL injection risk",
                    "metadata": {"vibegate_category": "injection", "vibegate_severity": "high", "confidence": "HIGH"},
                },
            }
        ]
    }
    findings = SemgrepScanner().normalize(data, target)
    assert len(findings) == 1
    assert findings[0].rule_id == "python-sql-injection-fstring"
    assert findings[0].category == "injection"
    assert findings[0].severity == "high"


def test_osv_normalizes_finding(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==2.0.1\n")
    target = ScanTarget(root=str(tmp_path), files=["requirements.txt"], version="staged")
    data = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "Flask", "version": "2.0.1", "ecosystem": "PyPI"},
                        "vulnerabilities": [{"id": "GHSA-xxxx", "summary": "Cookie issue", "affected": [{"package": {"name": "Flask"}, "ranges": [{"events": [{"fixed": "2.2.5"}]}]}]}],
                        "groups": [{"ids": ["GHSA-xxxx"], "aliases": ["CVE-2023-30861"], "max_severity": "7.5"}],
                    }
                ],
            }
        ]
    }
    findings = OSVScanner().normalize(data, target)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "2.2.5" in findings[0].remediation


def test_partially_staged_detection_and_staged_checkout(tmp_path):
    root = _init_git_repo(tmp_path)
    p = tmp_path / "app.py"
    p.write_text("x = 1\n")
    subprocess.run(["git", "add", "app.py"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=root, check=True, capture_output=True)

    # Stage v2, then modify working tree to v3 without staging
    p.write_text("x = 2  # staged\n")
    subprocess.run(["git", "add", "app.py"], cwd=root, check=True)
    p.write_text("x = 3  # unstaged\n")

    assert git.partially_staged(root) == ["app.py"]
    dest = tmp_path / "out"
    dest.mkdir()
    git.checkout_index(root, ["app.py"], str(dest))
    assert (dest / "app.py").read_text() == "x = 2  # staged\n"


def test_patch_proposal_and_apply(tmp_path):
    p = tmp_path / "app.py"
    p.write_text("def q(cur, customer):\n    cur.execute(f\"SELECT * FROM orders WHERE customer = '{customer}'\")\n")
    f = Finding(
        source="semgrep",
        rule_id="python-sql-injection-fstring",
        category="injection",
        severity="high",
        confidence="high",
        file="app.py",
        start_line=2,
        end_line=2,
        title="SQLi",
        evidence="",
        explanation="",
        remediation="",
    )
    prop = propose_patch(str(tmp_path), f)
    assert prop is not None
    assert "WHERE customer = ?" in prop.new_content
    assert "(customer,)" in prop.new_content
    apply_patch(str(tmp_path), prop)
    assert "WHERE customer = ?" in p.read_text()


def test_narrow_suppression(tmp_path):
    root = str(tmp_path)
    f1 = Finding("semgrep", "r1", "injection", "high", "high", "a.py", 10, 10, "t", "e", "x", "r")
    f2 = Finding("semgrep", "r1", "injection", "high", "high", "a.py", 25, 25, "t", "e", "x", "r")
    save_suppression(root, f1, "false positive in test helper", "dev@example.com")
    sups = load_suppressions(root)
    apply_suppressions([f1, f2], sups)
    assert f1.suppressed is True
    assert f2.suppressed is False


def test_ai_redacts_secrets_and_falls_back_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    redacted = _redact_secret_lines("KEY = 'super_sensitive_token_12345'\n@app.route('/')\ndef ok(): pass\n", {1})
    assert "super_sensitive_token_12345" not in redacted
    assert "[REDACTED" in redacted

    (tmp_path / "app.py").write_text("@app.route('/x')\ndef x(): pass\n")
    target = ScanTarget(root=str(tmp_path), files=["app.py"], version="staged")
    res = run_ai_review(target, [], Config(ai_enabled=True))
    assert res.status == "unavailable"


def test_cli_ci_json_empty_staged(tmp_path, capsys, monkeypatch):
    root = _init_git_repo(tmp_path)
    monkeypatch.chdir(root)
    rc = cli_main(["scan", "--ci", "--json", "--no-ai"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["policy"]["blocked"] is False
    assert payload["files_scanned"] == []


def test_is_git_url_and_remote_scan(tmp_path):
    assert git.is_git_url("https://github.com/org/repo.git")
    assert git.is_git_url("git@github.com:org/repo.git")
    assert not git.is_git_url("./demo")

    # Create a local bare-like source repo and scan it via file:// URL (no network needed)
    src = tmp_path / "src_repo"
    src.mkdir()
    root = _init_git_repo(src)
    (src / "app.py").write_text('cur.execute(f"SELECT * FROM users WHERE id = {uid}")\n')
    subprocess.run(["git", "add", "app.py"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-m", "add app"], cwd=root, check=True, capture_output=True)

    events = []
    report = scan_remote_repo(
        f"file://{root}",
        Config(scanners=["gitleaks"], ai_enabled=False),
        progress_cb=lambda ev, msg: events.append((ev, msg)),
    )
    assert report.scanned_version.startswith("git:file://")
    assert report.files_scanned == ["app.py"]
    cleanup_msgs = [msg for ev, msg in events if ev == "cleanup_done"]
    assert len(cleanup_msgs) == 1
    # Extract the temp dir path inside parentheses and confirm it was deleted
    cloned_dir = cleanup_msgs[0].split("(")[-1].rstrip(")")
    assert not os.path.exists(cloned_dir)


def test_scan_single_local_file_and_downloaded_folder(tmp_path):
    folder = tmp_path / "downloaded_project"
    folder.mkdir()
    single_file = folder / "local_model.py"
    single_file.write_text("x = 1\n")

    r_file = scan_working_tree(str(single_file), Config(scanners=["gitleaks"], ai_enabled=False))
    assert r_file.files_scanned == ["local_model.py"]
    assert r_file.scanned_version.startswith("file:")

    r_dir = scan_working_tree(str(folder), Config(scanners=["gitleaks"], ai_enabled=False))
    assert r_dir.files_scanned == ["local_model.py"]
    assert r_dir.scanned_version == "directory"
