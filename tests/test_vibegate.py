"""Tests for VibeGate core behavior: normalization, staged-only scanning, patching, suppression, AI fallback, CI."""

from __future__ import annotations

import json
import os
import subprocess

from vibegate import git
from vibegate.ai import _redact_secret_lines, run_ai_review
from vibegate.cli import main as cli_main
from vibegate.config import Config
from vibegate.engine import scan_push, scan_remote_repo, scan_staged, scan_working_tree
from vibegate.models import Finding
from vibegate.patcher import apply_all_safe_fixes, apply_patch, propose_patch
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

    # Create a local source repo with main + a second branch containing a secret
    src = tmp_path / "src_repo"
    src.mkdir()
    root = _init_git_repo(src)
    (src / "app.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "app.py"], cwd=root, check=True)
    subprocess.run(["git", "commit", "--no-verify", "-m", "add app"], cwd=root, check=True, capture_output=True)

    subprocess.run(["git", "checkout", "-b", "feature-pr"], cwd=root, check=True, capture_output=True)
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    (src / "secret.py").write_text(f'TOKEN = "{secret}"\n')
    subprocess.run(["git", "add", "secret.py"], cwd=root, check=True)
    subprocess.run(["git", "commit", "--no-verify", "-m", "add secret on branch"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "checkout", "-"], cwd=root, check=True, capture_output=True)

    events = []
    report = scan_remote_repo(
        f"file://{root}",
        Config(scanners=["gitleaks"], ai_enabled=False),
        progress_cb=lambda ev, msg: events.append((ev, msg)),
    )
    assert report.scanned_version.startswith("git:file://")
    assert report.files_scanned == ["app.py"]
    assert any(rs["ref"] == "branch:feature-pr" and rs["finding_count"] == 1 for rs in report.ref_summaries)
    assert any(f.file == "secret.py" and f.scanned_version == "branch:feature-pr" for f in report.findings)
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


def test_cli_rules_and_doctor(capsys):
    assert cli_main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "python-sql-injection-fstring" in out
    assert "python-ssrf-requests" in out

    assert cli_main(["doctor"]) == 0
    doc_out = capsys.readouterr().out
    assert "gitleaks:" in doc_out
    assert "semgrep:" in doc_out


def test_parallel_execution_and_offline_ai_fallback(tmp_path, monkeypatch):
    import httpx

    def fake_post(*_args, **_kwargs):
        raise httpx.ConnectError("offline")

    monkeypatch.setenv("GEMINI_API_KEY", "dummy-key")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr("httpx.post", fake_post)

    (tmp_path / "app.py").write_text('@app.route("/api/user/<int:user_id>")\ndef get_u(user_id): return {}\n')
    report = scan_working_tree(str(tmp_path), Config(scanners=["gitleaks"], ai_enabled=True))
    assert report.ai_result.status == "unavailable"
    assert len(report.scanner_results) == 1
    assert report.duration_ms >= 0


def test_vibegate_init_creates_config_and_hook(tmp_path, monkeypatch):
    root = _init_git_repo(tmp_path)
    monkeypatch.chdir(root)
    assert cli_main(["init"]) == 0
    assert (tmp_path / ".vibegate.toml").is_file()
    assert (tmp_path / ".git" / "hooks" / "pre-commit").is_file()


def test_one_keystroke_auto_patcher_all_four_types(tmp_path):
    root = _init_git_repo(tmp_path)
    app_file = tmp_path / "app.py"
    req_file = tmp_path / "requirements.txt"
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    app_file.write_text(
        f'GITHUB_TOKEN = "{secret}"\n'
        'def q(cur, customer):\n'
        '    cur.execute(f"SELECT * FROM orders WHERE customer = \'{customer}\'")\n'
        '@app.route("/api/user/<int:user_id>")\n'
        'def get_u(user_id):\n'
        '    return jsonify({"id": user_id})\n'
    )
    req_file.write_text("PyYAML==5.3.1\n")
    subprocess.run(["git", "add", "app.py", "requirements.txt"], cwd=root, check=True)

    findings = [
        Finding("gitleaks", "github-pat", "secret", "critical", "high", "app.py", 1, 1, "Secret", "", "", ""),
        Finding("semgrep", "python-sql-injection-fstring", "injection", "high", "high", "app.py", 3, 3, "SQLi", "", "", ""),
        Finding("semgrep", "python-flask-route-missing-auth", "access_control", "high", "medium", "app.py", 4, 6, "IDOR", "", "", ""),
        Finding("osv-scanner", "GHSA-test", "dependency", "high", "high", "requirements.txt", 1, 1, "PyYAML", "", "", "", extra={"package": "PyYAML", "fixed_versions": ["5.4"]}),
    ]
    applied, skipped = apply_all_safe_fixes(root, findings, restage=True)
    assert len(applied) == 4
    assert skipped == []

    patched_app = app_file.read_text()
    assert 'os.getenv("GITHUB_TOKEN", "")' in patched_app
    assert "WHERE customer = ?" in patched_app
    assert 'session.get("user_id") != user_id' in patched_app
    assert "PyYAML>=5.4" in req_file.read_text()
    assert f"GITHUB_TOKEN={secret}" in (tmp_path / ".env").read_text()
    assert "GITHUB_TOKEN=" in (tmp_path / ".env.example").read_text()


def test_pre_push_hook_install_and_scan_push(tmp_path, monkeypatch):
    root = _init_git_repo(tmp_path)
    monkeypatch.chdir(root)
    assert cli_main(["hook", "install", root, "--which", "all"]) == 0
    assert (tmp_path / ".git" / "hooks" / "pre-commit").is_file()
    assert (tmp_path / ".git" / "hooks" / "pre-push").is_file()

    # Create an unpushed commit containing a secret
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    (tmp_path / "leak.py").write_text(f'TOKEN = "{secret}"\n')
    subprocess.run(["git", "add", "leak.py"], cwd=root, check=True)
    subprocess.run(["git", "commit", "--no-verify", "-m", "add leak"], cwd=root, check=True, capture_output=True)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()

    report = scan_push(root, Config(scanners=["gitleaks"], ai_enabled=False), ref_lines=[f"refs/heads/main {sha} refs/heads/main {'0'*40}"])
    assert report.policy_blocked is True
    assert len(report.findings) == 1
    assert report.findings[0].file == "leak.py"


def test_ignore_update_suggestion_unblocks_policy():
    from vibegate.engine import ScanReport, evaluate_policy
    from vibegate.ai import AIReviewResult

    dep = Finding("osv-scanner", "GHSA-test", "dependency", "high", "high", "requirements.txt", 1, 1, "PyYAML", "", "", "Upgrade PyYAML")
    cfg = Config()
    blocked, _ = evaluate_policy([dep], [], cfg)
    assert blocked is True

    dep.dismissed = True
    dep.dismiss_note = "update suggestion ignored by developer"
    blocked_after, _ = evaluate_policy([dep], [], cfg)
    assert blocked_after is False


class _MockHTTPResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import httpx
            req = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
            resp = httpx.Response(self.status_code, request=req)
            raise httpx.HTTPStatusError(f"HTTP {self.status_code}", request=req, response=resp)

    def json(self) -> dict:
        return self._payload


def _gemini_payload(verdict: dict) -> dict:
    return {"candidates": [{"content": {"parts": [{"text": json.dumps(verdict)}]}}]}


def _groq_payload(verdict: dict) -> dict:
    return {"choices": [{"message": {"content": json.dumps(verdict)}}]}


def test_consensus_unanimous_safe(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    monkeypatch.setenv("GROQ_API_KEY", "q-key")
    (tmp_path / "app.py").write_text('@app.route("/api/user/<int:user_id>")\ndef u(user_id): pass\n')
    target = ScanTarget(root=str(tmp_path), files=["app.py"], version="staged")

    def fake_post(url, **_kwargs):
        if "generativelanguage.googleapis.com" in url:
            return _MockHTTPResponse(_gemini_payload({"is_vulnerable": False, "findings": [], "reasoning": "Gemini: ownership verified."}))
        return _MockHTTPResponse(_groq_payload({"is_vulnerable": False, "findings": [], "reasoning": "Groq: auth check present."}))

    monkeypatch.setattr("httpx.post", fake_post)
    res = run_ai_review(target, [], Config(ai_enabled=True, consensus_enabled=True))
    assert res.status == "ok"
    assert res.consensus_status == "2/2_safe"
    assert res.findings == []
    assert "Gemini:" in res.reasoning_trace["gemini"]
    assert "Groq:" in res.reasoning_trace["groq"]


def test_consensus_layer1_vulnerable_skips_layer2(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    monkeypatch.setenv("GROQ_API_KEY", "q-key")
    (tmp_path / "app.py").write_text('@app.route("/api/user/<int:user_id>")\ndef u(user_id): pass\n')
    target = ScanTarget(root=str(tmp_path), files=["app.py"], version="staged")

    g_finding = {"file": "app.py", "start_line": 2, "end_line": 2, "severity": "high", "confidence": "high", "title": "IDOR", "evidence": "def u", "explanation": "Missing check", "remediation": "Check session"}
    groq_called = False

    def fake_post(url, **_kwargs):
        nonlocal groq_called
        if "generativelanguage.googleapis.com" in url:
            return _MockHTTPResponse(_gemini_payload({"is_vulnerable": True, "findings": [g_finding], "reasoning": "Gemini found IDOR."}))
        groq_called = True
        return _MockHTTPResponse(_groq_payload({"is_vulnerable": False, "findings": [], "reasoning": "Should not be called."}))

    monkeypatch.setattr("httpx.post", fake_post)
    res = run_ai_review(target, [], Config(ai_enabled=True, consensus_enabled=True))
    assert groq_called is False
    assert res.status == "ok"
    assert res.consensus_status == "single"
    assert len(res.findings) == 1
    assert "Gemini found IDOR." in res.reasoning_trace["gemini"]


def test_consensus_disagreement_triggers_judge(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    monkeypatch.setenv("GROQ_API_KEY", "q-key")
    (tmp_path / "app.py").write_text('@app.route("/api/user/<int:user_id>")\ndef u(user_id): pass\n')
    target = ScanTarget(root=str(tmp_path), files=["app.py"], version="staged")

    calls = {"gemini": 0}
    j_finding = {"file": "app.py", "start_line": 2, "end_line": 2, "severity": "high", "confidence": "high", "title": "Confirmed IDOR", "evidence": "def u", "explanation": "No ownership check", "remediation": "Verify user_id"}

    def fake_post(url, **_kwargs):
        if "generativelanguage.googleapis.com" in url:
            calls["gemini"] += 1
            if calls["gemini"] == 1:
                return _MockHTTPResponse(_gemini_payload({"is_vulnerable": False, "findings": [], "reasoning": "Gemini thought safe."}))
            return _MockHTTPResponse(_gemini_payload({"is_vulnerable": True, "findings": [j_finding], "reasoning": "Judge confirmed IDOR."}))
        return _MockHTTPResponse(_groq_payload({"is_vulnerable": True, "findings": [j_finding], "reasoning": "Groq flagged IDOR."}))

    monkeypatch.setattr("httpx.post", fake_post)
    res = run_ai_review(target, [], Config(ai_enabled=True, consensus_enabled=True))
    assert calls["gemini"] == 2
    assert res.status == "ok"
    assert res.consensus_status == "debate_resolved"
    assert len(res.findings) == 1
    assert res.reasoning_trace["judge"] == "Judge confirmed IDOR."


def test_consensus_groq_429_falls_back_to_gemini(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    monkeypatch.setenv("GROQ_API_KEY", "q-key")
    (tmp_path / "app.py").write_text('@app.route("/api/user/<int:user_id>")\ndef u(user_id): pass\n')
    target = ScanTarget(root=str(tmp_path), files=["app.py"], version="staged")

    def fake_post(url, **_kwargs):
        if "generativelanguage.googleapis.com" in url:
            return _MockHTTPResponse(_gemini_payload({"is_vulnerable": False, "findings": [], "reasoning": "Gemini found no issues."}))
        return _MockHTTPResponse({}, status_code=429)

    monkeypatch.setattr("httpx.post", fake_post)
    res = run_ai_review(target, [], Config(ai_enabled=True, consensus_enabled=True))
    assert res.status == "ok"
    assert res.consensus_status == "single_fallback"
    assert res.findings == []
    assert "Gemini found no issues." in res.reasoning_trace["gemini"]
    assert "fallback" in res.reasoning_trace["groq"]


def test_consensus_gemini_404_falls_back_to_groq(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    monkeypatch.setenv("GROQ_API_KEY", "q-key")
    (tmp_path / "app.py").write_text('@app.route("/api/user/<int:user_id>")\ndef u(user_id): pass\n')
    target = ScanTarget(root=str(tmp_path), files=["app.py"], version="staged")

    def fake_post(url, **_kwargs):
        if "generativelanguage.googleapis.com" in url:
            return _MockHTTPResponse({}, status_code=404)
        return _MockHTTPResponse(_groq_payload({"is_vulnerable": False, "findings": [], "reasoning": "Groq verified no IDOR."}))

    monkeypatch.setattr("httpx.post", fake_post)
    res = run_ai_review(target, [], Config(ai_enabled=True, consensus_enabled=True))
    assert res.status == "ok"
    assert res.consensus_status == "single_fallback"
    assert "Groq verified no IDOR." in res.reasoning_trace["groq"]
    assert "fallback" in res.reasoning_trace["gemini"]


def test_distinct_report_entries_per_vulnerability(tmp_path):
    from io import StringIO
    from rich.console import Console
    from vibegate.ui import render_summary, threat_impact

    (tmp_path / "app.py").write_text(
        'API_KEY = "ghp_****************"\n'
        'def q(cur, uid):\n'
        '    cur.execute(f"SELECT * FROM u WHERE id = {uid}")\n'
    )
    (tmp_path / "utils.py").write_text(
        'def parse():\n'
        '    try:\n'
        '        return 1\n'
        '    except:\n'
        '        return 0\n'
    )
    cfg = Config(scanners=["semgrep"], ai_enabled=False)
    report = scan_working_tree(str(tmp_path), cfg)
    # Add a simulated secret finding to cover multiple files & categories
    secret_f = Finding(
        "gitleaks", "github-pat", "secret", "critical", "high", "app.py", 1, 1,
        "GitHub PAT", 'API_KEY = "ghp_****************"', "Hardcoded token in source.", "Move to .env.",
        code_snippet='API_KEY = "ghp_****************"', scanned_version="git:https://example.com/repo.git",
    )
    report.findings.insert(0, secret_f)
    report.scanned_version = "git:https://example.com/repo.git"

    # Assert distinct code_snippet, issue, threat, and fix across findings
    assert len(report.findings) >= 3
    snippets = {f.code_snippet for f in report.findings}
    threats = {threat_impact(f) for f in report.findings}
    issues = {f.explanation for f in report.findings}
    fixes = {f.remediation for f in report.findings}
    assert len(snippets) == len(report.findings)
    assert len(threats) == len(report.findings)
    assert len(issues) == len(report.findings)
    assert len(fixes) == len(report.findings)

    buf = StringIO()
    render_summary(report, Console(file=buf, width=120))
    rendered = buf.getvalue()
    assert "app.py:1" in rendered
    assert "app.py:3" in rendered
    assert "utils.py:2-5" in rendered
    assert "/var/folders/" not in rendered


def test_detect_stacks_django_flask_fastapi_express(tmp_path):
    from vibegate.detect import detect_stacks

    dj = tmp_path / "dj"
    dj.mkdir()
    (dj / "manage.py").write_text("import django\n")
    (dj / "settings.py").write_text("DEBUG = True\n")
    assert detect_stacks(ScanTarget(root=str(dj), files=["manage.py", "settings.py"], version="working")) == ["django"]

    fl = tmp_path / "fl"
    fl.mkdir()
    (fl / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    assert detect_stacks(ScanTarget(root=str(fl), files=["app.py"], version="working")) == ["flask"]

    fa = tmp_path / "fa"
    fa.mkdir()
    (fa / "requirements.txt").write_text("fastapi==0.115.0\nuvicorn\n")
    (fa / "main.py").write_text("print('hi')\n")
    assert detect_stacks(ScanTarget(root=str(fa), files=["requirements.txt", "main.py"], version="working")) == ["fastapi"]

    ex = tmp_path / "ex"
    ex.mkdir()
    (ex / "package.json").write_text('{"name": "api", "dependencies": {"express": "^4.19.0"}}\n')
    (ex / "index.js").write_text("console.log('hi');\n")
    assert detect_stacks(ScanTarget(root=str(ex), files=["package.json", "index.js"], version="working")) == ["express"]


def test_stack_rule_paths_and_django_semgrep_rules(tmp_path):
    from vibegate.detect import stack_rule_paths

    paths = stack_rule_paths(["django"])
    assert any(p.endswith("semgrep.yml") for p in paths)
    assert any(p.endswith("django.yml") for p in paths)
    assert not any(p.endswith("flask.yml") for p in paths)

    (tmp_path / "manage.py").write_text("#!/usr/bin/env python\n")
    (tmp_path / "settings.py").write_text("DEBUG = True\nALLOWED_HOSTS = ['*']\n")
    (tmp_path / "views.py").write_text(
        "from django.views.decorators.csrf import csrf_exempt\n"
        "from django.db.models.expressions import RawSQL\n"
        "@csrf_exempt\n"
        "def update_item(request):\n"
        "    return Item.objects.annotate(val=RawSQL('SELECT 1', []))\n"
    )
    report = scan_working_tree(str(tmp_path), Config(scanners=["semgrep"], ai_enabled=False))
    assert report.detected_stacks == ["django"]
    rule_ids = {f.rule_id for f in report.findings}
    assert "debug-enabled" in rule_ids
    assert "allowed-hosts-wildcard" in rule_ids
    assert "csrf-exempt" in rule_ids
    assert "raw-sql-extra" in rule_ids
    assert "missing-login-required" in rule_ids


def test_ai_prompt_includes_stack_guidance(tmp_path, monkeypatch):
    from vibegate.detect import stack_ai_guidance

    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    (tmp_path / "views.py").write_text("def profile(request, pk):\n    pass\n")
    target = ScanTarget(root=str(tmp_path), files=["views.py"], version="staged")
    captured_prompts: list[str] = []

    def fake_post(url, **kwargs):
        captured_prompts.append(json.dumps(kwargs.get("json", {})))
        return _MockHTTPResponse(_gemini_payload({"is_vulnerable": False, "findings": [], "reasoning": "Safe."}))

    monkeypatch.setattr("httpx.post", fake_post)
    guidance = stack_ai_guidance(["django"])
    res = run_ai_review(target, [], Config(ai_enabled=True, consensus_enabled=False), stack_guidance=guidance)
    assert res.status == "ok"
    assert captured_prompts
    assert "This is a Django project" in captured_prompts[0]
    assert "get_object_or_404(Model, pk=id, owner=request.user)" in captured_prompts[0]


def test_ai_review_covers_all_files_across_batches_and_skips_vendor(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    (tmp_path / "CollegeERP").mkdir()
    (tmp_path / "CollegeERP" / "settings.py").write_text("DEBUG = True\n")
    (tmp_path / "info").mkdir()
    (tmp_path / "info" / "views.py").write_text("def edit(request):\n    pass\n")
    (tmp_path / "info" / "models.py").write_text("class Student:\n    pass\n")
    (tmp_path / "info" / "static" / "vendor").mkdir(parents=True)
    (tmp_path / "info" / "static" / "vendor" / "jquery.dataTables.min.js").write_text("var x=1;\n")

    target = ScanTarget(
        root=str(tmp_path),
        files=[
            "CollegeERP/settings.py",
            "info/views.py",
            "info/models.py",
            "info/static/vendor/jquery.dataTables.min.js",
        ],
        version="working",
    )

    def fake_post(url, **kwargs):
        prompt = kwargs["json"]["contents"][0]["parts"][0]["text"]
        # Return a finding using basename for settings.py to also verify _resolve_valid_file
        if "CollegeERP/settings.py" in prompt:
            f = {"file": "settings.py", "start_line": 1, "end_line": 1, "severity": "high", "confidence": "high", "title": "Debug True", "evidence": "DEBUG = True", "explanation": "Debug on", "remediation": "Set False"}
        elif "info/views.py" in prompt:
            f = {"file": "info/views.py", "start_line": 1, "end_line": 1, "severity": "high", "confidence": "high", "title": "Missing Auth", "evidence": "def edit", "explanation": "No auth", "remediation": "Add @login_required"}
        else:
            f = {"file": "info/models.py", "start_line": 1, "end_line": 1, "severity": "medium", "confidence": "medium", "title": "Model Issue", "evidence": "class Student", "explanation": "Weak field", "remediation": "Fix field"}
        return _MockHTTPResponse(_gemini_payload({"is_vulnerable": True, "findings": [f], "reasoning": "Reviewed file."}))

    monkeypatch.setattr("httpx.post", fake_post)
    cfg = Config(ai_enabled=True, consensus_enabled=False, ai_max_files=1)
    res = run_ai_review(target, [], cfg)
    assert res.status == "ok"
    found_files = {f.file for f in res.findings}
    assert found_files == {"CollegeERP/settings.py", "info/views.py", "info/models.py"}


def test_table_renders_access_example_column_after_status(tmp_path):
    from io import StringIO
    from rich.console import Console
    from vibegate.ai import AIReviewResult
    from vibegate.engine import ScanReport
    from vibegate.ui import render_summary

    f1 = Finding(
        "ai-review", "ai-injection", "injection", "high", "high", "login/login.php", 11, 11,
        "SQL Injection in Login Query", "$q = \"SELECT * FROM users WHERE user='$u'\"",
        "Unsanitized input in SQL query.", "Use prepared statements.",
        extra={"access_example": "POST user=' OR '1'='1' --"},
    )
    f2 = Finding(
        "ai-review", "ai-xss", "injection", "medium", "medium", "pages/contact.php", 121, 121,
        "Reflected Cross-Site Scripting (XSS)", "echo $_GET['msg'];",
        "Unescaped GET parameter.", "Use htmlspecialchars().",
    )
    report = ScanReport(
        target_root=str(tmp_path),
        scanned_version="working",
        files_scanned=["login/login.php", "pages/contact.php"],
        partially_staged_files=[],
        findings=[f1, f2],
        scanner_results=[],
        ai_result=AIReviewResult("ok", [f1, f2], "ok"),
    )
    buf = StringIO()
    render_summary(report, Console(file=buf, width=180))
    rendered = buf.getvalue()
    assert "How to Access / Example" in rendered
    assert "POST user=' OR '1'='1' --" in rendered
    assert "<script>alert(1)</script>" in rendered


def test_web_audit_passive_checks_and_cli(monkeypatch):
    import httpx
    from vibegate.web_audit import audit_domain, is_web_target, normalize_web_url

    assert is_web_target("example.com") is True
    assert is_web_target("https://myapp.vercel.app") is True
    assert is_web_target("https://github.com/owner/repo.git") is False
    assert normalize_web_url("myapp.com") == "https://myapp.com"
    assert normalize_web_url("localhost:8000") == "http://localhost:8000"

    class _FakeResp:
        def __init__(self, url, status_code=200, headers=None, text="<html>ok</html>"):
            self.url = url
            self.status_code = status_code
            self.headers = httpx.Headers(headers or [])
            self.text = text

    class _FakeClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get(self, url, **_kwargs):
            if url.endswith("/.env"):
                return _FakeResp(url, 200, text="SECRET_KEY=supersecret123\n")
            if url.endswith("/.git/HEAD"):
                return _FakeResp(url, 404, text="Not Found")
            return _FakeResp(
                "http://myapp.example.com/",
                200,
                headers=[
                    ("Server", "nginx/1.18.0"),
                    ("Access-Control-Allow-Origin", "*"),
                    ("Set-Cookie", "session=abc123; Path=/"),
                ],
                text=(
                    '<script>const k="AIzaSyDummyExposedKey1234567890";</script>'
                    '<form method="post" action="/pay"><input type="password" name="pw"></form>'
                ),
            )

    monkeypatch.setattr("vibegate.web_audit.httpx.Client", _FakeClient)
    report = audit_domain("myapp.co.in", Config(fail_on="high"))
    assert report.scanned_version == "web:https://myapp.co.in"
    assert report.policy_blocked is True
    rule_ids = {f.rule_id for f in report.findings}
    assert "web.http.no-https" in rule_ids
    assert "web.header.missing-csp" in rule_ids
    assert "web.header.missing-xfo" in rule_ids
    assert "web.header.missing-permissions-policy" in rule_ids
    assert "web.header.missing-cache-control" in rule_ids
    assert "web.cors.wildcard" in rule_ids
    assert "web.cookie.missing-flags" in rule_ids
    assert "web.header.version-disclosure" in rule_ids
    assert "web.exposure.dotenv" in rule_ids
    assert "web.body.exposed-secret" in rule_ids
    assert "web.body.form-no-csrf" in rule_ids
    assert "web.body.password-over-http" in rule_ids

    from io import StringIO
    from rich.console import Console
    from vibegate.ui import render_summary, threat_impact, vulnerability_type

    dotenv_f = next(f for f in report.findings if f.rule_id == "web.exposure.dotenv")
    assert vulnerability_type(dotenv_f) == "Exposed Secret / Credential Leak"
    assert "database passwords" in threat_impact(dotenv_f)

    buf = StringIO()
    render_summary(report, Console(file=buf, width=160))
    rendered = buf.getvalue()
    assert "Type" in rendered
    assert "If Unfixed" in rendered
    assert "A-to-Z Hosted Site Security Checklist" in rendered


def test_discover_ai_providers_scales_arbitrarily(monkeypatch):
    from vibegate.ai import discover_ai_providers

    for k in list(os.environ):
        if "API_KEY" in k or k.startswith("CUSTOM_AI_"):
            monkeypatch.delenv(k, raising=False)

    monkeypatch.setenv("GEMINI_API_KEY", "gem-1")
    monkeypatch.setenv("GEMINI_API_KEYS", "gem-2,gem-3")
    for i in range(1, 11):
        monkeypatch.setenv(f"GROQ_API_KEY_{i}", f"groq-{i}")
    monkeypatch.setenv("OPENAI_API_KEY", "oa-1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ant-1")
    monkeypatch.setenv("CUSTOM_AI_KEY_1", "cust-1")
    monkeypatch.setenv("CUSTOM_AI_URL_1", "https://llm.internal/v1/chat/completions")

    providers = discover_ai_providers(Config())
    # 3 Gemini + 10 Groq + 1 OpenAI + 1 Anthropic + 1 Custom = 16 keys discovered automatically
    assert len(providers) == 16
    assert {p.kind for p in providers} == {"gemini", "openai_compat", "anthropic"}


def test_n_provider_consensus_and_judge(tmp_path, monkeypatch):
    for k in list(os.environ):
        if "API_KEY" in k or k.startswith("CUSTOM_AI_"):
            monkeypatch.delenv(k, raising=False)

    monkeypatch.setenv("GEMINI_API_KEY", "gem-1")
    monkeypatch.setenv("GROQ_API_KEY", "groq-1")
    monkeypatch.setenv("OPENAI_API_KEY", "oa-1")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-1")

    (tmp_path / "app.py").write_text('@app.route("/api/user/<int:user_id>")\ndef u(user_id): pass\n')
    target = ScanTarget(root=str(tmp_path), files=["app.py"], version="staged")

    f_idor = {"file": "app.py", "start_line": 2, "end_line": 2, "severity": "high", "confidence": "high", "title": "IDOR", "evidence": "def u", "explanation": "Missing check", "remediation": "Verify owner"}
    gem_calls = {"n": 0}

    def fake_post(url, **_kwargs):
        if "generativelanguage.googleapis.com" in url:
            gem_calls["n"] += 1
            if gem_calls["n"] == 1:
                return _MockHTTPResponse(_gemini_payload({"is_vulnerable": False, "findings": [], "reasoning": "Gemini thought safe."}))
            return _MockHTTPResponse(_gemini_payload({"is_vulnerable": True, "findings": [f_idor], "reasoning": "Synthesis Judge confirmed IDOR."}))
        if "api.openai.com" in url:
            return _MockHTTPResponse(_groq_payload({"is_vulnerable": True, "findings": [f_idor], "reasoning": "OpenAI found IDOR."}))
        if "api.deepseek.com" in url:
            return _MockHTTPResponse(_groq_payload({"is_vulnerable": True, "findings": [f_idor], "reasoning": "DeepSeek found IDOR."}))
        return _MockHTTPResponse(_groq_payload({"is_vulnerable": False, "findings": [], "reasoning": "Groq thought safe."}))

    monkeypatch.setattr("httpx.post", fake_post)
    res = run_ai_review(target, [], Config(ai_enabled=True))
    assert res.status == "ok"
    assert res.consensus_status == "debate_resolved"
    assert len(res.findings) == 1
    assert "judge" in res.reasoning_trace
    assert "openai" in res.reasoning_trace
    assert "deepseek" in res.reasoning_trace


def test_markdown_and_sarif_export(tmp_path):
    from vibegate.ai import AIReviewResult
    from vibegate.engine import ScanReport, report_to_sarif
    from vibegate.ui import render_markdown_report

    f = Finding(
        "semgrep", "sql-fstring", "injection", "high", "high", "app.py", 12, 12,
        "SQL query built with an f-string", 'cur.execute(f"SELECT * FROM u WHERE id={uid}")',
        "User input interpolated into SQL.", "Use parameterized queries.",
    )
    report = ScanReport(
        target_root=str(tmp_path),
        scanned_version="working",
        files_scanned=["app.py"],
        partially_staged_files=[],
        findings=[f],
        scanner_results=[],
        ai_result=AIReviewResult("skipped", [], "test"),
        policy_blocked=True,
    )
    md = render_markdown_report(report)
    assert "# VibeGate Security Report" in md
    assert "SQL Injection (SQLi)" in md
    assert "Use parameterized queries." in md

    sarif = report_to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "sql-fstring"
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_web_audit_js_bundle_secret_and_grade(monkeypatch):
    import httpx
    from vibegate.web_audit import audit_domain, compute_web_grade

    class _FakeResp:
        def __init__(self, url, status_code=200, headers=None, text=""):
            self.url = url
            self.status_code = status_code
            self.headers = httpx.Headers(headers or [])
            self.text = text

    class _FakeClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get(self, url, **_kwargs):
            if url.endswith("/assets/app.js"):
                return _FakeResp(url, 200, text='const k = "' + "sk_live_" + '51AbCdEfGhIjKlMnOpQrStUv";')
            if url.endswith("/login"):
                return _FakeResp(url, 200, text='<form method="post" action="/auth"><input type="password"></form>')
            if url.endswith(("/.env", "/.git/HEAD", "/.DS_Store", "/phpinfo.php", "/openapi.json")):
                return _FakeResp(url, 404, text="Not Found")
            return _FakeResp(
                "https://shop.example.in/",
                200,
                headers=[
                    ("Strict-Transport-Security", "max-age=31536000"),
                    ("Content-Security-Policy", "default-src 'self'"),
                    ("X-Frame-Options", "DENY"),
                    ("X-Content-Type-Options", "nosniff"),
                    ("Referrer-Policy", "strict-origin-when-cross-origin"),
                    ("Permissions-Policy", "camera=()"),
                ],
                text='<script src="/assets/app.js"></script><a href="/login">Login</a>',
            )

    monkeypatch.setattr("vibegate.web_audit.httpx.Client", _FakeClient)
    report = audit_domain("https://shop.example.in", Config(fail_on="high"))
    rids = {f.rule_id for f in report.findings}
    assert "web.bundle.exposed-secret" in rids
    assert "web.body.form-no-csrf" in rids
    grade, score = compute_web_grade(report.findings)
    assert score < 80
    assert grade in ("C", "D", "F")


def test_web_audit_https_refused_falls_back_to_http_and_unreachable_is_not_a_plus(monkeypatch):
    import httpx
    from io import StringIO
    from rich.console import Console
    from vibegate.ui import render_summary
    from vibegate.web_audit import audit_domain

    class _FakeResp:
        def __init__(self, url, status_code=200, headers=None, text="<html><body>Hello</body></html>"):
            self.url = url
            self.status_code = status_code
            self.headers = httpx.Headers(headers or [])
            self.text = text

    class _FallbackClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get(self, url, **_kwargs):
            if url.startswith("https://"):
                raise httpx.ConnectError("Connection refused")
            if url.endswith(("/.env", "/.git/HEAD", "/.DS_Store", "/phpinfo.php", "/openapi.json")):
                return _FakeResp(url, 404, text="Not Found")
            return _FakeResp(url, 200, headers=[("Server", "Apache/2.4.7")])

    monkeypatch.setattr("vibegate.web_audit.httpx.Client", _FallbackClient)
    report = audit_domain("scanme.nmap.org", Config(fail_on="high", ai_enabled=False))
    rids = {f.rule_id for f in report.findings}
    assert "web.http.no-https" in rids
    assert "web.header.missing-csp" in rids
    assert report.policy_blocked is True

    class _DeadClient(_FallbackClient):
        def get(self, url, **_kwargs):
            raise httpx.ConnectError("Connection refused")

    monkeypatch.setattr("vibegate.web_audit.httpx.Client", _DeadClient)
    dead_report = audit_domain("dead.example.invalid", Config(fail_on="high", ai_enabled=False))
    buf = StringIO()
    render_summary(dead_report, Console(file=buf, width=120))
    out = buf.getvalue()
    assert "UNREACHABLE — AUDIT FAILED" in out
    assert "N/A (Site Unreachable)" in out
    assert "A+" not in out


def test_web_audit_ai_receives_multipage_snapshot_and_guideline(monkeypatch):
    import httpx
    from vibegate.web_audit import audit_domain

    for k in list(os.environ):
        if "API_KEY" in k or k.startswith("CUSTOM_AI_"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "gem-test-key")

    class _FakeResp:
        def __init__(self, url, status_code=200, headers=None, text=""):
            self.url = url
            self.status_code = status_code
            self.headers = httpx.Headers(headers or [])
            self.text = text

    class _FakeClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get(self, url, **_kwargs):
            if url.endswith("/login"):
                return _FakeResp(url, 200, text="<form method='post'><input type='password'></form>")
            if url.endswith(("/.env", "/.git/HEAD", "/.DS_Store", "/phpinfo.php", "/openapi.json")):
                return _FakeResp(url, 404, text="Not Found")
            return _FakeResp("https://app.example.com/", 200, text='<a href="/login">Sign in</a>')

    captured = []

    def fake_post(url, **kwargs):
        captured.append(json.dumps(kwargs.get("json", {})))
        return _MockHTTPResponse(_gemini_payload({"is_vulnerable": False, "findings": [], "reasoning": "Reviewed all pages."}))

    monkeypatch.setattr("vibegate.web_audit.httpx.Client", _FakeClient)
    monkeypatch.setattr("httpx.post", fake_post)
    report = audit_domain("https://app.example.com", Config(ai_enabled=True))
    assert report.ai_result.status == "ok"
    assert captured
    assert "HOSTED WEBSITE AUDIT GUIDELINE" in captured[0]
    assert "/login" in captured[0]


def test_several_keys_work_together_across_batches(tmp_path, monkeypatch):
    for k in list(os.environ):
        if "API_KEY" in k or k.startswith("CUSTOM_AI_"):
            monkeypatch.delenv(k, raising=False)

    for i in range(1, 5):
        monkeypatch.setenv(f"GROQ_API_KEY_{i}", f"groq-key-{i}")

    files = []
    for i in range(1, 5):
        name = f"route_{i}.py"
        (tmp_path / name).write_text(f"@app.route('/r{i}')\ndef f{i}():\n    return 'ok'\n")
        files.append(name)

    target = ScanTarget(root=str(tmp_path), files=files, version="working")
    used_keys: set[str] = set()

    def fake_post(url, **kwargs):
        auth = kwargs.get("headers", {}).get("Authorization", "")
        used_keys.add(auth.replace("Bearer ", ""))
        return _MockHTTPResponse(_groq_payload({"is_vulnerable": False, "findings": [], "reasoning": "All 5 tasks checked; safe."}))

    monkeypatch.setattr("httpx.post", fake_post)
    res = run_ai_review(target, [], Config(ai_enabled=True, ai_max_files=1))
    assert res.status == "ok"
    assert used_keys == {"groq-key-1", "groq-key-2", "groq-key-3", "groq-key-4"}
