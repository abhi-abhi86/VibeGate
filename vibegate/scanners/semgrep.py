"""Semgrep adapter: selected SAST rules shipped with VibeGate (run fully offline, metrics off)."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile

from vibegate.models import CONFIDENCES, Finding
from vibegate.scanners.base import Scanner, ScannerResult, ScanTarget

RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "semgrep.yml")
SEV_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _semgrep_env(tmp_dir: str) -> dict[str, str]:
    return {
        **os.environ,
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "SEMGREP_USER_LOG_FILE": os.path.join(tmp_dir, "semgrep.log"),
        "SEMGREP_SETTINGS_FILE": os.path.join(tmp_dir, "settings.yml"),
    }


class SemgrepScanner(Scanner):
    name = "semgrep"
    binary = "semgrep"
    install_hint = "Install: brew install semgrep"

    def __init__(self, configs: list[str] | None = None):
        self.configs = configs or [RULES_PATH]

    def version(self) -> str | None:
        with tempfile.TemporaryDirectory() as td:
            try:
                proc = subprocess.run(
                    [self.binary, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    env=_semgrep_env(td),
                )
            except (OSError, subprocess.TimeoutExpired):
                return None
            out = (proc.stdout or proc.stderr).strip().splitlines()
            return out[0].strip() if out else None

    def _run(self, target: ScanTarget, timeout: int) -> ScannerResult:
        if not target.files:
            return ScannerResult(self.name, "skipped", message="no files to scan")
        cmd = [self.binary, "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet", "--no-git-ignore"]
        for c in self.configs:
            cmd += ["--config", c]
        cmd += ["--", *target.files]
        with tempfile.TemporaryDirectory() as td:
            proc = subprocess.run(
                cmd, cwd=target.root, capture_output=True, text=True, timeout=timeout, env=_semgrep_env(td)
            )
        if proc.returncode not in (0, 1) or not proc.stdout.strip():
            return ScannerResult(self.name, "error", message=(proc.stderr or proc.stdout).strip()[-500:])
        data = json.loads(proc.stdout)
        errors = [e for e in data.get("errors", []) if e.get("level") == "error"]
        msg = f"{len(errors)} file(s) could not be parsed" if errors else ""
        return ScannerResult(self.name, "ok", findings=self.normalize(data, target), message=msg)

    def normalize(self, data: dict, target: ScanTarget) -> list[Finding]:
        findings = []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            rel = self.rel(r.get("path", ""), target)
            start = int(r.get("start", {}).get("line", 0))
            end = int(r.get("end", {}).get("line", start))
            rule = r.get("check_id", "semgrep")
            short_rule = rule.split(".")[-1]
            sev = meta.get("vibegate_severity") or SEV_MAP.get(extra.get("severity", ""), "medium")
            conf = str(meta.get("confidence", "medium")).lower()
            snippet = "\n".join(target.read(rel).splitlines()[start - 1 : min(end, start + 4)]).strip()
            findings.append(
                Finding(
                    source=self.name,
                    rule_id=short_rule,
                    category=meta.get("vibegate_category", "other"),
                    severity=sev,
                    confidence=conf if conf in CONFIDENCES else "medium",
                    file=rel,
                    start_line=start,
                    end_line=end,
                    title=meta.get("title") or short_rule.replace("-", " "),
                    evidence=snippet[:400],
                    explanation=extra.get("message", "").strip(),
                    remediation=meta.get("remediation", "Review the flagged code."),
                    extra={"cwe": meta.get("cwe"), "full_rule_id": rule},
                )
            )
        return findings

