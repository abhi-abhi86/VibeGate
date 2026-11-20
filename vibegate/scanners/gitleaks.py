"""Gitleaks adapter: likely hard-coded secrets. Raw secret values never leave this module."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile

from vibegate.models import Finding
from vibegate.scanners.base import Scanner, ScannerResult, ScanTarget

CRITICAL_HINTS = ("private-key", "aws", "gcp", "stripe", "github-pat", "slack", "openai", "anthropic")


def mask(secret: str) -> str:
    if not secret:
        return "****"
    keep = 4 if len(secret) > 12 else 2
    return secret[:keep] + "*" * min(len(secret) - keep, 16)


class GitleaksScanner(Scanner):
    name = "gitleaks"
    binary = "gitleaks"
    install_hint = "Install: brew install gitleaks"

    def _run(self, target: ScanTarget, timeout: int) -> ScannerResult:
        with tempfile.TemporaryDirectory() as td:
            report = os.path.join(td, "gitleaks.json")
            cmd = [
                self.binary, "dir", target.root,
                "--report-format", "json", "--report-path", report,
                "--no-banner", "--exit-code", "0", "--log-level", "error",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if proc.returncode != 0:
                return ScannerResult(self.name, "error", message=(proc.stderr or proc.stdout).strip()[:500])
            with open(report, encoding="utf-8") as fh:
                raw = fh.read().strip() or "[]"
        return ScannerResult(self.name, "ok", findings=self.normalize(json.loads(raw), target))

    def normalize(self, items: list[dict], target: ScanTarget) -> list[Finding]:
        findings = []
        allowed = set(target.files) if target.files else None
        for it in items or []:
            rel = self.rel(it.get("File", ""), target)
            if allowed is not None and rel not in allowed:
                continue
            rule = it.get("RuleID", "secret")
            secret = it.get("Secret", "") or ""
            start = int(it.get("StartLine") or 0)
            end = int(it.get("EndLine") or start)
            line_text = target.line(rel, start).strip()
            evidence = line_text.replace(secret, mask(secret)) if secret else line_text
            if secret and secret in evidence:  # paranoia: never surface the secret
                evidence = "[line contains secret; redacted]"
            sev = "critical" if any(h in rule.lower() for h in CRITICAL_HINTS) else "high"
            conf = "medium" if rule.startswith("generic") else "high"
            findings.append(
                Finding(
                    source=self.name,
                    rule_id=rule,
                    category="secret",
                    severity=sev,
                    confidence=conf,
                    file=rel,
                    start_line=start,
                    end_line=end,
                    title=it.get("Description") or "Possible hard-coded secret",
                    evidence=evidence[:300],
                    explanation=(
                        "Gitleaks matched a pattern that looks like a credential committed in source code. "
                        "Anyone with read access to the repository (or its history) could use it."
                    ),
                    remediation=(
                        "Remove the value from source, load it from an environment variable or secret manager, "
                        "and rotate the credential if it was ever real or shared. Committing it even once "
                        "leaves it in Git history."
                    ),
                    extra={
                        "fingerprint": hashlib.sha256(secret.encode()).hexdigest()[:12],
                        "entropy": it.get("Entropy"),
                    },
                )
            )
        return findings

