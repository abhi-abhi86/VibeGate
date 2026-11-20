"""OSV-Scanner adapter: dependency manifests / lockfiles checked against known vulnerability data."""

from __future__ import annotations

import json
import os
import re
import subprocess

from vibegate.models import Finding
from vibegate.scanners.base import Scanner, ScannerResult, ScanTarget

MANIFESTS = {
    "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "go.mod", "Cargo.lock", "Gemfile.lock", "composer.lock", "pom.xml",
    "gradle.lockfile", "mix.lock", "pubspec.lock", "packages.lock.json",
}


def is_manifest(path: str) -> bool:
    base = os.path.basename(path)
    return base in MANIFESTS or (base.startswith("requirements") and base.endswith(".txt"))


def cvss_to_severity(score: str | None) -> str:
    try:
        s = float(score)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "medium"  # unknown severity: do not silently downgrade
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    return "low" if s > 0 else "info"


class OSVScanner(Scanner):
    name = "osv-scanner"
    binary = "osv-scanner"
    install_hint = "Install: brew install osv-scanner"

    def _run(self, target: ScanTarget, timeout: int) -> ScannerResult:
        manifests = [f for f in target.files if is_manifest(f)]
        if not manifests:
            return ScannerResult(self.name, "skipped", message="no dependency manifests or lockfiles in the scan set")
        cmd = [self.binary, "scan", "source", "--format", "json"]
        for m in manifests:
            cmd += ["--lockfile", m]
        proc = subprocess.run(cmd, cwd=target.root, capture_output=True, text=True, timeout=timeout)
        # 0 = no vulns, 1 = vulns found, 128 = no packages found
        if proc.returncode == 128:
            return ScannerResult(self.name, "ok", message="no packages found in manifests")
        if proc.returncode not in (0, 1) or not proc.stdout.strip().startswith("{"):
            err = (proc.stderr or proc.stdout).strip()
            hint = " (OSV-Scanner needs network access to query osv.dev)" if "dial" in err or "network" in err.lower() else ""
            return ScannerResult(self.name, "error", message=err[-400:] + hint)
        return ScannerResult(self.name, "ok", findings=self.normalize(json.loads(proc.stdout), target),
                             message=f"checked {len(manifests)} manifest(s)")

    def normalize(self, data: dict, target: ScanTarget) -> list[Finding]:
        findings = []
        for res in data.get("results") or []:
            rel = self.rel(res.get("source", {}).get("path", ""), target)
            text_lines = target.read(rel).splitlines()
            for pkg in res.get("packages") or []:
                info = pkg.get("package", {})
                name, version, eco = info.get("name", "?"), info.get("version", "?"), info.get("ecosystem", "")
                vulns = {v.get("id"): v for v in pkg.get("vulnerabilities") or []}
                groups = pkg.get("groups") or [{"ids": [vid]} for vid in vulns]
                line = self._find_line(text_lines, name)
                for g in groups:
                    ids = g.get("ids") or []
                    if not ids:
                        continue
                    primary = next((i for i in ids if i.startswith("GHSA")), ids[0])
                    v = vulns.get(primary) or vulns.get(ids[0]) or {}
                    aliases = sorted(set(ids) | set(g.get("aliases") or []) - {primary})
                    fixed = self._fixed_versions(v, name)
                    summary = v.get("summary") or (v.get("details") or "Known vulnerability")[:160]
                    remediation = (
                        f"Upgrade {name} to {fixed[-1]} or later (first fixed version listed by OSV), then rerun the scan."
                        if fixed else f"No fixed version is listed for {name}; consider replacing it or assessing exposure."
                    )
                    findings.append(
                        Finding(
                            source=self.name,
                            rule_id=primary,
                            category="dependency",
                            severity=cvss_to_severity(g.get("max_severity")),
                            confidence="high",
                            file=rel,
                            start_line=line,
                            end_line=line,
                            title=f"{name} {version}: {summary}",
                            evidence=f"{name}=={version} ({eco}) matches {primary}"
                            + (f" (aliases: {', '.join(aliases[:4])})" if aliases else ""),
                            explanation=(
                                f"OSV-Scanner reports that {name} {version} is affected by {primary}. "
                                "Whether it is exploitable depends on how your code uses the package."
                            ),
                            remediation=remediation,
                            extra={"package": name, "version": version, "ecosystem": eco, "vuln_id": primary,
                                   "aliases": aliases, "fixed_versions": fixed, "fingerprint": f"{name}@{version}"},
                        )
                    )
        return findings

    @staticmethod
    def _find_line(lines: list[str], name: str) -> int:
        pat = re.compile(rf"(^|[\s\"'/]){re.escape(name)}([\s\"'=<>~!\[@:]|$)", re.I)
        for i, ln in enumerate(lines, 1):
            if pat.search(ln):
                return i
        return 0

    @staticmethod
    def _fixed_versions(v: dict, name: str) -> list[str]:
        fixed = []
        for aff in v.get("affected") or []:
            if aff.get("package", {}).get("name", "").lower() != name.lower():
                continue
            for rng in aff.get("ranges") or []:
                for ev in rng.get("events") or []:
                    if "fixed" in ev and ev["fixed"] not in fixed:
                        fixed.append(ev["fixed"])
        return fixed

