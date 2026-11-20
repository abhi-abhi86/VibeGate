"""Scanner adapter interface."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field

from vibegate.models import Finding


@dataclass
class ScanTarget:
    """A directory holding the exact content to scan, plus the repo-relative files in it."""

    root: str
    files: list[str]
    version: str  # "staged" | "working tree" | "directory"

    def read(self, rel: str) -> str:
        try:
            with open(os.path.join(self.root, rel), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return ""

    def line(self, rel: str, lineno: int) -> str:
        lines = self.read(rel).splitlines()
        return lines[lineno - 1] if 0 < lineno <= len(lines) else ""


@dataclass
class ScannerResult:
    name: str
    status: str  # ok | skipped | not_installed | error | timeout
    findings: list[Finding] = field(default_factory=list)
    message: str = ""
    duration_ms: int = 0
    version: str | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "duration_ms": self.duration_ms,
            "version": self.version,
            "finding_count": len(self.findings),
        }


class Scanner:
    name = ""
    binary = ""
    install_hint = ""

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def version(self) -> str | None:
        try:
            proc = subprocess.run([self.binary, "--version"], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            return None
        out = (proc.stdout or proc.stderr).strip().splitlines()
        return out[0].strip() if out else None

    def run(self, target: ScanTarget, timeout: int) -> ScannerResult:
        start = time.monotonic()
        if not self.available():
            return ScannerResult(self.name, "not_installed", message=f"{self.binary} not found on PATH. {self.install_hint}")
        try:
            result = self._run(target, timeout)
        except subprocess.TimeoutExpired:
            result = ScannerResult(self.name, "timeout", message=f"{self.name} exceeded {timeout}s")
        except Exception as exc:  # adapters must never crash the gate
            result = ScannerResult(self.name, "error", message=f"{type(exc).__name__}: {exc}")
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    def _run(self, target: ScanTarget, timeout: int) -> ScannerResult:  # pragma: no cover - abstract
        raise NotImplementedError

    @staticmethod
    def rel(path: str, target: ScanTarget) -> str:
        p = path
        root = os.path.realpath(target.root)
        if os.path.isabs(p):
            p = os.path.relpath(os.path.realpath(p), root)
        if p.startswith("./"):
            p = p[2:]
        return p

