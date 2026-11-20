from vibegate.scanners.base import Scanner, ScannerResult, ScanTarget
from vibegate.scanners.gitleaks import GitleaksScanner
from vibegate.scanners.osv import OSVScanner
from vibegate.scanners.semgrep import SemgrepScanner

ALL_SCANNERS = {s.name: s for s in (GitleaksScanner, SemgrepScanner, OSVScanner)}


def build_scanners(names: list[str]) -> dict[str, Scanner]:
    unknown = [n for n in names if n not in ALL_SCANNERS]
    if unknown:
        raise ValueError(f"unknown scanner(s): {unknown}; choose from {list(ALL_SCANNERS)}")
    return {n: ALL_SCANNERS[n]() for n in names}


__all__ = ["Scanner", "ScannerResult", "ScanTarget", "build_scanners", "ALL_SCANNERS"]

