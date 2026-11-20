"""Auditable repository-level suppressions (.vibegate-ignore.json)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from vibegate.models import Finding

SUPPRESS_FILE = ".vibegate-ignore.json"


@dataclass
class Suppression:
    rule_id: str
    file: str
    line: int | None = None
    reason: str = ""
    added_by: str = ""
    added_at: str = ""

    def matches(self, finding: Finding) -> bool:
        if self.rule_id != finding.rule_id or self.file != finding.file:
            return False
        if self.line is not None and self.line != finding.start_line:
            return False
        return True


def load_suppressions(root: str | None) -> list[Suppression]:
    if not root:
        return []
    path = os.path.join(root, SUPPRESS_FILE)
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    items = data.get("suppressions", []) if isinstance(data, dict) else []
    return [Suppression(**it) for it in items if isinstance(it, dict) and it.get("rule_id") and it.get("file")]


def save_suppression(root: str, finding: Finding, reason: str, added_by: str) -> Suppression:
    existing = load_suppressions(root)
    sup = Suppression(
        rule_id=finding.rule_id,
        file=finding.file,
        line=finding.start_line or None,
        reason=reason.strip() or "Reviewed and suppressed by developer",
        added_by=added_by,
        added_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    # Replace duplicate narrow rule if one already exists
    filtered = [s for s in existing if not (s.rule_id == sup.rule_id and s.file == sup.file and s.line == sup.line)]
    filtered.append(sup)
    path = os.path.join(root, SUPPRESS_FILE)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "suppressions": [asdict(s) for s in filtered]}, fh, indent=2)
        fh.write("\n")
    return sup


def apply_suppressions(findings: list[Finding], suppressions: list[Suppression]) -> None:
    for f in findings:
        for s in suppressions:
            if s.matches(f):
                f.suppressed = True
                f.suppression_reason = s.reason or "suppressed in .vibegate-ignore.json"
                break

