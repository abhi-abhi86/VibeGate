"""The unified finding format shared by every scanner adapter, the TUI and CI output."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field

SEVERITIES = ["info", "low", "medium", "high", "critical"]
CATEGORIES = ["secret", "injection", "access_control", "dependency", "other"]
CONFIDENCES = ["low", "medium", "high"]

# verification_status values
DETECTED = "detected"
NOT_RECHECKED = DETECTED  # backwards-compatible alias
NO_LONGER_REPRODUCES = "no_longer_reproduces"
STILL_REPRODUCES = "still_reproduces"
AI_CANDIDATE = "ai_candidate"
AI_PATCH_APPLIED = "ai_patch_applied_unverified"
TESTS_PASSED = "patched_tests_passed"
TESTS_FAILED = "patched_tests_failed"


def sev_rank(severity: str) -> int:
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return 0


@dataclass
class Finding:
    source: str  # gitleaks | semgrep | osv-scanner | ai-review
    rule_id: str
    category: str  # secret | injection | access_control | dependency | other
    severity: str  # critical | high | medium | low | info
    confidence: str  # high | medium | low
    file: str  # repo-relative path
    start_line: int
    end_line: int
    title: str
    evidence: str  # concise supporting detail; secrets are always masked
    explanation: str
    remediation: str
    ai_generated: bool = False
    verification_status: str = NOT_RECHECKED
    verification_note: str | None = None
    suppressed: bool = False
    suppression_reason: str | None = None
    dismissed: bool = False
    dismiss_note: str | None = None
    suggested_patch: str | None = None
    patch_source: str | None = None  # deterministic | ai
    scanned_version: str = "staged"
    extra: dict = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raw = "|".join(
                [self.source, self.rule_id, self.file, str(self.start_line), str(self.extra.get("fingerprint", ""))]
            )
            self.id = "VG-" + hashlib.sha1(raw.encode()).hexdigest()[:8]

    @property
    def location(self) -> str:
        if self.start_line and self.end_line and self.end_line != self.start_line:
            return f"{self.file}:{self.start_line}-{self.end_line}"
        if self.start_line:
            return f"{self.file}:{self.start_line}"
        return self.file

    @property
    def source_label(self) -> str:
        return "AI review (candidate)" if self.ai_generated else self.source

    def to_dict(self) -> dict:
        return asdict(self)

