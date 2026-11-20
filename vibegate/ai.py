"""Optional AI-assisted authorization / access-control review using Gemini API."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from vibegate.config import Config
from vibegate.models import AI_CANDIDATE, CONFIDENCES, SEVERITIES, Finding
from vibegate.scanners.base import ScanTarget

ROUTE_HINTS = re.compile(
    r"(@app\.route|@router\.|@bp\.route|app\.(get|post|put|patch|delete)\(|"
    r"router\.(get|post|put|patch|delete)\(|def\s+(get|post|put|delete|update|remove)_|"
    r"login_required|current_user|session\[|Authorization|Bearer|SELECT\s+.+\s+FROM|"
    r"WHERE\s+id\s*=|order_id|user_id|account_id)",
    re.IGNORECASE,
)

CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java", ".php", ".cs"}


@dataclass
class AIReviewResult:
    status: str  # ok | skipped | unavailable | timeout | error
    findings: list[Finding]
    message: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "message": self.message,
            "duration_ms": self.duration_ms,
            "finding_count": len(self.findings),
        }


def _is_candidate_file(rel: str, content: str) -> bool:
    _, ext = os.path.splitext(rel.lower())
    if ext not in CODE_EXTENSIONS:
        return False
    if rel.startswith("tests/") or "/tests/" in rel or rel.endswith("_test.py") or ".test." in rel:
        return False
    return bool(ROUTE_HINTS.search(content))


def _redact_secret_lines(content: str, secret_lines: set[int]) -> str:
    if not secret_lines:
        return content
    out = []
    for idx, line in enumerate(content.splitlines(), 1):
        if idx in secret_lines:
            out.append("[REDACTED: line flagged by secret scanner]")
        else:
            out.append(line)
    return "\n".join(out)


def _select_context(target: ScanTarget, secret_findings: list[Finding], cfg: Config) -> list[tuple[str, str]]:
    secrets_by_file: dict[str, set[int]] = {}
    for f in secret_findings:
        if f.category == "secret" and f.start_line:
            secrets_by_file.setdefault(f.file, set()).update(range(f.start_line, max(f.start_line, f.end_line) + 1))

    selected: list[tuple[str, str]] = []
    total_chars = 0
    for rel in target.files:
        if len(selected) >= cfg.ai_max_files:
            break
        raw = target.read(rel)
        if not raw.strip() or not _is_candidate_file(rel, raw):
            continue
        redacted = _redact_secret_lines(raw, secrets_by_file.get(rel, set()))
        numbered = "\n".join(f"{i}: {ln}" for i, ln in enumerate(redacted.splitlines(), 1))
        if total_chars + len(numbered) > cfg.ai_max_chars:
            remaining = cfg.ai_max_chars - total_chars
            if remaining < 400:
                break
            numbered = numbered[:remaining] + "\n... [truncated]"
        selected.append((rel, numbered))
        total_chars += len(numbered)
    return selected


def _build_prompt(snippets: list[tuple[str, str]]) -> str:
    files_block = "\n\n".join(f"=== FILE: {rel} ===\n{body}" for rel, body in snippets)
    return (
        "You are reviewing staged code changes for LIKELY missing authentication, "
        "object-level authorization (IDOR), or permission checks.\n"
        "Rules:\n"
        "- Only report concrete, high-signal access-control concerns visible in the provided code.\n"
        "- Do NOT report SQL injection, secrets, or dependency issues (other tools handle those).\n"
        "- Remember your output is a candidate finding for human review, not a confirmed vulnerability.\n"
        "- Return ONLY a JSON object with a single key \"findings\", which is a list of objects with keys:\n"
        "  file (string), start_line (int), end_line (int), severity (one of: high, medium, low, info),\n"
        "  confidence (one of: high, medium, low), title (string), evidence (short quote/detail),\n"
        "  explanation (plain English, 1-2 sentences), remediation (plain English, 1-2 sentences).\n"
        "- If there are no likely access-control issues, return {\"findings\": []}.\n\n"
        f"{files_block}"
    )


def _parse_findings(raw_text: str, valid_files: set[str], scanned_version: str) -> list[Finding]:
    text = raw_text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.DOTALL).strip()
    data = json.loads(text)
    items = data.get("findings", []) if isinstance(data, dict) else []
    findings: list[Finding] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        rel = str(it.get("file", "")).strip()
        if rel not in valid_files:
            continue
        sev = str(it.get("severity", "medium")).lower()
        if sev not in SEVERITIES:
            sev = "medium"
        conf = str(it.get("confidence", "medium")).lower()
        if conf not in CONFIDENCES:
            conf = "medium"
        start = max(1, int(it.get("start_line") or 1))
        end = max(start, int(it.get("end_line") or start))
        findings.append(
            Finding(
                source="ai-review",
                rule_id="ai-access-control",
                category="access_control",
                severity=sev,
                confidence=conf,
                file=rel,
                start_line=start,
                end_line=end,
                title=str(it.get("title") or "Possible missing authorization check")[:120],
                evidence=str(it.get("evidence") or "")[:300],
                explanation=str(it.get("explanation") or "AI review flagged a potential access-control gap."),
                remediation=str(it.get("remediation") or "Verify authentication and object ownership before acting on the resource."),
                ai_generated=True,
                verification_status=AI_CANDIDATE,
                verification_note="AI candidate finding; verify against your application's auth middleware and tests.",
                scanned_version=scanned_version,
            )
        )
    return findings


def run_ai_review(target: ScanTarget, secret_findings: list[Finding], cfg: Config) -> AIReviewResult:
    start = time.monotonic()
    if not cfg.ai_enabled:
        return AIReviewResult("skipped", [], "AI review disabled (--no-ai or config)")

    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        return AIReviewResult("unavailable", [], "GEMINI_API_KEY not set; AI authorization review skipped")

    snippets = _select_context(target, secret_findings, cfg)
    if not snippets:
        return AIReviewResult("skipped", [], "no route/controller/auth-relevant code in staged changes")

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{cfg.ai_model}:generateContent"
    payload = {
        "contents": [{"parts": [{"text": _build_prompt(snippets)}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=cfg.ai_timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        text = body["candidates"][0]["content"]["parts"][0]["text"]
        findings = _parse_findings(text, {rel for rel, _ in snippets}, target.version)
        ms = int((time.monotonic() - start) * 1000)
        return AIReviewResult("ok", findings, f"reviewed {len(snippets)} file(s) with {cfg.ai_model}", ms)
    except TimeoutError:
        return AIReviewResult("timeout", [], f"AI review timed out after {cfg.ai_timeout}s", int((time.monotonic() - start) * 1000))
    except urllib.error.URLError as exc:
        return AIReviewResult("unavailable", [], f"AI review unavailable ({exc.reason}); deterministic results shown", int((time.monotonic() - start) * 1000))
    except Exception as exc:
        return AIReviewResult("error", [], f"AI review failed ({type(exc).__name__}: {exc}); deterministic results shown", int((time.monotonic() - start) * 1000))

