"""Optional AI-assisted authorization review with 2-layer Multi-LLM Consensus (Gemini + Groq)."""

from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import httpx

from vibegate.config import Config
from vibegate.models import AI_CANDIDATE, CATEGORIES, CONFIDENCES, SEVERITIES, Finding
from vibegate.scanners.base import ScanTarget

ROUTE_HINTS = re.compile(
    r"(@app\.route|@router\.|@bp\.route|app\.(get|post|put|patch|delete)\(|"
    r"router\.(get|post|put|patch|delete)\(|def\s+(get|post|put|delete|update|remove)_|"
    r"login_required|current_user|session\[|Authorization|Bearer|SELECT\s+.+\s+FROM|"
    r"WHERE\s+id\s*=|order_id|user_id|account_id|/api/)",
    re.IGNORECASE,
)

# Pre-redaction patterns so secrets are stripped even when AI runs concurrently with Gitleaks
SECRET_LINE_HINTS = re.compile(
    r"(ghp_[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{20,}|"
    r"(?:API_KEY|SECRET_KEY|TOKEN|PASSWORD|PRIVATE_KEY)\s*=\s*['\"][^'\"]{10,}['\"])"
)

CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java", ".php", ".cs", ".sql", ".sh", ".yml", ".yaml"}
LLM_CALL_TIMEOUT = 15.0


@dataclass
class AIReviewResult:
    status: str  # ok | skipped | unavailable | timeout | error
    findings: list[Finding]
    message: str = ""
    duration_ms: int = 0
    consensus_status: str = "single"  # 2/2_safe | 2/2_vulnerable | debate_resolved | single_fallback | single
    reasoning_trace: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "message": self.message,
            "duration_ms": self.duration_ms,
            "finding_count": len(self.findings),
            "consensus_status": self.consensus_status,
            "reasoning_trace": self.reasoning_trace,
        }


def _is_candidate_file(rel: str, content: str) -> bool:
    _, ext = os.path.splitext(rel.lower())
    if ext not in CODE_EXTENSIONS:
        return False
    if rel.startswith("tests/") or "/tests/" in rel or rel.endswith("_test.py") or ".test." in rel:
        return False
    return bool(content.strip())


def _redact_secret_lines(content: str, secret_lines: set[int]) -> str:
    out = []
    for idx, line in enumerate(content.splitlines(), 1):
        if idx in secret_lines or SECRET_LINE_HINTS.search(line):
            out.append("[REDACTED: potential secret]")
        else:
            out.append(line)
    return "\n".join(out)


def _select_context(target: ScanTarget, secret_findings: list[Finding], cfg: Config) -> list[tuple[str, str]]:
    secrets_by_file: dict[str, set[int]] = {}
    for f in secret_findings:
        if f.category == "secret" and f.start_line:
            secrets_by_file.setdefault(f.file, set()).update(range(f.start_line, max(f.start_line, f.end_line) + 1))

    # Prioritize route/auth/DB-relevant files first, then include other code files
    ordered = sorted(
        target.files,
        key=lambda r: (0 if ROUTE_HINTS.search(target.read(r)) else 1, r),
    )
    selected: list[tuple[str, str]] = []
    total_chars = 0
    for rel in ordered:
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
        "You are an expert application security reviewer. Inspect the provided code for ALL types of "
        "security vulnerabilities and serious code bugs, including:\n"
        "- Broken Access Control / IDOR / missing authentication or ownership checks\n"
        "- Injection flaws (SQL injection, OS command injection, SSTI, XSS, NoSQL injection)\n"
        "- SSRF (Server-Side Request Forgery) & Path Traversal\n"
        "- Unsafe deserialization (pickle, yaml.load), weak cryptography, disabled TLS verification, hardcoded credentials\n"
        "- Critical logic bugs, race conditions, or swallowed exceptions\n"
        "Rules:\n"
        "- Only report genuine, concrete vulnerabilities or bugs actually present in the provided lines; never guess or invent issues.\n"
        "- In `reasoning`, cite the specific files, functions/routes, and checks you observed.\n"
        "- Return ONLY a strict JSON object with keys:\n"
        '  {"is_vulnerable": bool, "findings": [...], "reasoning": "2-3 sentence grounded explanation"}\n'
        "- Each finding object in findings must have:\n"
        "  file (string), start_line (int), end_line (int),\n"
        "  category (one of: access_control, injection, secret, bug, other),\n"
        "  severity (critical|high|medium|low|info), confidence (high|medium|low),\n"
        "  title (string), evidence (exact code quote from the file), explanation (1-2 sentences),\n"
        "  impact (1 sentence on the real-world threat in this code), remediation (1-2 sentences),\n"
        "  patch_old (optional exact existing line(s) to replace), patch_new (optional replacement line(s)).\n"
        "- If the code has no security vulnerabilities or serious bugs, set is_vulnerable=false and findings=[].\n\n"
        f"{files_block}"
    )


def _build_judge_prompt(
    snippets: list[tuple[str, str]],
    gemini_verdict: tuple[bool, list[Finding], str],
    groq_verdict: tuple[bool, list[Finding], str],
) -> str:
    files_block = "\n\n".join(f"=== FILE: {rel} ===\n{body}" for rel, body in snippets)
    g_vuln, g_findings, g_reason = gemini_verdict
    q_vuln, q_findings, q_reason = groq_verdict
    return (
        "You are the final Security Judge resolving a disagreement between two AI security reviewers.\n"
        f"Layer 1 (Gemini) verdict: is_vulnerable={g_vuln}, findings={len(g_findings)}\n"
        f"Layer 1 reasoning: {g_reason}\n\n"
        f"Layer 2 (Groq) verdict: is_vulnerable={q_vuln}, findings={len(q_findings)}\n"
        f"Layer 2 reasoning: {q_reason}\n\n"
        "Review the code carefully and issue the authoritative tie-breaker verdict.\n"
        "Return ONLY a strict JSON object:\n"
        '{"is_vulnerable": bool, "findings": [...], "reasoning": "2-3 sentence tie-breaker explanation"}\n\n'
        f"{files_block}"
    )


def _parse_verdict(raw_text: str, valid_files: set[str], scanned_version: str) -> tuple[bool, list[Finding], str]:
    text = raw_text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.DOTALL).strip()
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("AI response is not a JSON object")

    items = data.get("findings", [])
    if not isinstance(items, list):
        items = []
    reasoning = str(data.get("reasoning") or "").strip()

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
        cat = str(it.get("category", "other")).lower()
        if cat not in CATEGORIES or cat == "dependency":
            cat = "access_control" if any(k in str(it.get("title", "")).lower() for k in ("auth", "idor", "access")) else "other"
        raw_title = str(it.get("title") or "Potential security vulnerability")[:120]
        extra = {}
        if it.get("impact"):
            extra["impact"] = str(it["impact"])[:300]
        if it.get("patch_old") and it.get("patch_new"):
            extra["patch_old"] = str(it["patch_old"])
            extra["patch_new"] = str(it["patch_new"])
        findings.append(
            Finding(
                source="ai-review",
                rule_id=f"ai-{cat}",
                category=cat,
                severity=sev,
                confidence=conf,
                file=rel,
                start_line=start,
                end_line=end,
                title=raw_title,
                evidence=str(it.get("evidence") or "")[:300],
                explanation=str(it.get("explanation") or "AI review flagged a potential security or bug issue."),
                remediation=str(it.get("remediation") or "Review and remediate the flagged code."),
                ai_generated=True,
                verification_status=AI_CANDIDATE,
                verification_note="AI candidate finding; verify against your application logic and tests.",
                scanned_version=scanned_version,
                extra=extra,
            )
        )
    is_vuln = bool(data.get("is_vulnerable", bool(findings)))
    if not is_vuln:
        findings = []
    return is_vuln, findings, reasoning


def _call_gemini(prompt: str, api_key: str, model: str, valid_files: set[str], scanned_version: str, timeout: float) -> tuple[bool, list[Finding], str]:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
    }
    resp = httpx.post(
        url,
        json=payload,
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
        timeout=timeout,
    )
    resp.raise_for_status()
    body = resp.json()
    text = body["candidates"][0]["content"]["parts"][0]["text"]
    return _parse_verdict(text, valid_files, scanned_version)


def _call_groq(prompt: str, api_key: str, model: str, valid_files: set[str], scanned_version: str, timeout: float) -> tuple[bool, list[Finding], str]:
    url = "https://api.groq.com/openai/v1/chat/completions"
    payload = {
        "model": model,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": "You are an application security reviewer. Output strict JSON only."},
            {"role": "user", "content": prompt},
        ],
    }
    resp = httpx.post(
        url,
        json=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        timeout=timeout,
    )
    resp.raise_for_status()
    body = resp.json()
    text = body["choices"][0]["message"]["content"]
    return _parse_verdict(text, valid_files, scanned_version)


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int]] = set()
    merged: list[Finding] = []
    for f in findings:
        key = (f.file, f.start_line)
        if key not in seen:
            seen.add(key)
            merged.append(f)
    return merged


def _attach_consensus(findings: list[Finding], status: str, trace: dict[str, str]) -> list[Finding]:
    for f in findings:
        f.consensus_status = status
        f.reasoning_trace = dict(trace)
    return findings


def run_ai_review(
    target: ScanTarget,
    secret_findings: list[Finding],
    cfg: Config,
    progress_cb=None,
) -> AIReviewResult:
    def emit(event: str, msg: str) -> None:
        if progress_cb:
            progress_cb(event, msg)

    start = time.monotonic()
    if not cfg.ai_enabled:
        return AIReviewResult("skipped", [], "AI review disabled (--no-ai or config)")

    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    groq_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not gemini_key:
        return AIReviewResult("unavailable", [], "GEMINI_API_KEY not set; AI authorization review skipped")

    snippets = _select_context(target, secret_findings, cfg)
    if not snippets:
        return AIReviewResult("skipped", [], "no route/controller/auth-relevant code in staged changes")

    valid_files = {rel for rel, _ in snippets}
    files_list = ", ".join(sorted(valid_files))
    prompt = _build_prompt(snippets)
    per_call_timeout = min(float(cfg.ai_timeout), LLM_CALL_TIMEOUT)
    use_consensus = cfg.consensus_enabled or bool(gemini_key and groq_key)

    gemini_q = f"Are there any security vulnerabilities (auth/IDOR, injection, XSS, SSRF, crypto, secrets) or code bugs in {files_list}?"
    groq_q = f"Gemini reported Safe — double-check {files_list} for any hidden vulnerabilities or code bugs?"

    if not use_consensus:
        emit("ai_start", f"Layer 1 (Gemini) Q: {gemini_q}")
        try:
            _is_vuln, findings, reasoning = _call_gemini(prompt, gemini_key, cfg.ai_model, valid_files, target.version, per_call_timeout)
            trace = {"gemini_q": gemini_q, "gemini": reasoning} if reasoning else {"gemini_q": gemini_q}
            _attach_consensus(findings, "single", trace)
            ms = int((time.monotonic() - start) * 1000)
            return AIReviewResult("ok", findings, f"reviewed {len(snippets)} file(s) with {cfg.ai_model}", ms, "single", trace)
        except httpx.TimeoutException:
            return AIReviewResult("timeout", [], f"AI review timed out after {per_call_timeout}s", int((time.monotonic() - start) * 1000))
        except httpx.HTTPStatusError as exc:
            return AIReviewResult("unavailable", [], f"AI review HTTP {exc.response.status_code}; deterministic results shown", int((time.monotonic() - start) * 1000))
        except httpx.HTTPError as exc:
            return AIReviewResult("unavailable", [], f"AI review unavailable ({exc}); deterministic results shown", int((time.monotonic() - start) * 1000))
        except Exception as exc:
            return AIReviewResult("error", [], f"AI review failed ({type(exc).__name__}: {exc}); deterministic results shown", int((time.monotonic() - start) * 1000))

    # 2-Layer Gated Consensus:
    # 1) Run Layer 1 (Gemini). If Gemini finds vulnerabilities, return immediately without calling Groq.
    # 2) Only if Gemini says Safe (no vulnerabilities) OR Gemini errors/times out, run Layer 2 (Groq).
    emit("ai_start", f"Layer 1 (Gemini) Q: {gemini_q}")
    g_verdict = None
    g_err = None
    try:
        g_verdict = _call_gemini(prompt, gemini_key, cfg.ai_model, valid_files, target.version, per_call_timeout)
    except httpx.TimeoutException:
        g_err = f"timed out after {per_call_timeout}s"
    except httpx.HTTPStatusError as exc:
        g_err = f"HTTP {exc.response.status_code}"
    except httpx.HTTPError as exc:
        g_err = f"unavailable ({exc})"
    except Exception as exc:
        g_err = f"{type(exc).__name__}: {exc}"

    if g_verdict is None:
        # Layer 1 (Gemini) failed -> fall back to Layer 2 (Groq) instead of skipping AI reasoning
        fallback_q = f"Gemini failed ({g_err}) — review {files_list} for missing auth or IDOR risks?"
        emit("ai_start", f"Layer 2 (Groq) Q: {fallback_q}")
        try:
            q_vuln, q_findings, q_reason = _call_groq(prompt, groq_key, cfg.groq_model, valid_files, target.version, per_call_timeout)
            trace = {"gemini_q": gemini_q, "gemini": f"fallback ({g_err})", "groq_q": fallback_q, "groq": q_reason}
            final_findings = q_findings if q_vuln else []
            _attach_consensus(final_findings, "single_fallback", trace)
            ms = int((time.monotonic() - start) * 1000)
            return AIReviewResult("ok", final_findings, f"Gemini unavailable ({g_err}); used Groq ({cfg.groq_model})", ms, "single_fallback", trace)
        except Exception as q_exc:
            ms = int((time.monotonic() - start) * 1000)
            q_err = f"HTTP {q_exc.response.status_code}" if isinstance(q_exc, httpx.HTTPStatusError) else f"{type(q_exc).__name__}: {q_exc}"
            return AIReviewResult("unavailable", [], f"Gemini ({g_err}) and Groq ({q_err}) unavailable; deterministic results shown", ms)

    g_vuln, g_findings, g_reason = g_verdict
    if g_vuln:
        trace = {"gemini_q": gemini_q, "gemini": g_reason} if g_reason else {"gemini_q": gemini_q}
        _attach_consensus(g_findings, "single", trace)
        ms = int((time.monotonic() - start) * 1000)
        return AIReviewResult("ok", g_findings, f"Layer 1 (Gemini) found {len(g_findings)} issue(s)", ms, "single", trace)

    # Layer 1 (Gemini) reported no vulnerabilities -> run Layer 2 (Groq)
    emit("ai_done", f"Layer 1 (Gemini) answered: No vulnerabilities — escalating to Layer 2 (Groq)")
    emit("ai_start", f"Layer 2 (Groq) Q: {groq_q}")
    try:
        q_vuln, q_findings, q_reason = _call_groq(prompt, groq_key, cfg.groq_model, valid_files, target.version, per_call_timeout)
    except Exception as exc:
        # Hard fallback: Groq timeout / 429 / JSON failure never crashes the gate
        trace = {"gemini_q": gemini_q, "gemini": g_reason, "groq_q": groq_q, "groq": f"fallback ({type(exc).__name__}: {exc})"}
        ms = int((time.monotonic() - start) * 1000)
        return AIReviewResult(
            "ok",
            [],
            f"Groq fallback triggered; using Gemini verdict ({cfg.ai_model})",
            ms,
            "single_fallback",
            trace,
        )

    trace = {"gemini_q": gemini_q, "gemini": g_reason, "groq_q": groq_q, "groq": q_reason}
    if not q_vuln:
        ms = int((time.monotonic() - start) * 1000)
        return AIReviewResult("ok", [], "2/2 consensus: Safe (both models verified)", ms, "2/2_safe", trace)

    # Disagreement (Gemini: Safe, Groq: Vulnerable) -> trigger Judge call via Gemini
    judge_q = f"Gemini said Safe while Groq flagged {len(q_findings)} issue(s) — which verdict is correct for {files_list}?"
    emit("ai_start", f"Judge (Gemini) Q: {judge_q}")
    judge_prompt = _build_judge_prompt(snippets, g_verdict, (q_vuln, q_findings, q_reason))
    try:
        j_vuln, j_findings, j_reason = _call_gemini(judge_prompt, gemini_key, cfg.ai_model, valid_files, target.version, per_call_timeout)
        trace["judge_q"] = judge_q
        trace["judge"] = j_reason
        final_findings = j_findings if j_vuln else []
        _attach_consensus(final_findings, "debate_resolved", trace)
        ms = int((time.monotonic() - start) * 1000)
        return AIReviewResult("ok", final_findings, "consensus debate resolved by Judge", ms, "debate_resolved", trace)
    except Exception as exc:
        trace["judge_q"] = judge_q
        trace["judge"] = f"judge fallback ({type(exc).__name__}: {exc})"
        ms = int((time.monotonic() - start) * 1000)
        return AIReviewResult("ok", [], "Judge unavailable; using Gemini Safe verdict", ms, "single_fallback", trace)
