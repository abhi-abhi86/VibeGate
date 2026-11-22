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

CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java", ".php", ".cs", ".sql", ".sh", ".yml", ".yaml", ".html"}
LLM_CALL_TIMEOUT = 15.0


@dataclass
class AIProvider:
    name: str
    kind: str  # gemini | openai_compat | anthropic
    api_key: str
    model: str
    url: str = ""


_OPENAI_COMPAT_SPECS = (
    ("GROQ", "groq", "https://api.groq.com/openai/v1/chat/completions", "openai/gpt-oss-120b"),
    ("OPENAI", "openai", "https://api.openai.com/v1/chat/completions", "gpt-4o-mini"),
    ("OPENROUTER", "openrouter", "https://openrouter.ai/api/v1/chat/completions", "openai/gpt-4o-mini"),
    ("MISTRAL", "mistral", "https://api.mistral.ai/v1/chat/completions", "mistral-small-latest"),
    ("DEEPSEEK", "deepseek", "https://api.deepseek.com/v1/chat/completions", "deepseek-chat"),
    ("TOGETHER", "together", "https://api.together.xyz/v1/chat/completions", "meta-llama/Llama-3.3-70B-Instruct-Turbo"),
    ("XAI", "xai", "https://api.x.ai/v1/chat/completions", "grok-2-latest"),
)


def _collect_env_keys(prefix: str) -> list[str]:
    """Collect single, comma-separated (<PREFIX>_API_KEYS), and numbered (<PREFIX>_API_KEY_1..N) keys."""
    keys: list[str] = []
    single = os.environ.get(f"{prefix}_API_KEY", "").strip()
    if single:
        keys.append(single)
    multi = os.environ.get(f"{prefix}_API_KEYS", "").strip()
    if multi:
        keys.extend(k.strip() for k in multi.split(",") if k.strip())
    numbered: list[tuple[int, str]] = []
    pat = re.compile(rf"^{re.escape(prefix)}_API_KEY_(\d+)$")
    for env_name, env_val in os.environ.items():
        m = pat.match(env_name)
        if m and env_val.strip():
            numbered.append((int(m.group(1)), env_val.strip()))
    for _, val in sorted(numbered, key=lambda x: x[0]):
        keys.append(val)
    # Preserve order while deduplicating identical keys
    seen: set[str] = set()
    out: list[str] = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def discover_ai_providers(cfg: Config) -> list[AIProvider]:
    """Discover all configured AI API keys (1, 2, 10, 25, or 100+) from environment variables."""
    providers: list[AIProvider] = []

    gemini_keys = _collect_env_keys("GEMINI")
    for idx, key in enumerate(gemini_keys, 1):
        name = "gemini" if idx == 1 else f"gemini_{idx}"
        providers.append(AIProvider(name=name, kind="gemini", api_key=key, model=cfg.ai_model))

    for prefix, slug, default_url, default_model in _OPENAI_COMPAT_SPECS:
        model_override = cfg.groq_model if prefix == "GROQ" else os.environ.get(f"{prefix}_MODEL", "").strip() or default_model
        url_override = os.environ.get(f"{prefix}_BASE_URL", "").strip() or default_url
        keys = _collect_env_keys(prefix)
        for idx, key in enumerate(keys, 1):
            name = slug if idx == 1 else f"{slug}_{idx}"
            providers.append(AIProvider(name=name, kind="openai_compat", api_key=key, model=model_override, url=url_override))

    anthropic_keys = _collect_env_keys("ANTHROPIC")
    anthropic_model = os.environ.get("ANTHROPIC_MODEL", "").strip() or "claude-3-5-haiku-latest"
    for idx, key in enumerate(anthropic_keys, 1):
        name = "anthropic" if idx == 1 else f"anthropic_{idx}"
        providers.append(
            AIProvider(
                name=name,
                kind="anthropic",
                api_key=key,
                model=anthropic_model,
                url="https://api.anthropic.com/v1/messages",
            )
        )

    # Custom OpenAI-compatible endpoints: CUSTOM_AI_KEY_1..N + CUSTOM_AI_URL_1..N
    custom_pat = re.compile(r"^CUSTOM_AI_KEY_(\d+)$")
    custom_idxs = sorted(int(m.group(1)) for k in os.environ if (m := custom_pat.match(k)) and os.environ[k].strip())
    for idx in custom_idxs:
        key = os.environ.get(f"CUSTOM_AI_KEY_{idx}", "").strip()
        url = os.environ.get(f"CUSTOM_AI_URL_{idx}", "").strip()
        model = os.environ.get(f"CUSTOM_AI_MODEL_{idx}", "").strip() or "gpt-4o-mini"
        if key and url:
            providers.append(AIProvider(name=f"custom_{idx}", kind="openai_compat", api_key=key, model=model, url=url))

    return providers


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
    norm = rel.replace("\\", "/").lower()
    _, ext = os.path.splitext(norm)
    if ext not in CODE_EXTENSIONS:
        return False
    if norm.startswith("tests/") or "/tests/" in norm or norm.endswith("_test.py") or ".test." in norm:
        return False
    if norm.endswith((".min.js", ".min.css")) or any(
        seg in norm for seg in ("/vendor/", "/node_modules/", "/dist/", "/build/", "/.venv/")
    ):
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


def _select_batches(target: ScanTarget, secret_findings: list[Finding], cfg: Config) -> list[list[tuple[str, str]]]:
    """Group all candidate code files into prompt-sized batches so no file is dropped."""
    secrets_by_file: dict[str, set[int]] = {}
    for f in secret_findings:
        if f.category == "secret" and f.start_line:
            secrets_by_file.setdefault(f.file, set()).update(range(f.start_line, max(f.start_line, f.end_line) + 1))

    # Prioritize route/auth/DB-relevant files first, then include all other code files
    ordered = sorted(
        target.files,
        key=lambda r: (0 if ROUTE_HINTS.search(target.read(r)) else 1, r),
    )

    max_files_per_batch = max(1, cfg.ai_max_files)
    max_chars_per_batch = max(1000, cfg.ai_max_chars)
    batches: list[list[tuple[str, str]]] = []
    current_batch: list[tuple[str, str]] = []
    current_chars = 0

    for rel in ordered:
        raw = target.read(rel)
        if not raw.strip() or not _is_candidate_file(rel, raw):
            continue
        redacted = _redact_secret_lines(raw, secrets_by_file.get(rel, set()))
        numbered = "\n".join(f"{i}: {ln}" for i, ln in enumerate(redacted.splitlines(), 1))
        if len(numbered) > max_chars_per_batch:
            numbered = numbered[:max_chars_per_batch] + "\n... [truncated]"

        if current_batch and (len(current_batch) >= max_files_per_batch or current_chars + len(numbered) > max_chars_per_batch):
            batches.append(current_batch)
            current_batch = []
            current_chars = 0

        current_batch.append((rel, numbered))
        current_chars += len(numbered)

    if current_batch:
        batches.append(current_batch)
    return batches


def _select_context(target: ScanTarget, secret_findings: list[Finding], cfg: Config) -> list[tuple[str, str]]:
    batches = _select_batches(target, secret_findings, cfg)
    return batches[0] if batches else []


def _build_prompt(snippets: list[tuple[str, str]], stack_guidance: str = "") -> str:
    files_block = "\n\n".join(f"=== FILE: {rel} ===\n{body}" for rel, body in snippets)
    stack_section = f"\nFRAMEWORK / STACK CONTEXT:\n{stack_guidance}\n" if stack_guidance else ""
    return (
        "You are an expert application security reviewer. Complete ALL 5 security tasks below thoroughly — "
        "do not skip any category:\n"
        f"{stack_section}"
        "TASK 1 (Access Control & Auth): Check every route/endpoint/form for Broken Access Control, IDOR, "
        "missing authentication/ownership checks, privilege escalation, and missing CSRF protection.\n"
        "TASK 2 (Injections & Traversal): Check for SQL injection, NoSQL injection, OS command injection, "
        "SSTI, XSS, SSRF, and Path Traversal.\n"
        "TASK 3 (Secrets, Crypto & Transport): Check for hardcoded credentials/API keys, weak cryptography "
        "(MD5/SHA1), disabled TLS verification, insecure cookies, wildcard CORS, and debug mode enabled.\n"
        "TASK 4 (Logic & Deserialization Bugs): Check for unsafe deserialization (pickle, yaml.load), "
        "race conditions, swallowed exceptions, or critical business-logic bypasses.\n"
        "TASK 5 (Explain Impact, Access & Fix): For every confirmed finding, state what happens if unfixed (`impact`), "
        "how it can be accessed (`access_example`), and a concrete `remediation` (plus `patch_old`/`patch_new` when safe).\n"
        "Rules:\n"
        "- Inspect EVERY provided file and EVERY function/route/line from top to bottom.\n"
        "- Do NOT stop after finding an issue in one file — list ALL distinct vulnerabilities and serious bugs across ALL provided files.\n"
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
        "  access_example (short 1-line example of how an attacker accesses/exploits it, e.g. \"?id=1' OR '1'='1' --\" or \"?q=<script>alert(1)</script>\" or \"GET /api/user/2 without auth\"),\n"
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


def _resolve_valid_file(raw_file: str, valid_files: set[str]) -> str | None:
    rel = raw_file.strip().lstrip("./")
    if rel in valid_files:
        return rel
    if raw_file.strip() in valid_files:
        return raw_file.strip()
    matches = [vf for vf in valid_files if vf == rel or vf.endswith("/" + rel) or os.path.basename(vf) == rel]
    if len(matches) == 1:
        return matches[0]
    return None


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
        rel = _resolve_valid_file(str(it.get("file", "")), valid_files)
        if not rel:
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
        if it.get("access_example"):
            extra["access_example"] = str(it["access_example"])[:200]
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


def _call_openai_compat(
    url: str,
    prompt: str,
    api_key: str,
    model: str,
    valid_files: set[str],
    scanned_version: str,
    timeout: float,
) -> tuple[bool, list[Finding], str]:
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


def _call_groq(prompt: str, api_key: str, model: str, valid_files: set[str], scanned_version: str, timeout: float) -> tuple[bool, list[Finding], str]:
    return _call_openai_compat(
        "https://api.groq.com/openai/v1/chat/completions",
        prompt,
        api_key,
        model,
        valid_files,
        scanned_version,
        timeout,
    )


def _call_anthropic(
    url: str,
    prompt: str,
    api_key: str,
    model: str,
    valid_files: set[str],
    scanned_version: str,
    timeout: float,
) -> tuple[bool, list[Finding], str]:
    payload = {
        "model": model,
        "max_tokens": 2048,
        "temperature": 0.1,
        "messages": [{"role": "user", "content": prompt}],
    }
    resp = httpx.post(
        url,
        json=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    body = resp.json()
    text = body["content"][0]["text"]
    return _parse_verdict(text, valid_files, scanned_version)


def _call_provider(
    provider: AIProvider,
    prompt: str,
    valid_files: set[str],
    scanned_version: str,
    timeout: float,
) -> tuple[bool, list[Finding], str]:
    if provider.kind == "gemini":
        return _call_gemini(prompt, provider.api_key, provider.model, valid_files, scanned_version, timeout)
    if provider.kind == "anthropic":
        return _call_anthropic(provider.url, prompt, provider.api_key, provider.model, valid_files, scanned_version, timeout)
    return _call_openai_compat(provider.url, prompt, provider.api_key, provider.model, valid_files, scanned_version, timeout)


def _build_multi_judge_prompt(
    snippets: list[tuple[str, str]],
    verdicts: list[tuple[str, bool, list[Finding], str]],
) -> str:
    files_block = "\n\n".join(f"=== FILE: {rel} ===\n{body}" for rel, body in snippets)
    opinions = []
    for pname, is_v, flist, reason in verdicts:
        titles = ", ".join(f"{f.file}:{f.start_line} {f.title}" for f in flist[:6]) or "none"
        opinions.append(f"- {pname}: is_vulnerable={is_v}, findings=[{titles}]\n  reasoning: {reason}")
    opinions_block = "\n".join(opinions)
    return (
        "You are the final Consensus Judge synthesizing independent reviews from multiple AI security models.\n"
        "Review their verdicts and reasoning below, verify against the actual provided code/data, and produce one "
        "authoritative consensus JSON verdict.\n\n"
        f"MODEL OPINIONS ({len(verdicts)}):\n{opinions_block}\n\n"
        "Return ONLY a strict JSON object:\n"
        '{"is_vulnerable": bool, "findings": [...], "reasoning": "2-3 sentence consensus explanation"}\n\n'
        f"{files_block}"
    )


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


def _run_n_provider_consensus(
    providers: list[AIProvider],
    snippets: list[tuple[str, str]],
    scanned_version: str,
    cfg: Config,
    per_call_timeout: float,
    stack_guidance: str,
    emit,
    start: float,
) -> AIReviewResult:
    """Run all N configured API keys/providers concurrently and synthesize a consensus verdict."""
    valid_files = {rel for rel, _ in snippets}
    files_list = ", ".join(sorted(valid_files))
    prompt = _build_prompt(snippets, stack_guidance=stack_guidance)
    question = f"Review {files_list} for security vulnerabilities, auth/IDOR gaps, and code bugs."
    emit("ai_start", f"Multi-Key Consensus ({len(providers)} key(s)): {question}")

    verdicts: list[tuple[AIProvider, bool, list[Finding], str]] = []
    errors: list[tuple[AIProvider, str]] = []

    def _ask(prov: AIProvider):
        return prov, _call_provider(prov, prompt, valid_files, scanned_version, per_call_timeout)

    with ThreadPoolExecutor(max_workers=min(12, len(providers))) as pool:
        for prov, outcome in pool.map(
            lambda p: _safe_call_provider(p, prompt, valid_files, scanned_version, per_call_timeout),
            providers,
        ):
            if isinstance(outcome, str):
                errors.append((prov, outcome))
            else:
                is_v, flist, reason = outcome
                verdicts.append((prov, is_v, flist, reason))

    if not verdicts:
        ms = int((time.monotonic() - start) * 1000)
        summary_err = "; ".join(f"{p.name}: {e}" for p, e in errors[:3])
        return AIReviewResult("unavailable", [], f"All {len(providers)} AI key(s) failed ({summary_err})", ms)

    trace: dict[str, str] = {"consensus_q": question}
    for prov, is_v, flist, reason in verdicts:
        trace[prov.name] = f"[{'VULNERABLE' if is_v else 'SAFE'} · {len(flist)} finding(s)] {reason}"
    for prov, err in errors:
        trace[prov.name] = f"fallback ({err})"

    total_ok = len(verdicts)
    vuln_votes = [v for v in verdicts if v[1]]
    safe_votes = [v for v in verdicts if not v[1]]
    ms = int((time.monotonic() - start) * 1000)

    # Unanimous Safe
    if not vuln_votes:
        status = f"{total_ok}/{total_ok}_safe" if total_ok >= 2 else "single"
        return AIReviewResult("ok", [], f"{total_ok}/{len(providers)} AI key(s) agreed: Safe", ms, status, trace)

    # Unanimous Vulnerable (or single provider) -> merge findings
    if not safe_votes:
        merged = _deduplicate_findings([f for _, _, flist, _ in vuln_votes for f in flist])
        status = f"{total_ok}/{total_ok}_vulnerable" if total_ok >= 2 else "single"
        _attach_consensus(merged, status, trace)
        return AIReviewResult("ok", merged, f"{total_ok}/{len(providers)} AI key(s) found {len(merged)} issue(s)", ms, status, trace)

    # Disagreement among N providers -> Synthesis Judge using the first responding provider
    judge_prov = verdicts[0][0]
    judge_prompt = _build_multi_judge_prompt(
        snippets,
        [(p.name, is_v, flist, reason) for p, is_v, flist, reason in verdicts],
    )
    emit("ai_start", f"Consensus Judge ({judge_prov.name}) synthesizing {total_ok} opinions for {files_list}...")
    try:
        j_vuln, j_findings, j_reason = _call_provider(judge_prov, judge_prompt, valid_files, scanned_version, per_call_timeout)
        trace["judge"] = j_reason
        final_findings = j_findings if j_vuln else []
        _attach_consensus(final_findings, "debate_resolved", trace)
        ms = int((time.monotonic() - start) * 1000)
        return AIReviewResult(
            "ok",
            final_findings,
            f"Consensus Judge ({judge_prov.name}) synthesized {total_ok} AI opinions",
            ms,
            "debate_resolved",
            trace,
        )
    except Exception as exc:
        trace["judge"] = f"judge fallback ({type(exc).__name__}: {exc})"
        merged = _deduplicate_findings([f for _, _, flist, _ in vuln_votes for f in flist]) if len(vuln_votes) >= len(safe_votes) else []
        _attach_consensus(merged, "single_fallback", trace)
        ms = int((time.monotonic() - start) * 1000)
        return AIReviewResult("ok", merged, f"Majority vote across {total_ok} AI key(s)", ms, "single_fallback", trace)


def _safe_call_provider(
    prov: AIProvider,
    prompt: str,
    valid_files: set[str],
    scanned_version: str,
    timeout: float,
):
    try:
        return prov, _call_provider(prov, prompt, valid_files, scanned_version, timeout)
    except httpx.TimeoutException:
        return prov, f"timed out after {timeout}s"
    except httpx.HTTPStatusError as exc:
        return prov, f"HTTP {exc.response.status_code}"
    except Exception as exc:
        return prov, f"{type(exc).__name__}: {exc}"


def _review_batch(
    snippets: list[tuple[str, str]],
    scanned_version: str,
    cfg: Config,
    providers: list[AIProvider],
    per_call_timeout: float,
    use_consensus: bool,
    stack_guidance: str,
    emit,
    start: float,
) -> AIReviewResult:
    # 3+ keys, or non-(Gemini+Groq) combinations -> dynamic N-provider parallel consensus + synthesis judge
    is_classic_two_key = (
        len(providers) == 2 and providers[0].name == "gemini" and providers[1].name == "groq"
    )
    if len(providers) >= 3 or (len(providers) >= 1 and not is_classic_two_key and providers[0].name != "gemini"):
        return _run_n_provider_consensus(
            providers, snippets, scanned_version, cfg, per_call_timeout, stack_guidance, emit, start
        )
    if len(providers) == 1 and not use_consensus:
        # Classic single Gemini path
        gemini_key = providers[0].api_key
        groq_key = ""
    elif is_classic_two_key:
        gemini_key = providers[0].api_key
        groq_key = providers[1].api_key
    else:
        gemini_key = providers[0].api_key
        groq_key = ""

    valid_files = {rel for rel, _ in snippets}
    files_list = ", ".join(sorted(valid_files))
    prompt = _build_prompt(snippets, stack_guidance=stack_guidance)

    gemini_q = f"Are there any security vulnerabilities (auth/IDOR, injection, XSS, SSRF, crypto, secrets) or code bugs in {files_list}?"
    groq_q = f"Gemini reported Safe — double-check {files_list} for any hidden vulnerabilities or code bugs?"

    if not use_consensus or not groq_key:
        emit("ai_start", f"Layer 1 (Gemini) Q: {gemini_q}")
        try:
            _is_vuln, findings, reasoning = _call_gemini(prompt, gemini_key, cfg.ai_model, valid_files, scanned_version, per_call_timeout)
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
        g_verdict = _call_gemini(prompt, gemini_key, cfg.ai_model, valid_files, scanned_version, per_call_timeout)
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
            q_vuln, q_findings, q_reason = _call_groq(prompt, groq_key, cfg.groq_model, valid_files, scanned_version, per_call_timeout)
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
        q_vuln, q_findings, q_reason = _call_groq(prompt, groq_key, cfg.groq_model, valid_files, scanned_version, per_call_timeout)
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
        j_vuln, j_findings, j_reason = _call_gemini(judge_prompt, gemini_key, cfg.ai_model, valid_files, scanned_version, per_call_timeout)
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


def run_ai_review(
    target: ScanTarget,
    secret_findings: list[Finding],
    cfg: Config,
    progress_cb=None,
    stack_guidance: str = "",
) -> AIReviewResult:
    def emit(event: str, msg: str) -> None:
        if progress_cb:
            progress_cb(event, msg)

    start = time.monotonic()
    if not cfg.ai_enabled:
        return AIReviewResult("skipped", [], "AI review disabled (--no-ai or config)")

    providers = discover_ai_providers(cfg)
    if not providers:
        return AIReviewResult("unavailable", [], "No AI API keys set (e.g. GEMINI_API_KEY, GROQ_API_KEY, OPENAI_API_KEY); AI review skipped")

    batches = _select_batches(target, secret_findings, cfg)
    if not batches:
        return AIReviewResult("skipped", [], "no route/controller/auth-relevant code in staged changes")

    per_call_timeout = min(float(cfg.ai_timeout), LLM_CALL_TIMEOUT)
    use_consensus = cfg.consensus_enabled or len(providers) >= 2

    if len(batches) == 1:
        return _review_batch(
            batches[0],
            target.version,
            cfg,
            providers,
            per_call_timeout,
            use_consensus,
            stack_guidance,
            emit,
            start,
        )

    total_files = sum(len(b) for b in batches)
    # When 3+ keys are available across multiple batches, rotate a multi-key quorum per batch
    # so all keys work together in parallel without exhausting rate limits on a single key.
    def _providers_for_batch(batch_idx: int) -> list[AIProvider]:
        if len(providers) <= 3:
            return providers
        quorum_size = min(3, len(providers))
        offset = (batch_idx * quorum_size) % len(providers)
        return [providers[(offset + j) % len(providers)] for j in range(quorum_size)]

    with ThreadPoolExecutor(max_workers=min(8, max(len(batches), len(providers)))) as pool:
        results = list(
            pool.map(
                lambda item: _review_batch(
                    item[1],
                    target.version,
                    cfg,
                    _providers_for_batch(item[0]),
                    per_call_timeout,
                    use_consensus,
                    stack_guidance,
                    emit,
                    start,
                ),
                enumerate(batches),
            )
        )

    ok_results = [r for r in results if r.status == "ok"]
    ms = int((time.monotonic() - start) * 1000)
    if not ok_results:
        return results[0]

    all_findings = _deduplicate_findings([f for r in ok_results for f in r.findings])
    merged_trace: dict[str, str] = {}
    for idx, r in enumerate(ok_results, 1):
        for k, v in r.reasoning_trace.items():
            key = k if len(ok_results) == 1 else f"batch{idx}_{k}"
            merged_trace[key] = v

    consensus = ok_results[0].consensus_status if all(r.consensus_status == ok_results[0].consensus_status for r in ok_results) else "single"
    return AIReviewResult(
        "ok",
        all_findings,
        f"reviewed {total_files} file(s) across {len(batches)} batch(es) with {cfg.ai_model}",
        ms,
        consensus,
        merged_trace,
    )
