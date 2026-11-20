"""Reviewable patch proposals, one-keystroke auto-fixing, and post-patch verification."""

from __future__ import annotations

import difflib
import os
import re
import subprocess
from dataclasses import dataclass

from vibegate import git
from vibegate.models import (
    NO_LONGER_REPRODUCES,
    STILL_REPRODUCES,
    TESTS_FAILED,
    TESTS_PASSED,
    Finding,
)
from vibegate.scanners import build_scanners
from vibegate.scanners.base import ScanTarget


@dataclass
class PatchProposal:
    finding_id: str
    file: str
    description: str
    original_content: str
    new_content: str
    diff: str
    patch_source: str = "deterministic"
    env_updates: dict[str, str] | None = None


def _unified_diff(rel: str, old: str, new: str) -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
    )


def _ensure_import_os(content: str) -> str:
    if re.search(r"(?m)^\s*import\s+os\b", content) or re.search(r"(?m)^\s*from\s+os\s+import\b", content):
        return content
    lines = content.splitlines(keepends=True)
    insert_at = 0
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("#") or s.startswith('"""') or s.startswith("'''") or not s:
            insert_at = i + 1
            continue
        if s.startswith("import ") or s.startswith("from "):
            insert_at = i
        break
    lines.insert(insert_at, "import os\n")
    return "".join(lines)


def _propose_secret_to_env(content: str, finding: Finding) -> tuple[str, str, dict[str, str]] | None:
    """Move a hard-coded Python string assignment into .env and replace with os.getenv(...)."""
    lines = content.splitlines(keepends=True)
    idx = max(0, finding.start_line - 1)
    for i in [idx, *range(max(0, idx - 3), min(len(lines), idx + 6))]:
        if i >= len(lines):
            continue
        line = lines[i]
        m = re.match(r'^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(["\'])(.+?)\3(.*)$', line.rstrip("\r\n"))
        if not m:
            continue
        indent, var_name, _quote, secret_val, trailing = m.groups()
        env_key = var_name.upper()
        newline = "\n" if line.endswith("\n") else ""
        lines[i] = f'{indent}{var_name} = os.getenv("{env_key}", ""){trailing}{newline}'
        new_content = _ensure_import_os("".join(lines))
        return new_content, f'Move {var_name} to .env and load via os.getenv("{env_key}")', {env_key: secret_val}
    return None


def _propose_python_fstring_sqli(content: str, finding: Finding) -> tuple[str, str] | None:
    """Convert simple single-line `cur.execute(f"... {var} ...")` to parameterized `?` query."""
    lines = content.splitlines(keepends=True)
    idx = max(0, finding.start_line - 1)
    for i in [idx, *range(max(0, idx - 3), min(len(lines), idx + 6))]:
        if i >= len(lines):
            continue
        line = lines[i]
        m = re.match(
            r'^(\s*)([A-Za-z_][\w.]*\.execute)\(\s*f(["\'])(.+?)\3\s*\)(.*)$',
            line.rstrip("\r\n"),
        )
        if not m:
            continue
        indent, call, quote, sql_body, trailing = m.groups()
        vars_found = re.findall(r"\{([^{}]+)\}", sql_body)
        if not vars_found:
            continue
        param_sql = re.sub(r"['\"]?\{[^{}]+\}['\"]?", "?", sql_body)
        params_tuple = ", ".join(v.strip() for v in vars_found)
        if len(vars_found) == 1:
            params_tuple += ","
        newline = "\n" if line.endswith("\n") else ""
        new_line = f"{indent}{call}({quote}{param_sql}{quote}, ({params_tuple})){trailing}{newline}"
        new_lines = lines[:i] + [new_line] + lines[i + 1 :]
        return "".join(new_lines), "Replace interpolated f-string SQL with parameterized query (?)"
    return None


def _propose_flask_debug_off(content: str, finding: Finding) -> tuple[str, str] | None:
    lines = content.splitlines(keepends=True)
    idx = finding.start_line - 1
    if idx < 0 or idx >= len(lines):
        return None
    line = lines[idx]
    if "debug=True" not in line:
        return None
    new_line = line.replace("debug=True", "debug=False")
    new_lines = lines[:idx] + [new_line] + lines[idx + 1 :]
    return "".join(new_lines), "Disable Flask debug=True"


def _propose_access_control_fix(content: str, finding: Finding) -> tuple[str, str] | None:
    """Apply AI-suggested minimal patch if present, or insert a Flask ownership check on route ID."""
    patch_old = finding.extra.get("patch_old")
    patch_new = finding.extra.get("patch_new")
    if patch_old and patch_new and patch_old in content:
        return content.replace(patch_old, patch_new, 1), "Apply AI-suggested authorization check"

    lines = content.splitlines(keepends=True)
    idx = max(0, finding.start_line - 1)
    for i in range(idx, min(len(lines), idx + 6)):
        m = re.match(r"^(\s*)def\s+\w+\([^)]*\b([A-Za-z_]*id)\b[^)]*\)\s*:", lines[i])
        if not m:
            continue
        def_indent, id_param = m.groups()
        body_indent = def_indent + "    "
        insert_at = i + 1
        while insert_at < len(lines) and (lines[insert_at].strip().startswith("#") or not lines[insert_at].strip()):
            insert_at += 1
        guard = (
            f'{body_indent}if session.get("user_id") != {id_param}:\n'
            f'{body_indent}    return jsonify({{"error": "forbidden"}}), 403\n'
        )
        new_lines = lines[:insert_at] + [guard] + lines[insert_at:]
        return "".join(new_lines), f"Enforce session['user_id'] == {id_param} ownership check"
    return None


def _propose_requirements_bump(content: str, finding: Finding) -> tuple[str, str] | None:
    pkg = finding.extra.get("package")
    fixed = finding.extra.get("fixed_versions") or []
    if not pkg or not fixed:
        return None
    target_ver = max(fixed, key=lambda v: tuple(int(p) if p.isdigit() else 0 for p in v.split(".")))
    lines = content.splitlines(keepends=True)
    pat = re.compile(rf"^(\s*{re.escape(pkg)})\s*(?:==|>=|~=)\s*[^\s;#]+(.*)$", re.IGNORECASE)
    changed = False
    for i, ln in enumerate(lines):
        m = pat.match(ln.rstrip("\r\n"))
        if m:
            newline = "\n" if ln.endswith("\n") else ""
            lines[i] = f"{m.group(1)}>={target_ver}{m.group(2)}{newline}"
            changed = True
            break
    if not changed:
        return None
    return "".join(lines), f"Bump {pkg} to >={target_ver}"


def propose_patch(root: str, finding: Finding) -> PatchProposal | None:
    """Return a reviewable PatchProposal for supported rules, or None."""
    path = os.path.join(root, finding.file)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as fh:
        original = fh.read()

    res: tuple[str, str] | None = None
    env_updates: dict[str, str] | None = None
    patch_source = "deterministic"

    if finding.category == "secret" and finding.file.endswith(".py"):
        sec_res = _propose_secret_to_env(original, finding)
        if sec_res:
            new_content, desc, env_updates = sec_res
            res = (new_content, desc)
    elif finding.rule_id == "python-sql-injection-fstring":
        res = _propose_python_fstring_sqli(original, finding)
    elif finding.rule_id == "flask-debug-enabled":
        res = _propose_flask_debug_off(original, finding)
    elif finding.category == "access_control":
        res = _propose_access_control_fix(original, finding)
        patch_source = "ai" if finding.ai_generated else "deterministic"
    elif finding.category == "dependency":
        res = _propose_requirements_bump(original, finding)

    if not res:
        return None
    new_content, desc = res
    if new_content == original:
        return None
    diff = _unified_diff(finding.file, original, new_content)
    finding.suggested_patch = diff
    finding.patch_source = patch_source
    return PatchProposal(
        finding_id=finding.id,
        file=finding.file,
        description=desc,
        original_content=original,
        new_content=new_content,
        diff=diff,
        patch_source=patch_source,
        env_updates=env_updates,
    )


def _write_env_updates(root: str, env_updates: dict[str, str]) -> None:
    if not env_updates:
        return
    env_path = os.path.join(root, ".env")
    example_path = os.path.join(root, ".env.example")
    for path, include_val in ((env_path, True), (example_path, False)):
        existing = ""
        if os.path.isfile(path):
            with open(path, encoding="utf-8", errors="replace") as fh:
                existing = fh.read()
        lines = existing.splitlines()
        for k, v in env_updates.items():
            prefix = f"{k}="
            replaced = False
            for i, ln in enumerate(lines):
                if ln.startswith(prefix):
                    if include_val:
                        lines[i] = f"{k}={v}"
                    replaced = True
                    break
            if not replaced:
                lines.append(f"{k}={v if include_val else ''}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")


def apply_patch(root: str, proposal: PatchProposal) -> None:
    path = os.path.join(root, proposal.file)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(proposal.new_content)
    if proposal.env_updates:
        _write_env_updates(root, proposal.env_updates)


def apply_all_safe_fixes(
    root: str,
    findings: list[Finding],
    partially_staged_files: list[str] | None = None,
    restage: bool = True,
) -> tuple[list[PatchProposal], list[str]]:
    """Apply all available safe patches sequentially and optionally re-stage modified files."""
    partial = set(partially_staged_files or [])
    applied: list[PatchProposal] = []
    skipped: list[str] = []
    touched_files: set[str] = set()

    for f in findings:
        if f.suppressed or f.dismissed or f.verification_status == NO_LONGER_REPRODUCES:
            continue
        if f.file in partial:
            skipped.append(f"{f.id} ({f.file}): partially staged; skipped auto-patch")
            continue
        prop = propose_patch(root, f)
        if not prop:
            skipped.append(f"{f.id} ({f.rule_id}): no auto-patch template")
            continue
        apply_patch(root, prop)
        applied.append(prop)
        touched_files.add(prop.file)
        if prop.env_updates and os.path.isfile(os.path.join(root, ".env.example")):
            touched_files.add(".env.example")

    if restage and touched_files and git.find_repo_root(root):
        for rel in sorted(touched_files):
            git.stage_file(root, rel)

    return applied, skipped


def verify_finding_recheck(root: str, finding: Finding, timeout: int = 60) -> tuple[str, str]:
    """Rerun only the original deterministic scanner on the modified file and report precisely."""
    if finding.source not in ("gitleaks", "semgrep", "osv-scanner"):
        return finding.verification_status, "Cannot deterministically re-verify an AI candidate finding."

    scanner = build_scanners([finding.source])[finding.source]
    target = ScanTarget(root=root, files=[finding.file], version="working tree")
    res = scanner.run(target, timeout=timeout)
    if res.status != "ok":
        return finding.verification_status, f"Rescan with {finding.source} did not complete ({res.status}: {res.message})."

    still = [
        f
        for f in res.findings
        if f.rule_id == finding.rule_id and f.file == finding.file
    ]
    if not still:
        finding.verification_status = NO_LONGER_REPRODUCES
        finding.verification_note = (
            f"The {finding.source} rule '{finding.rule_id}' no longer reproduces on {finding.file} (working tree)."
        )
    else:
        finding.verification_status = STILL_REPRODUCES
        finding.verification_note = (
            f"The {finding.source} rule '{finding.rule_id}' still triggers on {finding.file} (line {still[0].start_line})."
        )
    return finding.verification_status, finding.verification_note


def run_authorized_tests(root: str, command: str, finding: Finding) -> tuple[bool, str]:
    proc = subprocess.run(command, shell=True, cwd=root, capture_output=True, text=True, timeout=120)
    output = (proc.stdout + "\n" + proc.stderr).strip()[-800:]
    if proc.returncode == 0:
        finding.verification_status = TESTS_PASSED
        finding.verification_note = f"Test command `{command}` passed after patch."
        return True, output
    finding.verification_status = TESTS_FAILED
    finding.verification_note = f"Test command `{command}` failed (exit {proc.returncode})."
    return False, output


def stage_patched_file(root: str, rel: str) -> None:
    git.stage_file(root, rel)
