"""Reviewable patch proposals, explicit diff/apply, and post-patch verification."""

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


def _unified_diff(rel: str, old: str, new: str) -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
    )


def _propose_python_fstring_sqli(content: str, finding: Finding) -> tuple[str, str] | None:
    """Convert simple single-line `cur.execute(f"... {var} ...")` to parameterized `?` query."""
    lines = content.splitlines(keepends=True)
    idx = finding.start_line - 1
    if idx < 0 or idx >= len(lines):
        return None
    line = lines[idx]
    m = re.match(
        r'^(\s*)([A-Za-z_][\w.]*\.execute)\(\s*f(["\'])(.+?)\3\s*\)(.*)$',
        line.rstrip("\r\n"),
    )
    if not m:
        return None
    indent, call, quote, sql_body, trailing = m.groups()
    vars_found = re.findall(r"\{([^{}]+)\}", sql_body)
    if not vars_found:
        return None
    # Replace quoted '{var}' or bare {var} with SQL placeholder ?
    param_sql = re.sub(r"['\"]?\{[^{}]+\}['\"]?", "?", sql_body)
    params_tuple = ", ".join(v.strip() for v in vars_found)
    if len(vars_found) == 1:
        params_tuple += ","
    newline = "\n" if line.endswith("\n") else ""
    new_line = f"{indent}{call}({quote}{param_sql}{quote}, ({params_tuple})){trailing}{newline}"
    new_lines = lines[:idx] + [new_line] + lines[idx + 1 :]
    return "".join(new_lines), "Replace interpolated f-string SQL with parameterized query (?)"


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


def propose_patch(root: str, finding: Finding) -> PatchProposal | None:
    """Return a reviewable PatchProposal for supported deterministic rules, or None."""
    path = os.path.join(root, finding.file)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as fh:
        original = fh.read()

    res: tuple[str, str] | None = None
    if finding.rule_id == "python-sql-injection-fstring":
        res = _propose_python_fstring_sqli(original, finding)
    elif finding.rule_id == "flask-debug-enabled":
        res = _propose_flask_debug_off(original, finding)

    if not res:
        return None
    new_content, desc = res
    if new_content == original:
        return None
    diff = _unified_diff(finding.file, original, new_content)
    finding.suggested_patch = diff
    finding.patch_source = "deterministic"
    return PatchProposal(
        finding_id=finding.id,
        file=finding.file,
        description=desc,
        original_content=original,
        new_content=new_content,
        diff=diff,
    )


def apply_patch(root: str, proposal: PatchProposal) -> None:
    path = os.path.join(root, proposal.file)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(proposal.new_content)


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

