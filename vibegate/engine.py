"""Core scan engine: prepares staged/working-tree target, runs scanners in parallel, applies policy."""

from __future__ import annotations

import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

from vibegate import git
from vibegate.ai import AIReviewResult, run_ai_review
from vibegate.config import Config
from vibegate.detect import detect_stacks, stack_ai_guidance, stack_rule_paths
from vibegate.models import Finding, sev_rank
from vibegate.scanners import ScannerResult, ScanTarget, build_scanners
from vibegate.scanners.semgrep import SemgrepScanner
from vibegate.suppress import Suppression, apply_suppressions, load_suppressions


@dataclass
class ScanReport:
    target_root: str
    scanned_version: str
    files_scanned: list[str]
    partially_staged_files: list[str]
    findings: list[Finding]
    scanner_results: list[ScannerResult]
    ai_result: AIReviewResult
    suppressions_loaded: list[Suppression] = field(default_factory=list)
    ref_summaries: list[dict] = field(default_factory=list)
    detected_stacks: list[str] = field(default_factory=list)
    duration_ms: int = 0
    policy_fail_on: str = "high"
    policy_blocked: bool = False
    block_reasons: list[str] = field(default_factory=list)

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed and not f.dismissed]

    @property
    def suppressed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.suppressed or f.dismissed]

    def to_dict(self) -> dict:
        return {
            "version": "0.1.0",
            "scanned_version": self.scanned_version,
            "detected_stacks": self.detected_stacks,
            "files_scanned": self.files_scanned,
            "partially_staged_files": self.partially_staged_files,
            "duration_ms": self.duration_ms,
            "policy": {
                "fail_on": self.policy_fail_on,
                "blocked": self.policy_blocked,
                "reasons": self.block_reasons,
            },
            "scanners": [s.to_dict() for s in self.scanner_results],
            "ai_review": self.ai_result.to_dict(),
            "summary": {
                "total_findings": len(self.findings),
                "active_findings": len(self.active_findings),
                "suppressed_or_dismissed": len(self.suppressed_findings),
            },
            "ref_summaries": self.ref_summaries,
            "findings": [f.to_dict() for f in self.findings],
        }


def evaluate_policy(
    findings: list[Finding],
    scanner_results: list[ScannerResult],
    cfg: Config,
) -> tuple[bool, list[str]]:
    threshold = sev_rank(cfg.fail_on)
    reasons: list[str] = []
    blocking = []
    for f in findings:
        if f.suppressed or f.dismissed:
            continue
        if f.ai_generated and not cfg.ai_findings_block:
            continue
        if sev_rank(f.severity) >= threshold:
            blocking.append(f)
    if blocking:
        reasons.append(f"{len(blocking)} active finding(s) at or above severity '{cfg.fail_on}'")
    if cfg.block_on_scanner_error:
        bad = [s for s in scanner_results if s.status in ("error", "timeout", "not_installed")]
        if bad:
            reasons.append("scanner failure(s): " + ", ".join(f"{s.name}={s.status}" for s in bad))
    return bool(reasons), reasons


def _run_on_target(
    target: ScanTarget,
    repo_root: str | None,
    partially_staged_files: list[str],
    cfg: Config,
    start_time: float,
    progress_cb: Callable[[str, str], None] | None = None,
) -> ScanReport:
    def emit(event: str, msg: str) -> None:
        if progress_cb:
            progress_cb(event, msg)

    stacks = detect_stacks(target)
    scanners = build_scanners(cfg.scanners)
    if "semgrep" in scanners:
        scanners["semgrep"] = SemgrepScanner(configs=stack_rule_paths(stacks))
    guidance = stack_ai_guidance(stacks)

    scanner_results: list[ScannerResult] = []
    ai_res: AIReviewResult | None = None
    emit("scanners_start", f"Running {', '.join(scanners)} + ai-review concurrently on {len(target.files)} file(s)...")
    with ThreadPoolExecutor(max_workers=max(2, len(scanners) + 1)) as pool:
        scanner_futs = {pool.submit(s.run, target, cfg.scanner_timeout): name for name, s in scanners.items()}
        ai_fut = pool.submit(run_ai_review, target, [], cfg, progress_cb=progress_cb, stack_guidance=guidance)
        all_futs = list(scanner_futs.keys()) + [ai_fut]
        for fut in as_completed(all_futs):
            if fut is ai_fut:
                ai_res = fut.result()
                emit("ai_done", f"ai-review: {ai_res.status} ({ai_res.duration_ms}ms, {len(ai_res.findings)} finding(s))")
            else:
                res = fut.result()
                scanner_results.append(res)
                emit("scanner_done", f"{res.name}: {res.status} ({res.duration_ms}ms, {len(res.findings)} finding(s))")

    assert ai_res is not None
    findings: list[Finding] = []
    for sr in scanner_results:
        for f in sr.findings:
            f.scanned_version = target.version
            findings.append(f)

    for f in ai_res.findings:
        f.scanned_version = target.version
        # Avoid duplicate panels when a deterministic scanner already flagged the same file & line range
        overlaps = any(
            df.file == f.file
            and df.start_line <= f.end_line
            and f.start_line <= max(df.start_line, df.end_line)
            for df in findings
        )
        if not overlaps:
            findings.append(f)

    for f in findings:
        if f.category == "secret":
            f.code_snippet = f.code_snippet or f.evidence
        elif f.start_line and not f.code_snippet:
            lines = target.read(f.file).splitlines()
            if lines:
                lo = max(1, f.start_line - 1)
                hi = min(len(lines), max(f.start_line, f.end_line) + 1)
                snippet_lines = [
                    f"{'>>' if f.start_line <= ln <= max(f.start_line, f.end_line) else '  '} {ln:>4} | {lines[ln - 1]}"
                    for ln in range(lo, hi + 1)
                ]
                f.code_snippet = "\n".join(snippet_lines)
        elif not f.code_snippet:
            f.code_snippet = f.evidence

    suppressions = load_suppressions(repo_root)
    apply_suppressions(findings, suppressions)

    findings.sort(key=lambda f: (1 if f.category == "dependency" else 0, -sev_rank(f.severity), f.file, f.start_line))
    blocked, reasons = evaluate_policy(findings, scanner_results, cfg)

    return ScanReport(
        target_root=repo_root or target.root,
        scanned_version=target.version,
        files_scanned=list(target.files),
        partially_staged_files=partially_staged_files,
        findings=findings,
        scanner_results=scanner_results,
        ai_result=ai_res,
        suppressions_loaded=suppressions,
        detected_stacks=stacks,
        duration_ms=int((time.monotonic() - start_time) * 1000),
        policy_fail_on=cfg.fail_on,
        policy_blocked=blocked,
        block_reasons=reasons,
    )


def scan_staged(
    repo_root: str, cfg: Config, progress_cb: Callable[[str, str], None] | None = None
) -> ScanReport:
    start = time.monotonic()
    files = git.staged_files(repo_root)
    partial = git.partially_staged(repo_root, files)
    if not files:
        return ScanReport(
            target_root=repo_root,
            scanned_version="staged",
            files_scanned=[],
            partially_staged_files=[],
            findings=[],
            scanner_results=[],
            ai_result=AIReviewResult("skipped", [], "no staged files to scan"),
            duration_ms=int((time.monotonic() - start) * 1000),
            policy_fail_on=cfg.fail_on,
        )

    with tempfile.TemporaryDirectory(prefix="vibegate-staged-") as td:
        git.checkout_index(repo_root, files, td)
        target = ScanTarget(root=td, files=files, version="staged")
        return _run_on_target(target, repo_root, partial, cfg, start, progress_cb=progress_cb)


def scan_working_tree(
    path: str, cfg: Config, progress_cb: Callable[[str, str], None] | None = None
) -> ScanReport:
    start = time.monotonic()
    abs_path = os.path.abspath(path)
    if os.path.isfile(abs_path):
        parent = os.path.dirname(abs_path)
        filename = os.path.basename(abs_path)
        target = ScanTarget(root=parent, files=[filename], version=f"file:{abs_path}")
        return _run_on_target(target, None, [], cfg, start, progress_cb=progress_cb)

    repo_root = git.find_repo_root(abs_path)
    if repo_root and os.path.realpath(abs_path) == os.path.realpath(repo_root):
        files = git.listed_files(repo_root)
        partial = git.partially_staged(repo_root)
        target = ScanTarget(root=repo_root, files=files, version="working tree")
        return _run_on_target(target, repo_root, partial, cfg, start, progress_cb=progress_cb)

    files = []
    for dirpath, dirnames, filenames in os.walk(abs_path):
        dirnames[:] = [d for d in dirnames if d not in (".git", ".venv", "node_modules", "__pycache__")]
        for fn in filenames:
            files.append(os.path.relpath(os.path.join(dirpath, fn), abs_path))
    target = ScanTarget(root=abs_path, files=sorted(files), version="directory")
    return _run_on_target(target, None, [], cfg, start, progress_cb=progress_cb)


def scan_remote_repo(
    url: str, cfg: Config, branch: str | None = None, progress_cb: Callable[[str, str], None] | None = None
) -> ScanReport:
    start = time.monotonic()
    if progress_cb:
        progress_cb("clone_start", f"Cloning {url}...")
    td_path = ""
    with tempfile.TemporaryDirectory(prefix="vibegate-repo-") as td:
        td_path = td
        git.clone_repo(url, td, branch=branch)
        head_sha = git._git(["rev-parse", "HEAD"], cwd=td, check=False).strip()
        head_branch = git._git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=td, check=False).strip() or "HEAD"
        files = git.listed_files(td)
        if progress_cb:
            progress_cb("clone_done", f"Cloned {len(files)} file(s) from {url} ({head_branch})")

        target = ScanTarget(root=td, files=files, version=f"branch:{head_branch}")
        report = _run_on_target(target, None, [], cfg, start, progress_cb=progress_cb)
        ref_summaries = [
            {
                "ref": f"branch:{head_branch} (default)",
                "sha": head_sha[:7],
                "finding_count": len(report.active_findings),
            }
        ]

        if not branch:
            all_refs = git.list_remote_branches_and_prs(td)
            seen_shas = {head_sha: f"branch:{head_branch}"}
            all_findings = list(report.findings)
            for label, sha in all_refs:
                if sha in seen_shas:
                    if label != f"branch:{head_branch}":
                        ref_summaries.append({"ref": label, "sha": sha[:7], "finding_count": len(report.active_findings), "note": f"same commit as {seen_shas[sha]}"})
                    continue
                if progress_cb:
                    progress_cb("ref_scan", f"Checking changed files in {label} ({sha[:7]})...")
                if not git.fetch_commit(td, sha):
                    continue
                seen_shas[sha] = label
                changed = git.changed_files_for_ref(td, head_sha, sha)
                if not changed:
                    ref_summaries.append({"ref": label, "sha": sha[:7], "finding_count": 0, "note": "no changed files"})
                    continue
                with tempfile.TemporaryDirectory(prefix="vibegate-ref-") as ref_td:
                    git.checkout_commit(td, sha, changed, ref_td)
                    ref_target = ScanTarget(root=ref_td, files=changed, version=label)
                    ref_report = _run_on_target(ref_target, None, [], cfg, start, progress_cb=None)
                ref_summaries.append(
                    {
                        "ref": label,
                        "sha": sha[:7],
                        "finding_count": len(ref_report.active_findings),
                        "note": f"{len(changed)} changed file(s)",
                    }
                )
                # Add findings from this branch/PR that weren't already reported at the exact same location
                existing_keys = {(f.rule_id, f.file, f.start_line) for f in all_findings}
                for rf in ref_report.findings:
                    if (rf.rule_id, rf.file, rf.start_line) not in existing_keys:
                        all_findings.append(rf)

            all_findings.sort(key=lambda f: (1 if f.category == "dependency" else 0, -sev_rank(f.severity), f.file, f.start_line))
            report.findings = all_findings
            report.ref_summaries = ref_summaries
            report.scanned_version = f"git:{url}"
            report.policy_blocked, report.block_reasons = evaluate_policy(all_findings, report.scanner_results, cfg)
            report.duration_ms = int((time.monotonic() - start) * 1000)

    if progress_cb:
        progress_cb("cleanup_done", f"Deleted temporary cloned repo ({td_path})")
    return report


def scan_push(
    repo_root: str,
    cfg: Config,
    ref_lines: list[str] | None = None,
    progress_cb: Callable[[str, str], None] | None = None,
) -> ScanReport:
    """Scan the exact commit(s) and file(s) about to be pushed by `git push`."""
    start = time.monotonic()
    pairs: list[tuple[str, str]] = []
    for raw in ref_lines or []:
        parts = raw.strip().split()
        if len(parts) >= 4:
            pairs.append((parts[1], parts[3]))  # (local_sha, remote_sha)

    if not pairs:
        local_sha = git._git(["rev-parse", "HEAD"], cwd=repo_root, check=False).strip()
        remote_sha = git._git(["rev-parse", "@{u}"], cwd=repo_root, check=False).strip() or git.ZERO_SHA
        if local_sha:
            pairs.append((local_sha, remote_sha))

    target_sha = ""
    files_set: set[str] = set()
    for local_sha, remote_sha in pairs:
        changed = git.push_changed_files(repo_root, local_sha, remote_sha)
        if changed:
            target_sha = local_sha
            files_set.update(changed)

    files = sorted(files_set)
    if not files or not target_sha:
        return ScanReport(
            target_root=repo_root,
            scanned_version="push",
            files_scanned=[],
            partially_staged_files=[],
            findings=[],
            scanner_results=[],
            ai_result=AIReviewResult("skipped", [], "no changed files in push"),
            duration_ms=int((time.monotonic() - start) * 1000),
            policy_fail_on=cfg.fail_on,
        )

    with tempfile.TemporaryDirectory(prefix="vibegate-push-") as td:
        git.checkout_commit(repo_root, target_sha, files, td)
        target = ScanTarget(root=td, files=files, version=f"push ({target_sha[:7]})")
        return _run_on_target(target, repo_root, [], cfg, start, progress_cb=progress_cb)

