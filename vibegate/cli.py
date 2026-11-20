"""VibeGate CLI entry point."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys

from rich.console import Console

from vibegate import __version__, git
from vibegate.config import CONFIG_FILE, DEFAULT_TOML, load_config
from vibegate.engine import scan_remote_repo, scan_staged, scan_working_tree
from vibegate.models import SEVERITIES
from vibegate.scanners import ALL_SCANNERS
from vibegate.scanners.semgrep import RULES_PATH
from vibegate.patcher import apply_all_safe_fixes
from vibegate.suppress import SUPPRESS_FILE, load_suppressions
from vibegate.ui import LiveScanDisplay, print_banner, render_summary, run_interactive

HOOK_MARKER = "# vibegate-managed-pre-commit"
HOOK_SCRIPT = f"""#!/usr/bin/env sh
{HOOK_MARKER}
exec vibegate scan --staged "$@"
"""


def _run_scan(args: argparse.Namespace, progress_cb) -> "ScanReport | int":
    target = (args.repo or args.path).strip()
    if git.is_git_url(target):
        cfg = load_config(None)
        if args.fail_on:
            cfg.fail_on = args.fail_on
        if args.no_ai:
            cfg.ai_enabled = False
        if args.deps and "osv-scanner" not in cfg.scanners:
            cfg.scanners.append("osv-scanner")
        try:
            return scan_remote_repo(target, cfg, branch=args.branch, progress_cb=progress_cb), cfg
        except git.GitError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2, cfg

    cwd = os.path.abspath(target)
    if not os.path.exists(cwd):
        print(f"Error: path not found: {cwd}", file=sys.stderr)
        return 2, load_config(None)
    if os.path.isfile(cwd):
        cfg = load_config(os.path.dirname(cwd))
        if args.fail_on:
            cfg.fail_on = args.fail_on
        if args.no_ai:
            cfg.ai_enabled = False
        if args.deps and "osv-scanner" not in cfg.scanners:
            cfg.scanners.append("osv-scanner")
        return scan_working_tree(cwd, cfg, progress_cb=progress_cb), cfg

    repo_root = git.find_repo_root(cwd)
    cfg = load_config(repo_root or cwd)
    if args.fail_on:
        cfg.fail_on = args.fail_on
    if args.no_ai:
        cfg.ai_enabled = False
    if args.deps and "osv-scanner" not in cfg.scanners:
        cfg.scanners.append("osv-scanner")

    if args.all or not repo_root or os.path.realpath(cwd) != os.path.realpath(repo_root):
        return scan_working_tree(cwd, cfg, progress_cb=progress_cb), cfg
    return scan_staged(repo_root, cfg, progress_cb=progress_cb), cfg


def cmd_scan(args: argparse.Namespace) -> int:
    if args.json:
        result, cfg = _run_scan(args, None)
        if isinstance(result, int):
            return result
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(result.to_dict(), fh, indent=2)
                fh.write("\n")
        print(json.dumps(result.to_dict(), indent=2))
        return 1 if result.policy_blocked else 0

    console = Console()
    print_banner(console)
    with LiveScanDisplay(console) as live:
        result, cfg = _run_scan(args, live.update)
    if isinstance(result, int):
        return result

    report = result
    if args.auto_fix and not report.scanned_version.startswith("git:"):
        before_n = len(report.active_findings)
        applied, skipped = apply_all_safe_fixes(
            report.target_root,
            report.active_findings,
            partially_staged_files=report.partially_staged_files,
            restage=True,
        )
        for prop in applied:
            console.print(f"  [green]✓ Auto-fixed[/green] {prop.file}: {prop.description}")
        for msg in skipped:
            console.print(f"  [yellow]• Skipped[/yellow] {msg}")
        console.print(f"[bold]Applied {len(applied)} safe fix(es) (Before: {before_n} risk(s)).[/bold]")
        return 0 if applied else (1 if report.policy_blocked else 0)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report.to_dict(), fh, indent=2)
            fh.write("\n")
        console.print(f"[dim]Saved JSON report to {args.output}[/dim]")
    if args.ci or args.no_tui:
        render_summary(report, console)
        if report.policy_blocked:
            console.print("\n[bold red]BLOCKED:[/bold red] " + "; ".join(report.block_reasons))
        else:
            console.print("\n[bold green]PASS:[/bold green] no policy-blocking findings.")
    else:
        report = run_interactive(report, cfg, console)
        if report.policy_blocked:
            console.print("\n[bold red]COMMIT BLOCKED:[/bold red] " + "; ".join(report.block_reasons))
        else:
            console.print("\n[bold green]GATE PASSED.[/bold green]")

    return 1 if report.policy_blocked else 0


def cmd_hook(args: argparse.Namespace) -> int:
    root = git.find_repo_root(".")
    if not root:
        print("Error: not inside a Git repository.", file=sys.stderr)
        return 2
    hook_path = os.path.join(git.hooks_dir(root), "pre-commit")
    if args.hook_action == "install":
        if os.path.exists(hook_path) and not args.force:
            with open(hook_path, encoding="utf-8", errors="replace") as fh:
                if HOOK_MARKER not in fh.read():
                    print(f"Error: {hook_path} already exists. Re-run with --force to overwrite.", file=sys.stderr)
                    return 2
        os.makedirs(os.path.dirname(hook_path), exist_ok=True)
        with open(hook_path, "w", encoding="utf-8") as fh:
            fh.write(HOOK_SCRIPT)
        os.chmod(hook_path, os.stat(hook_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"Installed VibeGate pre-commit hook at {hook_path}")
        return 0
    if args.hook_action == "uninstall":
        if not os.path.exists(hook_path):
            print("No pre-commit hook found.")
            return 0
        with open(hook_path, encoding="utf-8", errors="replace") as fh:
            if HOOK_MARKER not in fh.read():
                print(f"Error: {hook_path} was not installed by VibeGate; leaving it untouched.", file=sys.stderr)
                return 2
        os.remove(hook_path)
        print(f"Removed VibeGate pre-commit hook at {hook_path}")
        return 0
    return 2


def cmd_init(args: argparse.Namespace) -> int:
    root = git.find_repo_root(".") or os.getcwd()
    path = os.path.join(root, CONFIG_FILE)
    if os.path.exists(path) and not args.force:
        print(f"{path} already exists (leaving existing config).")
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(DEFAULT_TOML)
        print(f"Wrote {path}")

    if git.find_repo_root(root):
        return cmd_hook(argparse.Namespace(hook_action="install", force=args.force))
    return 0


def cmd_doctor(_args: argparse.Namespace) -> int:
    console = Console()
    console.print(f"[bold]VibeGate {__version__} environment check[/bold]")
    git_path = shutil.which("git")
    console.print(f"  git: {'[green]' + git_path + '[/green]' if git_path else '[red]missing[/red]'}")
    for name, cls in ALL_SCANNERS.items():
        sc = cls()
        if sc.available():
            console.print(f"  {name}: [green]{sc.version() or 'installed'}[/green]")
        else:
            console.print(f"  {name}: [yellow]not installed[/yellow] ({sc.install_hint})")
    has_key = bool(os.environ.get("GEMINI_API_KEY", "").strip())
    console.print(f"  GEMINI_API_KEY: {'[green]set[/green]' if has_key else '[yellow]not set (AI review will be skipped)[/yellow]'}")
    return 0


def cmd_rules(_args: argparse.Namespace) -> int:
    """List built-in cybersecurity detection rules."""
    import re
    from rich.table import Table

    console = Console()
    with open(RULES_PATH, encoding="utf-8") as fh:
        raw = fh.read()

    # Parse rule blocks cleanly without requiring PyYAML as a runtime dependency
    blocks = re.split(r"(?m)^\s*-\s+id:\s*", raw)[1:]
    table = Table(title=f"Built-in Semgrep Rules ({len(blocks)})", header_style="bold")
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("CWE", overflow="fold")
    table.add_column("Title", overflow="fold")

    for b in blocks:
        lines = b.splitlines()
        rid = lines[0].strip()
        sev = re.search(r"vibegate_severity:\s*(\S+)", b)
        cat = re.search(r"vibegate_category:\s*(\S+)", b)
        cwe = re.search(r'cwe:\s*"?([^"\n]+)"?', b)
        title = re.search(r"title:\s*(.+)", b)
        table.add_row(
            rid,
            (sev.group(1) if sev else "medium").upper(),
            cat.group(1) if cat else "other",
            cwe.group(1).strip() if cwe else "-",
            title.group(1).strip() if title else rid,
        )
    console.print(table)
    return 0


def cmd_suppressions(args: argparse.Namespace) -> int:
    """Inspect or clear repository suppressions in .vibegate-ignore.json."""
    from rich.table import Table

    root = git.find_repo_root(".") or os.getcwd()
    path = os.path.join(root, SUPPRESS_FILE)
    if args.sup_action == "clear":
        if os.path.exists(path):
            os.remove(path)
            print(f"Removed {path}")
        else:
            print("No suppression file found.")
        return 0

    sups = load_suppressions(root)
    if not sups:
        print(f"No active suppressions in {root}.")
        return 0
    console = Console()
    table = Table(title=f"Suppressions ({SUPPRESS_FILE})", header_style="bold")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Location")
    table.add_column("Reason")
    table.add_column("Added By")
    table.add_column("Added At")
    for s in sups:
        loc = f"{s.file}:{s.line}" if s.line else s.file
        table.add_row(s.rule_id, loc, s.reason, s.added_by, s.added_at)
    console.print(table)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vibegate", description="Local-first security gate for AI-generated code.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a Git repo URL, local directory, or staged changes")
    scan.add_argument("path", nargs="?", default=".", help="Local path or Git repository URL (default: .)")
    scan.add_argument("--repo", help="Git repository URL to clone and scan")
    scan.add_argument("--branch", help="Branch or tag to clone when scanning --repo / a Git URL")
    scan.add_argument("--staged", action="store_true", help="Scan staged changes only (default inside local Git repos)")
    scan.add_argument("--all", action="store_true", help="Scan all tracked/unignored files in the working tree")
    scan.add_argument("--ci", action="store_true", help="Non-interactive mode for CI")
    scan.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
    scan.add_argument("--no-tui", action="store_true", help="Print summary without interactive prompt")
    scan.add_argument("--no-ai", action="store_true", help="Disable AI-assisted authorization review")
    scan.add_argument("--deps", action="store_true", help="Also scan dependency manifests/lockfiles with OSV-Scanner")
    scan.add_argument("--auto-fix", action="store_true", help="Apply all available safe fixes and re-stage")
    scan.add_argument("--output", "-o", help="Save JSON scan report to a file")
    scan.add_argument("--fail-on", choices=SEVERITIES, help="Override blocking severity threshold")
    scan.set_defaults(func=cmd_scan)

    hook = sub.add_parser("hook", help="Manage Git pre-commit hook")
    hook.add_argument("hook_action", choices=["install", "uninstall"])
    hook.add_argument("--force", action="store_true", help="Overwrite an existing non-VibeGate pre-commit hook")
    hook.set_defaults(func=cmd_hook)

    init = sub.add_parser("init", help="Create a default .vibegate.toml config")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)

    doc = sub.add_parser("doctor", help="Check installed scanners and environment")
    doc.set_defaults(func=cmd_doctor)

    rules = sub.add_parser("rules", help="List built-in cybersecurity detection rules")
    rules.set_defaults(func=cmd_rules)

    sups = sub.add_parser("suppressions", help="List or clear .vibegate-ignore.json suppressions")
    sups.add_argument("sup_action", nargs="?", choices=["list", "clear"], default="list")
    sups.set_defaults(func=cmd_suppressions)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)

