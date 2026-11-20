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
from vibegate.engine import scan_staged, scan_working_tree
from vibegate.models import SEVERITIES
from vibegate.scanners import ALL_SCANNERS
from vibegate.ui import render_summary, run_interactive

HOOK_MARKER = "# vibegate-managed-pre-commit"
HOOK_SCRIPT = f"""#!/usr/bin/env sh
{HOOK_MARKER}
exec vibegate scan --staged "$@"
"""


def cmd_scan(args: argparse.Namespace) -> int:
    cwd = os.path.abspath(args.path)
    repo_root = git.find_repo_root(cwd)
    cfg = load_config(repo_root or cwd)
    if args.fail_on:
        cfg.fail_on = args.fail_on
    if args.no_ai:
        cfg.ai_enabled = False

    if args.all or not repo_root:
        report = scan_working_tree(cwd, cfg)
    else:
        report = scan_staged(repo_root, cfg)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    elif args.ci or args.no_tui:
        console = Console(stderr=False)
        render_summary(report, console)
        if report.policy_blocked:
            console.print("\n[bold red]BLOCKED:[/bold red] " + "; ".join(report.block_reasons))
        else:
            console.print("\n[bold green]PASS:[/bold green] no policy-blocking findings.")
    else:
        console = Console()
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
        print(f"{path} already exists (use --force to overwrite).", file=sys.stderr)
        return 2
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(DEFAULT_TOML)
    print(f"Wrote {path}")
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vibegate", description="Local-first security gate for AI-generated code.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan staged changes (default) or working tree")
    scan.add_argument("path", nargs="?", default=".", help="Repository or directory path (default: .)")
    scan.add_argument("--staged", action="store_true", help="Scan staged changes only (default inside Git repos)")
    scan.add_argument("--all", action="store_true", help="Scan all tracked/unignored files in the working tree")
    scan.add_argument("--ci", action="store_true", help="Non-interactive mode for CI")
    scan.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
    scan.add_argument("--no-tui", action="store_true", help="Print summary without interactive prompt")
    scan.add_argument("--no-ai", action="store_true", help="Disable AI-assisted authorization review")
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
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)

