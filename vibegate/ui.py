"""Rich terminal UI and interactive review/patch/suppression loop."""

from __future__ import annotations

import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from vibegate import git
from vibegate.config import Config
from vibegate.engine import ScanReport, evaluate_policy
from vibegate.models import Finding
from vibegate.patcher import (
    apply_patch,
    propose_patch,
    run_authorized_tests,
    stage_patched_file,
    verify_finding_recheck,
)
from vibegate.suppress import save_suppression

SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _open_tty_input():
    """Inside a git pre-commit hook stdin is often /dev/null; try /dev/tty if available."""
    if sys.stdin.isatty():
        return sys.stdin
    try:
        return open("/dev/tty", "r", encoding="utf-8", errors="replace")
    except OSError:
        return None


def render_summary(report: ScanReport, console: Console) -> None:
    console.print()
    header = Text()
    header.append("VibeGate ", style="bold magenta")
    header.append(f"scanned {len(report.files_scanned)} file(s) ", style="bold")
    header.append(f"({report.scanned_version} version) ", style="cyan")
    header.append(f"in {report.duration_ms / 1000:.2f}s", style="dim")
    console.print(Panel(header, expand=False, border_style="magenta"))

    if report.partially_staged_files:
        console.print(
            "[yellow]Notice:[/yellow] Partially staged file(s) detected: "
            + ", ".join(report.partially_staged_files)
            + ". VibeGate scanned the [bold]staged[/bold] version only and will not auto-rewrite or auto-stage them."
        )

    # Scanner & AI status line
    parts = []
    for sr in report.scanner_results:
        color = "green" if sr.status == "ok" else ("dim" if sr.status == "skipped" else "yellow")
        parts.append(f"[{color}]{sr.name}: {sr.status}[/{color}] ({sr.duration_ms}ms)")
    ai = report.ai_result
    ai_color = "green" if ai.status == "ok" else ("dim" if ai.status == "skipped" else "yellow")
    parts.append(f"[{ai_color}]ai-review: {ai.status}[/{ai_color}]")
    console.print("Scanners: " + " | ".join(parts))
    for sr in report.scanner_results:
        if sr.status in ("error", "timeout", "not_installed") and sr.message:
            console.print(f"[yellow]{sr.name} note:[/yellow] {sr.message.splitlines()[-1]}")
    if ai.status not in ("ok", "skipped") and ai.message:
        console.print(f"[yellow]AI review note:[/yellow] {ai.message}")

    if not report.findings:
        console.print("[green]No findings reported.[/green]")
        return

    table = Table(title="Findings", show_lines=False, header_style="bold", expand=True)
    table.add_column("#", style="dim", no_wrap=True, width=3)
    table.add_column("Severity", no_wrap=True, width=8)
    table.add_column("Source", no_wrap=True, width=12)
    table.add_column("Location", style="cyan", overflow="fold", max_width=24)
    table.add_column("Title", overflow="ellipsis", min_width=24, no_wrap=True)
    table.add_column("Status", no_wrap=True, width=14)

    for idx, f in enumerate(report.findings, 1):
        sev = Text(f.severity.upper(), style=SEV_STYLE.get(f.severity, ""))
        status = f.verification_status
        if f.suppressed:
            status = "suppressed"
        elif f.dismissed:
            status = "dismissed"
        row_style = "dim" if (f.suppressed or f.dismissed) else ""
        table.add_row(str(idx), sev, f.source_label, f.location, f.title, status, style=row_style)

    console.print(table)
    if report.suppressed_findings:
        console.print(f"[dim]{len(report.suppressed_findings)} finding(s) suppressed or dismissed (still listed above for visibility).[/dim]")


def _show_finding_detail(finding: Finding, console: Console) -> None:
    lines = [
        f"[bold]ID:[/bold] {finding.id}   [bold]Rule:[/bold] {finding.rule_id}   [bold]Category:[/bold] {finding.category}",
        f"[bold]Source:[/bold] {finding.source_label}   [bold]Severity:[/bold] {finding.severity}   [bold]Confidence:[/bold] {finding.confidence}",
        f"[bold]Location:[/bold] {finding.location} (scanned: {finding.scanned_version})",
        f"[bold]Verification:[/bold] {finding.verification_status}",
    ]
    if finding.verification_note:
        lines.append(f"[bold]Note:[/bold] {finding.verification_note}")
    if finding.suppressed:
        lines.append(f"[yellow]Suppressed:[/yellow] {finding.suppression_reason}")
    if finding.dismissed:
        lines.append(f"[yellow]Dismissed:[/yellow] {finding.dismiss_note}")
    lines.append("")
    lines.append(f"[bold]Evidence:[/bold]\n{finding.evidence or '(none)'}")
    lines.append("")
    lines.append(f"[bold]Explanation:[/bold]\n{finding.explanation}")
    lines.append("")
    lines.append(f"[bold]Suggested remediation:[/bold]\n{finding.remediation}")
    console.print(Panel("\n".join(lines), title=finding.title, border_style=SEV_STYLE.get(finding.severity, "white")))


def _handle_patch(finding: Finding, report: ScanReport, cfg: Config, console: Console, tty) -> None:
    root = report.target_root
    if finding.file in report.partially_staged_files:
        console.print(
            f"[yellow]Blocked auto-patch:[/yellow] {finding.file} is partially staged (index differs from working tree). "
            "Resolve or stage your working changes explicitly before patching."
        )
        return
    proposal = propose_patch(root, finding)
    if not proposal:
        console.print("[yellow]No automatic patch template is available for this rule.[/yellow] Apply the remediation manually.")
        return

    console.print(f"\n[bold]Proposed patch:[/bold] {proposal.description}")
    console.print(Syntax(proposal.diff, "diff", theme="monokai", line_numbers=False))
    if not Confirm.ask("Apply this patch to the working tree?", default=False, console=console, stream=tty):
        console.print("Patch not applied.")
        return

    apply_patch(root, proposal)
    console.print(f"[green]Applied patch to {proposal.file}.[/green]")

    status, note = verify_finding_recheck(root, finding, timeout=cfg.scanner_timeout)
    console.print(f"[bold]Rescan result ({status}):[/bold] {note}")

    if cfg.test_command and Confirm.ask(f"Run configured test command `{cfg.test_command}`?", default=False, console=console, stream=tty):
        ok, out = run_authorized_tests(root, cfg.test_command, finding)
        console.print(f"[{'green' if ok else 'red'}]Tests {'passed' if ok else 'failed'}.[/]")
        if out:
            console.print(out)

    if git.find_repo_root(root) and Confirm.ask(f"Stage {proposal.file} now (`git add {proposal.file}`)?", default=False, console=console, stream=tty):
        stage_patched_file(root, proposal.file)
        console.print(f"[green]Staged {proposal.file}.[/green]")


def run_interactive(report: ScanReport, cfg: Config, console: Console) -> ScanReport:
    render_summary(report, console)
    if not report.findings:
        return report

    tty = _open_tty_input()
    if tty is None:
        return report

    try:
        while True:
            console.print("\nActions: [bold]<number>[/bold] inspect finding, [bold]r[/bold] refresh summary, [bold]q[/bold] finish")
            choice = Prompt.ask("vibegate", default="q", console=console, stream=tty).strip().lower()
            if choice in ("q", "quit", "exit", ""):
                break
            if choice == "r":
                render_summary(report, console)
                continue
            if not choice.isdigit() or not (1 <= int(choice) <= len(report.findings)):
                console.print("[red]Invalid selection.[/red]")
                continue

            finding = report.findings[int(choice) - 1]
            _show_finding_detail(finding, console)

            while True:
                action = Prompt.ask(
                    "Finding action: [p]atch, [s]uppress (.vibegate-ignore.json), [d]ismiss for this run, [b]ack",
                    choices=["p", "s", "d", "b"],
                    default="b",
                    console=console,
                    stream=tty,
                )
                if action == "b":
                    break
                if action == "p":
                    _handle_patch(finding, report, cfg, console, tty)
                elif action == "d":
                    note = Prompt.ask("Reason for dismissing this run", default="reviewed", console=console, stream=tty)
                    finding.dismissed = True
                    finding.dismiss_note = note
                    console.print("[yellow]Dismissed for this run.[/yellow]")
                    break
                elif action == "s":
                    if not git.find_repo_root(report.target_root) and not os.path.isdir(report.target_root):
                        console.print("[red]Cannot write suppression file outside a workspace.[/red]")
                        continue
                    reason = Prompt.ask("Justification for suppression (recorded in .vibegate-ignore.json)", console=console, stream=tty)
                    sup = save_suppression(report.target_root, finding, reason, git.user_identity(report.target_root))
                    finding.suppressed = True
                    finding.suppression_reason = sup.reason
                    console.print(f"[yellow]Saved narrow suppression for {sup.rule_id} at {sup.file}:{sup.line or '*'}.[/yellow]")
                    break
    finally:
        if tty is not sys.stdin:
            tty.close()

    # Re-evaluate policy after developer actions (dismiss/suppress/patch recheck)
    # Note: if a deterministic finding no longer reproduces after patch, don't block on it.
    effective = [f for f in report.findings if f.verification_status != "no_longer_reproduces"]
    blocked, reasons = evaluate_policy(effective, report.scanner_results, cfg)
    report.policy_blocked = blocked
    report.block_reasons = reasons
    return report

