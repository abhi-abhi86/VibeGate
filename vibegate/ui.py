"""Rich terminal UI and interactive review/patch/suppression loop."""

from __future__ import annotations

import os
import sys
import threading

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.spinner import Spinner
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from vibegate import git
from vibegate.config import Config
from vibegate.engine import ScanReport, evaluate_policy
from vibegate.models import Finding, sev_rank
from vibegate.patcher import (
    apply_all_safe_fixes,
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

STATUS_LABELS = {
    "detected": "detected",
    "not_rechecked": "detected",
    "ai_candidate": "ai candidate",
    "ai_candidate_unverified": "ai candidate",
    "no_longer_reproduces": "fixed (rescan ok)",
    "still_reproduces": "still triggers",
    "patched_tests_passed": "patched (tests ok)",
    "patched_tests_failed": "patched (tests fail)",
}

BANNER_LINES = [
    (r" __     ___ _           ____       _       ", "bold bright_cyan"),
    (r" \ \   / (_) |__   ___ / ___| __ _| |_ ___ ", "bold cyan"),
    (r"  \ \ / /| | '_ \ / _ \ |  _ / _` | __/ _ \ ", "bold bright_blue"),
    (r"   \ V / | | |_) |  __/ |_| | (_| | ||  __/", "bold magenta"),
    (r"    \_/  |_|_.__/ \___|\____|\__,_|\__\___|", "bold bright_magenta"),
]

BANNER = "\n".join(f"[{style}]{line}[/{style}]" for line, style in BANNER_LINES) + (
    "\n[dim]  Pre-Commit & Repo Security Gate  •  SAST + Secrets + SCA + 2-Layer AI[/dim]"
    "\n[bold cyan]  by team Z-ZONE[/bold cyan]"
)


def vulnerability_type(finding: Finding) -> str:
    """Classify the concrete vulnerability type strictly from the observed rule/category/title."""
    rid = finding.rule_id.lower()
    title = finding.title.lower()
    text = f"{rid} {title}"
    cat = finding.category

    if cat == "dependency":
        return "Vulnerable Dependency (Known CVE)"
    if "sql" in text or "rawsql" in text or "raw-sql" in text:
        return "SQL Injection (SQLi)"
    if any(k in text for k in ("ssti", "render_template_string")):
        return "Server-Side Template Injection (SSTI)"
    if any(k in text for k in ("xss", "cross-site scripting", "innerhtml", "document.write")):
        return "Cross-Site Scripting (XSS)"
    if any(k in text for k in ("subprocess", "os-system", "command", "pickle", "yaml", "deserializ", "eval", "exec")):
        return "Command / Code Injection (RCE)"
    if "traversal" in text:
        return "Path Traversal / Arbitrary File Read"
    if "ssrf" in text:
        return "Server-Side Request Forgery (SSRF)"
    if cat == "secret" or any(k in text for k in ("exposed-secret", "dotenv", "hardcoded-flask-secret")):
        return "Exposed Secret / Credential Leak"
    if "csrf" in text:
        return "Cross-Site Request Forgery (CSRF)"
    if "missing-xfo" in rid or "clickjacking" in text:
        return "Clickjacking (UI Redressing)"
    if "cors" in text:
        return "Cross-Origin Data Exposure (CORS Misconfiguration)"
    if "cookie" in text:
        return "Session Cookie Misconfiguration"
    if any(k in text for k in ("tls", "no-https", "hsts", "mixed-content")):
        return "Transport Security / Man-in-the-Middle (MitM) Risk"
    if any(k in text for k in ("weak-hash", "md5", "sha1")):
        return "Weak Cryptography / Password Hashing"
    if any(k in text for k in ("debug", "version-disclosure", "git-dir")):
        return "Sensitive Information / Debug Disclosure"
    if cat == "access_control" or any(k in text for k in ("idor", "auth", "login")):
        return "Broken Access Control / IDOR"
    if cat == "bug":
        return "Code Logic / Reliability Bug"
    return "Security Misconfiguration"


def threat_impact(finding: Finding) -> str:
    """Return a plain-English explanation of what will happen if this observed vulnerability is not fixed."""
    if finding.extra.get("impact"):
        return str(finding.extra["impact"])
    rid = finding.rule_id.lower()
    cat = finding.category
    if rid in ("web.exposure.dotenv", "web.body.password-over-http"):
        return "If not fixed, attackers can steal database passwords, API keys, or user login credentials in cleartext."
    if rid in ("web.exposure.git-dir", "web.exposure.ds-store", "web.exposure.phpinfo", "web.exposure.openapi"):
        return "If not fixed, attackers can map hidden files/endpoints, read environment details, or reconstruct source code."
    if rid in ("web.body.exposed-secret", "web.bundle.exposed-secret"):
        return "If not fixed, any visitor can extract this key from page source or JS bundles and abuse your API quota or backend data."
    if rid in ("web.http.no-https", "web.header.missing-hsts", "web.body.mixed-content") or "tls" in rid:
        return "If not fixed, attackers on the same network can intercept or tamper with traffic via a Man-in-the-Middle (MitM) attack."
    if rid in ("web.header.missing-csp", "web.header.weak-csp"):
        return "If not fixed, any XSS bug on the page can load external attacker scripts and exfiltrate user data."
    if rid == "web.header.missing-xfo":
        return "If not fixed, attackers can embed your site in a hidden iframe (Clickjacking) to trick users into unintended actions."
    if rid == "web.cookie.missing-flags":
        return "If not fixed, session cookies may be stolen via XSS (missing HttpOnly), leaked over HTTP (missing Secure), or abused via CSRF (missing SameSite)."
    if rid == "web.cors.wildcard":
        return "If not fixed, untrusted third-party websites can read responses from this endpoint inside a user's browser."
    if rid == "web.body.form-no-csrf":
        return "If not fixed, external sites can forge POST requests using a logged-in user's browser session (CSRF)."
    if rid in ("web.body.debug-leak", "web.header.version-disclosure"):
        return "If not fixed, attackers gain internal stack traces or exact software versions to target known CVEs."
    if cat == "secret":
        return (
            "Anyone with access to the repo or Git history can extract this credential to "
            "impersonate your service, access private data, or run up unauthorized API/cloud charges."
        )
    if "sql" in rid:
        return (
            "An attacker can manipulate the SQL query through user input to bypass login, "
            "exfiltrate sensitive database tables, or alter/delete records."
        )
    if any(k in rid for k in ("subprocess", "os-system", "exec", "eval", "ssti", "pickle", "yaml")):
        return (
            "An attacker can execute arbitrary OS commands or Python/JS code on your server "
            "(Remote Code Execution), leading to full system compromise."
        )
    if "xss" in rid:
        return (
            "An attacker can inject malicious JavaScript into victims' browsers to hijack "
            "sessions, steal cookies/tokens, or act on behalf of logged-in users."
        )
    if "ssrf" in rid:
        return (
            "An attacker can force your server to send requests to internal services, "
            "private networks, or cloud metadata endpoints to steal credentials."
        )
    if "path-traversal" in rid:
        return (
            "An attacker can use `../` sequences to read or overwrite arbitrary server files "
            "(such as `.env`, source code, or system credentials)."
        )
    if cat == "access_control":
        return (
            "A user can view, modify, or delete another user's private data without permission "
            "(Broken Access Control / IDOR)."
        )
    if "tls" in rid:
        return (
            "Disabling certificate checks allows a network attacker to intercept or tamper "
            "with sensitive traffic via a Man-in-the-Middle (MitM) attack."
        )
    if "weak-hash" in rid:
        return (
            "Attackers can crack weak MD5/SHA-1 hashes or forge collisions to compromise "
            "passwords or integrity checks."
        )
    if cat == "dependency":
        aliases = ", ".join((finding.extra.get("aliases") or [])[:3])
        ref = f"{finding.rule_id}" + (f" ({aliases})" if aliases else "")
        return (
            f"OSV advisory {ref} affects this package version. Actual impact depends on "
            "whether your code reaches the vulnerable function/path."
        )
    if "bare-except" in rid:
        return "Bare `except:` silently swallows unexpected errors, KeyboardInterrupt, and SystemExit, hiding crashes and security failures."
    if "mutable-default" in rid:
        return "Shared mutable default arguments (`[]`/`{}`) leak state between function calls or user requests, causing data corruption."
    if "is-literal" in rid:
        return "Using `is` instead of `==` compares memory identity rather than value, causing unpredictable logic branches."
    if "nan-equality" in rid:
        return "Comparing against `NaN` with `==`/`===` always evaluates to false, silently bypassing numeric validation."
    if "assignment-in-condition" in rid:
        return "Using `=` instead of `===` inside an `if` condition overwrites the variable and can bypass conditional checks."
    if "flask-debug" in rid:
        return "Flask debug mode exposes the Werkzeug interactive debugger, allowing remote code execution if reachable."
    if "hardcoded-flask-secret" in rid:
        return "Anyone who reads the source code can forge valid Flask session cookies and impersonate any user."
    if cat == "bug":
        return f"Code bug ({finding.rule_id}): can cause silent data corruption, logic bypasses, or unexpected runtime failures."
    return f"Security weakness ({finding.rule_id}): {finding.explanation}"


def access_example(finding: Finding) -> str:
    """Return a concise example of how the vulnerability can be accessed or exploited."""
    if finding.extra.get("access_example"):
        return str(finding.extra["access_example"]).strip()

    rid = finding.rule_id.lower()
    title = finding.title.lower()
    text = f"{rid} {title}"
    cat = finding.category

    if cat == "secret" or any(k in text for k in ("secret", "token", "api_key", "private_key", "hardcoded")):
        return "Read exposed credential directly from source or git history"
    if any(k in text for k in ("sql", "rawsql", "extra")):
        return "Input like: ' OR '1'='1' -- (bypasses query / dumps rows)"
    if any(k in text for k in ("ssti", "render_template_string")):
        return "Payload like: {{7*7}} or {{config.items()}} in template input"
    if any(k in text for k in ("xss", "cross-site scripting", "innerhtml", "document.write", "html")):
        return "Payload like: ?q=<script>alert(1)</script> in reflected input"
    if any(k in text for k in ("command", "shell", "subprocess", "os.system", "eval", "exec")):
        return "Payload like: ; id && whoami in command/eval input"
    if any(k in text for k in ("path traversal", "traversal", "send_file")):
        return "Param like: ?file=../../etc/passwd"
    if any(k in text for k in ("ssrf", "requests", "urllib")):
        return "URL like: http://169.254.169.254/latest/meta-data/"
    if any(k in text for k in ("md5", "sha1", "weak password", "weak hash", "crypto")):
        return "Crack leaked hash offline via rainbow table / hashcat"
    if any(k in text for k in ("pickle", "yaml", "deserializ", "unserialize")):
        return "Send crafted serialized payload to trigger remote code execution"
    if cat == "access_control" or any(k in text for k in ("idor", "auth", "login", "csrf", "ownership")):
        return "Call endpoint directly or swap ID (e.g. ?id=2) without auth"
    if any(k in text for k in ("debug", "allowed_hosts", "cors")):
        return "Trigger error page or cross-origin request to read internals"
    return f"Send untrusted input reaching {finding.location}"


def print_banner(console: Console) -> None:
    logo = Text()
    for line, style in BANNER_LINES:
        logo.append(line + "\n", style=style)
    tagline = Text.assemble(
        ("⚡ ", "bold yellow"),
        ("Pre-Commit & Repo Security Gate", "bold white"),
        ("  •  ", "dim"),
        ("SAST · Secrets · SCA · 2-Layer AI", "cyan"),
        ("\n", ""),
        ("   by team Z-ZONE", "bold magenta"),
    )
    console.print(
        Panel(
            Group(logo, tagline),
            box=box.ROUNDED,
            border_style="bright_cyan",
            padding=(0, 2),
            expand=False,
        )
    )


class LiveScanDisplay:
    """Real-time TUI progress panel during cloning, scanning, AI review, and cleanup."""

    def __init__(self, console: Console) -> None:
        self.console = console
        self.phase = "Preparing scan..."
        self.steps: list[tuple[str, str]] = []  # (status_icon, message)
        self._lock = threading.Lock()
        self._live: Live | None = None

    def __enter__(self) -> "LiveScanDisplay":
        if self.console.is_terminal:
            self._live = Live(self._render(), console=self.console, refresh_per_second=10, transient=True)
            self._live.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._live is not None:
            self._live.__exit__(exc_type, exc, tb)
        # Print a concise final progress summary so the steps remain visible above the report
        for icon, msg in self.steps:
            self.console.print(f"  {icon} {msg}")

    def update(self, event: str, msg: str) -> None:
        with self._lock:
            if event in ("clone_start", "scanners_start", "ai_start"):
                self.phase = msg
                self.steps.append(("[cyan]•[/cyan]", msg))
            elif event in ("clone_done", "scanner_done", "ai_done", "cleanup_done"):
                self.steps.append(("[green]✓[/green]", msg))
            else:
                self.steps.append(("[dim]•[/dim]", msg))
            if self._live is not None:
                self._live.update(self._render())

    def _render(self) -> Panel:
        spinner = Spinner("dots", text=Text(f" {self.phase}", style="bold cyan"))
        lines = [spinner]
        for icon, msg in self.steps[-8:]:
            lines.append(Text.from_markup(f"  {icon} {msg}"))
        return Panel(Group(*lines), title="VibeGate Live Scan", border_style="magenta", expand=False)


def _open_tty_input():
    """Inside a git pre-commit hook stdin is often /dev/null; try /dev/tty if available."""
    if sys.stdin.isatty():
        return sys.stdin
    try:
        return open("/dev/tty", "r", encoding="utf-8", errors="replace")
    except OSError:
        return None


def _status_text(f: Finding) -> str:
    if f.suppressed:
        return "suppressed"
    if f.dismissed:
        return "dismissed"
    return STATUS_LABELS.get(f.verification_status, f.verification_status)


def _render_detail_panel(idx: int, f: Finding, report: ScanReport, console: Console) -> None:
    sev_style = SEV_STYLE.get(f.severity, "white")
    is_temp = "/var/folders/" in report.target_root or report.target_root.startswith("/tmp/")
    if report.scanned_version.startswith("git:") or is_temp or not os.path.isdir(report.target_root):
        full_path = f"{f.scanned_version} -> {f.file}"
    else:
        full_path = os.path.join(report.target_root, f.file)
    line_info = f"Line {f.start_line}" if f.start_line else "File-level"
    if f.end_line and f.end_line != f.start_line:
        line_info = f"Lines {f.start_line}-{f.end_line}"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", width=10, no_wrap=True)
    grid.add_column()
    grid.add_row("File", f"[cyan]{f.location}[/cyan] ({line_info})   [dim]Rule: {f.rule_id} · {f.source_label}[/dim]")
    grid.add_row("Type", Text(vulnerability_type(f), style="bold yellow"))
    grid.add_row("Path", Text(full_path, style="dim"))
    grid.add_row("Code", Text(_pinpoint_code(report.target_root, f)))
    grid.add_row("Issue", Text(f.explanation))
    grid.add_row("If Unfixed", Text(threat_impact(f), style="red"))
    grid.add_row("Access", Text(access_example(f), style="yellow"))
    grid.add_row("Fix", Text(f.remediation, style="green"))

    console.print(
        Panel(
            grid,
            title=Text(f"#{idx} [{f.severity.upper()}] {f.title}"),
            border_style=sev_style,
            box=box.ROUNDED,
            expand=False,
        )
    )


CONSENSUS_BADGES = {
    "2/2_safe": "[bold green][AI Consensus: 2/2 Safe][/bold green]",
    "2/2_vulnerable": "[bold red][AI Consensus: 2/2 Vulnerable][/bold red]",
    "debate_resolved": "[bold yellow][AI Consensus: Debate Resolved][/bold yellow]",
    "single_fallback": "[yellow][AI: Single Fallback][/yellow]",
    "single": "[dim][AI: Single Model][/dim]",
}


def render_markdown_report(report: ScanReport) -> str:
    """Render a shareable Markdown security report (suitable for PRs or post-deploy audits)."""
    active = report.active_findings
    status_line = "BLOCKED" if report.policy_blocked else "PASS"
    lines = [
        "# VibeGate Security Report",
        "",
        f"- **Target:** `{report.target_root}` (`{report.scanned_version}`)",
        f"- **Scorecard:** **{len(active)} active risk(s)** — **{status_line}** (threshold: `{report.policy_fail_on}`)",
        f"- **Duration:** {report.duration_ms / 1000:.2f}s",
    ]
    if report.detected_stacks:
        lines.append(f"- **Detected Stack:** {', '.join(report.detected_stacks)}")
    lines.append("")

    if not active:
        lines.append("No active vulnerabilities or security risks were detected.")
        return "\n".join(lines) + "\n"

    lines.extend([
        "## Findings Summary",
        "",
        "| # | Severity | Type | Location | Title | How to Access / Example |",
        "|---:|---|---|---|---|---|",
    ])
    for idx, f in enumerate(active, 1):
        vtype = vulnerability_type(f).replace("|", "\\|")
        loc = f.location.replace("|", "\\|")
        title = f.title.replace("|", "\\|")
        ex = access_example(f).replace("|", "\\|")
        lines.append(f"| {idx} | {f.severity.upper()} | {vtype} | `{loc}` | {title} | `{ex}` |")

    lines.extend(["", "## Detailed Findings & Fixes", ""])
    for idx, f in enumerate(active, 1):
        lines.extend([
            f"### {idx}. [{f.severity.upper()}] {f.title}",
            f"- **Location:** `{f.location}` (`{f.rule_id}` via {f.source_label})",
            f"- **Type:** {vulnerability_type(f)}",
            f"- **Issue:** {f.explanation}",
            f"- **If Unfixed:** {threat_impact(f)}",
            f"- **How to Access / Example:** `{access_example(f)}`",
            f"- **Fix:** {f.remediation}",
            "",
        ])
    return "\n".join(lines)


def render_summary(report: ScanReport, console: Console, sev_filter: str | None = None, show_reasoning: bool = False) -> None:
    console.print()
    active_count = len(report.active_findings)
    crit_high = sum(1 for f in report.active_findings if f.severity in ("critical", "high"))
    web_failed = report.scanned_version.startswith("web:") and any(
        sr.name == "web-audit" and sr.status == "error" for sr in report.scanner_results
    )
    if web_failed:
        score_text = "[bold red]UNREACHABLE — AUDIT FAILED[/bold red]"
        border = "red"
    elif report.policy_blocked:
        score_text = f"[bold red]{active_count} Risk(s) ({crit_high} Critical/High) — BLOCKED[/bold red]"
        border = "red"
    elif active_count > 0:
        score_text = f"[yellow]{active_count} Non-blocking Risk(s) — PASS[/yellow]"
        border = "yellow"
    else:
        score_text = "[bold green]0 Risks — SAFE TO SHIP[/bold green]"
        border = "green"

    parts = []
    for sr in report.scanner_results:
        color = "green" if sr.status == "ok" else ("dim" if sr.status == "skipped" else "yellow")
        parts.append(f"[{color}]{sr.name}: {sr.status}[/{color}] ({sr.duration_ms}ms)")
    ai = report.ai_result
    ai_color = "green" if ai.status == "ok" else ("dim" if ai.status == "skipped" else "yellow")
    parts.append(f"[{ai_color}]ai-review: {ai.status}[/{ai_color}]")

    summary_grid = Table.grid(padding=(0, 2))
    summary_grid.add_column(style="bold", width=11, no_wrap=True)
    summary_grid.add_column()
    if report.scanned_version.startswith("web:"):
        target_label = f"live domain ({report.scanned_version[4:]})"
    elif report.scanned_version.startswith("file:"):
        target_label = f"1 file ({os.path.basename(report.scanned_version[5:])})"
    else:
        target_label = f"{len(report.files_scanned)} {report.scanned_version} file(s)"
    summary_grid.add_row(
        "Target",
        f"{target_label} scanned in [bold cyan]{report.duration_ms / 1000:.2f}s[/bold cyan]",
    )
    if report.detected_stacks:
        from vibegate.detect import STACK_LABELS
        stack_str = ", ".join(STACK_LABELS.get(s, s) for s in report.detected_stacks)
        summary_grid.add_row("Stack", f"[cyan]{stack_str}[/cyan]")
    summary_grid.add_row("Scorecard", score_text)
    summary_grid.add_row("Scanners", " | ".join(parts))
    if ai.status == "ok":
        badge = CONSENSUS_BADGES.get(ai.consensus_status, f"[dim][AI: {ai.consensus_status}][/dim]")
        summary_grid.add_row("AI Consensus", badge)

    counts: dict[str, int] = {}
    for f in report.active_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    if counts:
        sev_bar = "  ".join(
            f"[{SEV_STYLE.get(s, '')}]{s.upper()}: {counts[s]}[/{SEV_STYLE.get(s, '')}]"
            for s in ("critical", "high", "medium", "low", "info")
            if counts.get(s)
        )
        summary_grid.add_row("Threats", sev_bar)

    console.print(Panel(summary_grid, title="[bold magenta]VibeGate Report[/bold magenta]", box=box.ROUNDED, border_style=border, expand=False))

    if report.scanned_version.startswith("web:"):
        from vibegate.web_audit import compute_web_grade

        if web_failed:
            console.print(
                Panel(
                    "[bold red]Security Grade: N/A (Site Unreachable)[/bold red]\n\n"
                    "Could not connect to the target URL over HTTPS or HTTP; no security checks could be completed.",
                    title="[bold red]A-to-Z Hosted Site Security Checklist[/bold red]",
                    box=box.ROUNDED,
                    border_style="red",
                    expand=False,
                )
            )
        else:
            grade, score = compute_web_grade(report.findings)
            grade_color = "bold green" if grade in ("A+", "A") else ("bold yellow" if grade in ("B", "C") else "bold red")
            rids = {f.rule_id for f in report.active_findings}
            checklist = [
                ("Transport & TLS", any(r.startswith("web.tls.") or r in ("web.http.no-https", "web.header.missing-hsts", "web.body.mixed-content", "web.body.password-over-http") for r in rids)),
                ("Security Headers", any(r.startswith("web.header.") and r != "web.header.missing-hsts" for r in rids)),
                ("Cookies & Sessions", any(r.startswith("web.cookie.") for r in rids)),
                ("CORS Policy", "web.cors.wildcard" in rids),
                ("Public Exposures", any(r.startswith("web.exposure.") for r in rids)),
                ("HTML & JS Bundles", any(r in ("web.body.exposed-secret", "web.bundle.exposed-secret", "web.body.debug-leak", "web.body.form-no-csrf", "web.body.missing-sri") for r in rids)),
            ]
            chk_lines = [f"Security Grade: [{grade_color}]{grade} ({score}/100)[/{grade_color}]", ""] + [
                f"{'[red]✗[/red]' if failed else '[green]✓[/green]'} {label}: {'[red]Issues found[/red]' if failed else '[green]PASS[/green]'}"
                for label, failed in checklist
            ]
            console.print(Panel("\n".join(chk_lines), title="[bold cyan]A-to-Z Hosted Site Security Checklist[/bold cyan]", box=box.ROUNDED, border_style="cyan", expand=False))

    if report.ref_summaries:
        ref_table = Table(
            title="Branches & Pull Requests Checked",
            box=box.ROUNDED,
            border_style="bright_cyan",
            header_style="bold white on #003f88",
        )
        ref_table.add_column("Branch / PR", style="cyan", no_wrap=True)
        ref_table.add_column("Commit", style="dim", no_wrap=True)
        ref_table.add_column("Status", no_wrap=True)
        ref_table.add_column("Note")
        for rs in report.ref_summaries:
            cnt = rs.get("finding_count", 0)
            st = f"[bold red]VULNERABLE ({cnt})[/bold red]" if cnt > 0 else "[bold green]CLEAN (0)[/bold green]"
            ref_table.add_row(rs["ref"], rs["sha"], st, rs.get("note", ""))
        console.print(ref_table)

    if report.partially_staged_files:
        console.print(
            "[yellow]Notice:[/yellow] Partially staged file(s): "
            + ", ".join(report.partially_staged_files)
            + " (scanned [bold]staged[/bold] version only; auto-patch disabled for these)."
        )
    for sr in report.scanner_results:
        if sr.status in ("error", "timeout", "not_installed") and sr.message:
            console.print(f"[yellow]{sr.name} note:[/yellow] {sr.message.splitlines()[-1]}")
    if ai.status not in ("ok", "skipped") and ai.message:
        console.print(f"[yellow]AI review note:[/yellow] {ai.message}")

    if not report.policy_blocked and not web_failed:
        reasons_ok: list[str] = [
            f"Scanned {len(report.files_scanned)} file(s) with policy threshold >= '{report.policy_fail_on}'."
        ]
        for sr in report.scanner_results:
            if sr.status == "ok":
                reasons_ok.append(f"{sr.name}: passed ({len(sr.findings)} finding(s) in {sr.duration_ms}ms).")
            elif sr.status == "skipped":
                reasons_ok.append(f"{sr.name}: skipped ({sr.message or 'not applicable'}).")
        if ai.status == "ok" and not ai.findings:
            reasons_ok.append(f"ai-review ({ai.consensus_status}): {ai.message}.")
        elif ai.status != "ok":
            reasons_ok.append(f"ai-review: {ai.status} ({ai.message}).")
        if report.suppressed_findings:
            reasons_ok.append(f"{len(report.suppressed_findings)} finding(s) suppressed or ignored by developer.")
        console.print(
            Panel(
                "\n".join(f"[green]✓[/green] {r}" for r in reasons_ok),
                title="[bold green]Why It Passed[/bold green]",
                box=box.ROUNDED,
                border_style="green",
                expand=False,
            )
        )

    if ai.reasoning_trace:
        topic_labels = {
            "gemini": "Layer 1 · Gemini\n[dim](Auth & IDOR)[/dim]",
            "groq": "Layer 2 · Groq\n[dim](2nd Opinion)[/dim]",
            "judge": "Judge · Gemini\n[dim](Tie-Breaker)[/dim]",
        }
        trace_grid = Table.grid(padding=(0, 2))
        trace_grid.add_column(style="bold cyan", width=18, no_wrap=True)
        trace_grid.add_column()
        for layer in ("gemini", "groq", "judge"):
            q_key = f"{layer}_q"
            if q_key in ai.reasoning_trace or layer in ai.reasoning_trace:
                q_txt = ai.reasoning_trace.get(q_key, "")
                a_txt = ai.reasoning_trace.get(layer, "")
                cell = Text()
                if q_txt:
                    cell.append("Question: ", style="bold yellow")
                    cell.append(q_txt + "\n")
                if a_txt:
                    cell.append("Answer:   ", style="bold green")
                    cell.append(a_txt)
                trace_grid.add_row(topic_labels[layer], cell)
        console.print(Panel(trace_grid, title="AI Reasoning & Two-Key Dialogue", box=box.ROUNDED, border_style="magenta", expand=False))

    if not report.findings:
        console.print("[green]No findings reported.[/green]")
        return

    findings_iter = [
        (idx, f)
        for idx, f in enumerate(report.findings, 1)
        if not sev_filter or sev_filter == "all" or f.severity == sev_filter
    ]
    code_rows = [(idx, f) for idx, f in findings_iter if f.category != "dependency"]
    dep_rows = [(idx, f) for idx, f in findings_iter if f.category == "dependency"]

    if sev_filter and sev_filter != "all":
        console.print(f"[cyan]Filter active:[/cyan] showing [bold]{sev_filter.upper()}[/bold] findings ({len(findings_iter)}/{len(report.findings)}).")

    if code_rows:
        table = Table(
            title="[bold]Code Security Threats[/bold]",
            box=box.ROUNDED,
            style="on #002b5c",
            border_style="bright_cyan",
            header_style="bold white on #003f88",
            show_lines=False,
        )
        table.add_column("#", style="dim", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Source", no_wrap=True)
        table.add_column("Location", style="cyan", no_wrap=True)
        table.add_column("Title", overflow="fold")
        table.add_column("Status", no_wrap=True)
        table.add_column("How to Access / Example", style="yellow", overflow="fold")

        for idx, f in code_rows:
            sev = Text(f.severity.upper(), style=SEV_STYLE.get(f.severity, ""))
            row_style = "dim" if (f.suppressed or f.dismissed) else ""
            table.add_row(str(idx), sev, f.source_label, f.location, f.title, _status_text(f), access_example(f), style=row_style)
        console.print(table)

    if dep_rows:
        # Group dependency CVEs by (file, package, version) for a clean, readable summary
        grouped: dict[tuple[str, str, str], list[tuple[int, Finding]]] = {}
        for idx, f in dep_rows:
            pkg = f.extra.get("package", f.title.split(":")[0])
            ver = f.extra.get("version", "")
            grouped.setdefault((f.file, pkg, ver), []).append((idx, f))

        dep_table = Table(
            title=f"[bold]Dependency Advisories ({len(dep_rows)} CVEs across {len(grouped)} package(s))[/bold]",
            box=box.ROUNDED,
            style="on #002b5c",
            border_style="bright_cyan",
            header_style="bold white on #003f88",
        )
        dep_table.add_column("#", style="dim", no_wrap=True)
        dep_table.add_column("Max Sev", no_wrap=True)
        dep_table.add_column("Package", style="cyan", no_wrap=True)
        dep_table.add_column("Location", no_wrap=True)
        dep_table.add_column("CVEs", justify="right", no_wrap=True)
        dep_table.add_column("Recommended Fix")

        for (fpath, pkg, ver), items in grouped.items():
            top_idx, top_f = max(items, key=lambda pair: sev_rank(pair[1].severity))
            sev = Text(top_f.severity.upper(), style=SEV_STYLE.get(top_f.severity, ""))
            all_fixed = [v for _, it in items for v in (it.extra.get("fixed_versions") or [])]
            if all_fixed:
                best_fix = max(
                    all_fixed,
                    key=lambda v: tuple(int(p) if p.isdigit() else 0 for p in v.split(".")),
                )
                fix_txt = f"Upgrade {pkg} -> >={best_fix}"
            else:
                fix_txt = "No fixed version listed in OSV"
            dep_table.add_row(str(top_idx), sev, f"{pkg} {ver}".strip(), top_f.location, str(len(items)), fix_txt)
        console.print(dep_table)

    if report.suppressed_findings:
        console.print(f"[dim]{len(report.suppressed_findings)} finding(s) suppressed or dismissed.[/dim]")

    active_code = [(idx, f) for idx, f in code_rows if not f.suppressed and not f.dismissed]
    if active_code:
        console.print("\n[bold]Pinpointed Code Threats & Impact:[/bold]")
        for idx, f in active_code[:10]:
            _render_detail_panel(idx, f, report, console)
        if len(active_code) > 10:
            console.print(f"[dim]...and {len(active_code) - 10} more code finding(s). Enter #<number> to inspect.[/dim]")


def _pinpoint_code(root: str, finding: Finding) -> str:
    """Return a line-numbered code snippet pinpointing the exact vulnerable line(s)."""
    if finding.code_snippet:
        return finding.code_snippet
    if finding.category == "secret" or not finding.start_line:
        return finding.evidence or "(none)"
    path = os.path.join(root, finding.file) if root else ""
    if not path or not os.path.isfile(path):
        return str(finding.extra.get("code_snippet") or finding.evidence or "(none)")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return finding.evidence or "(none)"
    lo = max(1, finding.start_line - 1)
    hi = min(len(lines), max(finding.start_line, finding.end_line) + 1)
    out = []
    for ln_no in range(lo, hi + 1):
        marker = ">>" if finding.start_line <= ln_no <= max(finding.start_line, finding.end_line) else "  "
        out.append(f"{marker} {ln_no:>4} | {lines[ln_no - 1]}")
    return "\n".join(out) if out else (finding.evidence or "(none)")


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
    lines.append(f"[bold red]Threat / Impact:[/bold red]\n{threat_impact(finding)}")
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


def _render_command_bar(console: Console, sev_filter: str) -> None:
    bar = (
        "[bold green][A][/bold green] Auto-fix all & re-stage   "
        "[bold yellow][I][/bold yellow] Ignore updates   "
        f"[bold cyan][F][/bold cyan] Filter ({sev_filter})   "
        "[bold magenta][1-N][/bold magenta] Inspect   "
        "[bold][R][/bold] Refresh   "
        "[bold red][Q][/bold red] Finish"
    )
    console.print(Panel(bar, title="TUI Actions", box=box.ROUNDED, border_style="cyan", expand=False))


def run_interactive(report: ScanReport, cfg: Config, console: Console, show_reasoning: bool = False) -> ScanReport:
    sev_filter = "all"
    render_summary(report, console, sev_filter=sev_filter, show_reasoning=show_reasoning)
    if not report.findings:
        return report

    tty = _open_tty_input()
    if tty is None:
        return report

    try:
        while True:
            _render_command_bar(console, sev_filter)
            choice = Prompt.ask("vibegate", default="q", console=console, stream=tty).strip().lower()
            if choice in ("q", "quit", "exit", ""):
                break
            if choice == "f":
                sev_filter = Prompt.ask(
                    "Filter by severity",
                    choices=["all", "critical", "high", "medium", "low", "info"],
                    case_sensitive=False,
                    default="all",
                    console=console,
                    stream=tty,
                ).strip().lower()
                if console.is_terminal:
                    console.clear()
                render_summary(report, console, sev_filter=sev_filter)
                continue
            if choice == "i":
                dep_active = [f for f in report.active_findings if f.category == "dependency"]
                if not dep_active:
                    console.print("[dim]No active dependency update suggestions to ignore.[/dim]")
                    continue
                for f in dep_active:
                    f.dismissed = True
                    f.dismiss_note = "update suggestion ignored by developer"
                effective = [f for f in report.findings if f.verification_status != "no_longer_reproduces"]
                report.policy_blocked, report.block_reasons = evaluate_policy(effective, report.scanner_results, cfg)
                console.print(f"[yellow]Ignored {len(dep_active)} package update suggestion(s) for this run.[/yellow]")
                continue
            if choice == "a":
                if report.scanned_version.startswith("git:"):
                    console.print("[yellow]Remote repo clones are temporary; auto-patch is only available for local paths.[/yellow]")
                    continue
                before_n = len(report.active_findings)
                applied, skipped = apply_all_safe_fixes(
                    report.target_root,
                    report.active_findings,
                    partially_staged_files=report.partially_staged_files,
                    restage=True,
                )
                for prop in applied:
                    console.print(f"  [green]✓ Fixed[/green] {prop.file}: {prop.description}")
                for msg in skipped:
                    console.print(f"  [yellow]• Skipped[/yellow] {msg}")
                for f in report.active_findings:
                    if f.source in ("gitleaks", "semgrep", "osv-scanner"):
                        verify_finding_recheck(report.target_root, f, timeout=cfg.scanner_timeout)
                remaining = [f for f in report.active_findings if f.verification_status != "no_longer_reproduces"]
                console.print(
                    f"\n[bold]Scorecard:[/bold] Before: [red]{before_n} Risk(s)[/red]  ->  "
                    f"After: [{'green' if not remaining else 'yellow'}]{len(remaining)} Remaining Risk(s)"
                    f"{' (Safe to Ship)' if not remaining else ''}[/]"
                )
                continue
            if choice == "r":
                if console.is_terminal:
                    console.clear()
                render_summary(report, console, sev_filter=sev_filter)
                continue
            if not choice.isdigit() or not (1 <= int(choice) <= len(report.findings)):
                console.print("[red]Invalid selection.[/red]")
                continue

            cur_idx = int(choice) - 1
            while 0 <= cur_idx < len(report.findings):
                finding = report.findings[cur_idx]
                console.print(f"\n[dim]Finding {cur_idx + 1} of {len(report.findings)}[/dim]")
                _show_finding_detail(finding, console)

                action = Prompt.ask(
                    "Action: [p]atch, [i]gnore, [s]uppress, [n]ext, [v]prev, [b]ack",
                    choices=["p", "i", "s", "n", "v", "b"],
                    case_sensitive=False,
                    default="b",
                    console=console,
                    stream=tty,
                ).strip().lower()
                if action == "b":
                    break
                if action == "n":
                    if cur_idx + 1 < len(report.findings):
                        cur_idx += 1
                    else:
                        console.print("[dim]Already at the last finding.[/dim]")
                    continue
                if action == "v":
                    if cur_idx > 0:
                        cur_idx -= 1
                    else:
                        console.print("[dim]Already at the first finding.[/dim]")
                    continue
                if action == "p":
                    if report.scanned_version.startswith("git:"):
                        console.print("[yellow]Remote repo clones are temporary and already deleted; patching is only available for local paths.[/yellow]")
                        continue
                    _handle_patch(finding, report, cfg, console, tty)
                elif action == "i":
                    note = Prompt.ask("Reason for ignoring this suggestion", default="update suggestion ignored", console=console, stream=tty)
                    finding.dismissed = True
                    finding.dismiss_note = note
                    console.print("[yellow]Ignored suggestion for this run.[/yellow]")
                    if cur_idx + 1 < len(report.findings):
                        cur_idx += 1
                    else:
                        break
                elif action == "s":
                    if report.scanned_version.startswith("git:") or not os.path.isdir(report.target_root):
                        console.print("[red]Cannot write suppression file for a temporary/remote clone.[/red]")
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

