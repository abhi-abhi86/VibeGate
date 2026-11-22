"""Passive, non-destructive HTTP & TLS security posture audit for hosted domains."""

from __future__ import annotations

import os
import re
import socket
import ssl
import tempfile
import time
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlparse

import httpx

from vibegate.ai import AIReviewResult, discover_ai_providers, run_ai_review
from vibegate.config import Config
from vibegate.engine import ScanReport, evaluate_policy
from vibegate.models import Finding, sev_rank
from vibegate.scanners.base import ScannerResult, ScanTarget

_DOMAIN_RE = re.compile(
    r"^(?:https?://)?(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)(?::\d{1,5})?(?:/.*)?$"
)


def is_web_target(raw: str) -> bool:
    """Return True if raw looks like an HTTP(S) URL or bare web domain (not a local path or .git URL)."""
    val = (raw or "").strip()
    if not val or val.endswith(".git"):
        return False
    if os.path.exists(val):
        return False
    if val.startswith(("http://", "https://")):
        return True
    if "/" not in val and "\\" not in val and _DOMAIN_RE.match(val):
        return True
    return False


def normalize_web_url(raw: str) -> str:
    """Normalize a pasted domain or URL into an HTTP(S) URL."""
    val = raw.strip()
    if not val.startswith(("http://", "https://")):
        scheme = "http" if val.startswith(("localhost", "127.0.0.1")) else "https"
        val = f"{scheme}://{val}"
    return val


def _make_finding(
    rule_id: str,
    category: str,
    severity: str,
    location: str,
    title: str,
    evidence: str,
    explanation: str,
    remediation: str,
    access_example: str,
    scanned_version: str,
) -> Finding:
    return Finding(
        source="web-audit",
        rule_id=rule_id,
        category=category,
        severity=severity,
        confidence="high",
        file=location,
        start_line=1,
        end_line=1,
        title=title,
        evidence=evidence,
        explanation=explanation,
        remediation=remediation,
        scanned_version=scanned_version,
        extra={"access_example": access_example},
    )


def _check_tls(hostname: str, port: int, base_url: str, scanned_version: str) -> list[Finding]:
    findings: list[Finding] = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                proto = ssock.version() or ""
                cert = ssock.getpeercert() or {}
                if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append(
                        _make_finding(
                            "web.tls.legacy-protocol",
                            "other",
                            "high",
                            hostname,
                            f"Legacy TLS protocol enabled ({proto})",
                            f"Negotiated {proto} on {hostname}:{port}",
                            f"The server negotiated {proto}, which has known cryptographic weaknesses.",
                            "Disable TLS 1.0/1.1 in your web server or CDN and require TLS 1.2+ / TLS 1.3.",
                            f"openssl s_client -connect {hostname}:{port} -tls1",
                            scanned_version,
                        )
                    )
                not_after = cert.get("notAfter")
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (exp - datetime.now(timezone.utc)).days
                    if days_left < 14:
                        sev = "high" if days_left < 0 else "medium"
                        findings.append(
                            _make_finding(
                                "web.tls.cert-expiring",
                                "other",
                                sev,
                                hostname,
                                f"TLS certificate {'expired' if days_left < 0 else f'expiring in {days_left} day(s)'}",
                                f"notAfter: {not_after}",
                                "An expired or soon-to-expire TLS certificate causes browser warnings and outages.",
                                "Renew the TLS certificate immediately (e.g., certbot renew or managed CDN cert).",
                                f"curl -vI {base_url}",
                                scanned_version,
                            )
                        )
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            _make_finding(
                "web.tls.invalid-cert",
                "other",
                "high",
                hostname,
                "Invalid or untrusted TLS certificate",
                str(exc)[:200],
                "Clients cannot verify the server's TLS certificate, enabling Man-in-the-Middle attacks.",
                "Install a valid certificate chain from a trusted CA (e.g., Let's Encrypt / Cloudflare).",
                f"curl -vI {base_url}",
                scanned_version,
            )
        )
    except OSError:
        pass
    return findings


def _check_headers(headers: httpx.Headers, final_url: str, host: str, scanned_version: str) -> list[Finding]:
    findings: list[Finding] = []
    lower_keys = {k.lower(): v for k, v in headers.items()}

    if final_url.startswith("https://"):
        hsts = lower_keys.get("strict-transport-security", "")
        if not hsts:
            findings.append(
                _make_finding(
                    "web.header.missing-hsts",
                    "other",
                    "medium",
                    host,
                    "Missing Strict-Transport-Security (HSTS) header",
                    "Strict-Transport-Security header not present",
                    "Without HSTS, browsers may initially connect over plain HTTP and are vulnerable to SSL stripping.",
                    "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    f"curl -sI {final_url} | grep -i strict-transport-security",
                    scanned_version,
                )
            )
    else:
        findings.append(
            _make_finding(
                "web.http.no-https",
                "other",
                "high",
                host,
                "Site served over unencrypted HTTP without HTTPS redirect",
                f"Final URL remained {final_url}",
                "Traffic over plain HTTP can be intercepted or modified by anyone on the network.",
                "Enable HTTPS and redirect all HTTP (port 80) traffic to HTTPS (301).",
                f"curl -sI {final_url}",
                scanned_version,
            )
        )

    csp = lower_keys.get("content-security-policy", "")
    if not csp:
        findings.append(
            _make_finding(
                "web.header.missing-csp",
                "injection",
                "medium",
                host,
                "Missing Content-Security-Policy (CSP) header",
                "Content-Security-Policy header not present",
                "Without CSP, any XSS flaw can freely load external scripts or exfiltrate data.",
                "Add a Content-Security-Policy header (e.g. default-src 'self'; object-src 'none').",
                f"curl -sI {final_url} | grep -i content-security-policy",
                scanned_version,
            )
        )
    elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
        findings.append(
            _make_finding(
                "web.header.weak-csp",
                "injection",
                "low",
                host,
                "Permissive Content-Security-Policy ('unsafe-inline' / 'unsafe-eval')",
                f"Content-Security-Policy: {csp[:160]}",
                "Allowing 'unsafe-inline' or 'unsafe-eval' weakens XSS protection in CSP.",
                "Replace 'unsafe-inline'/'unsafe-eval' with cryptographic nonces or hashes.",
                f"curl -sI {final_url} | grep -i content-security-policy",
                scanned_version,
            )
        )

    xfo = lower_keys.get("x-frame-options", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        findings.append(
            _make_finding(
                "web.header.missing-xfo",
                "other",
                "medium",
                host,
                "Missing X-Frame-Options / CSP frame-ancestors (Clickjacking risk)",
                "Neither X-Frame-Options nor CSP frame-ancestors is set",
                "Attackers can embed your site in a hidden iframe to trick users into clicking unintended actions.",
                "Add header: X-Frame-Options: DENY (or CSP frame-ancestors 'none').",
                "Embed target URL inside <iframe src='...'></iframe>",
                scanned_version,
            )
        )

    xcto = lower_keys.get("x-content-type-options", "")
    if xcto.lower() != "nosniff":
        findings.append(
            _make_finding(
                "web.header.missing-nosniff",
                "other",
                "low",
                host,
                "Missing X-Content-Type-Options: nosniff",
                f"X-Content-Type-Options: {xcto or '<missing>'}",
                "Browsers may MIME-sniff responses as executable scripts if Content-Type is misconfigured.",
                "Add header: X-Content-Type-Options: nosniff",
                f"curl -sI {final_url} | grep -i x-content-type-options",
                scanned_version,
            )
        )

    if not lower_keys.get("referrer-policy"):
        findings.append(
            _make_finding(
                "web.header.missing-referrer-policy",
                "other",
                "info",
                host,
                "Missing Referrer-Policy header",
                "Referrer-Policy header not present",
                "URLs containing query tokens or sensitive paths may leak via the Referer header to external links.",
                "Add header: Referrer-Policy: strict-origin-when-cross-origin",
                f"curl -sI {final_url} | grep -i referrer-policy",
                scanned_version,
            )
        )

    if not lower_keys.get("permissions-policy"):
        findings.append(
            _make_finding(
                "web.header.missing-permissions-policy",
                "other",
                "info",
                host,
                "Missing Permissions-Policy header",
                "Permissions-Policy header not present",
                "Without Permissions-Policy, embedded third-party scripts/iframes may request camera, microphone, or geolocation.",
                "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
                f"curl -sI {final_url} | grep -i permissions-policy",
                scanned_version,
            )
        )

    if headers.get_list("set-cookie") and "no-store" not in lower_keys.get("cache-control", "").lower():
        findings.append(
            _make_finding(
                "web.header.missing-cache-control",
                "access_control",
                "low",
                host,
                "Authenticated/cookie response missing Cache-Control: no-store",
                f"Cache-Control: {lower_keys.get('cache-control') or '<missing>'}",
                "Shared proxies or browser caches may store pages containing user-specific or session-gated content.",
                "Add header on dynamic/authenticated responses: Cache-Control: no-store, private",
                f"curl -sI {final_url} | grep -i cache-control",
                scanned_version,
            )
        )

    acao = lower_keys.get("access-control-allow-origin", "")
    acac = lower_keys.get("access-control-allow-credentials", "")
    if acao.strip() == "*":
        sev = "high" if acac.strip().lower() == "true" else "medium"
        findings.append(
            _make_finding(
                "web.cors.wildcard",
                "access_control",
                sev,
                host,
                "Wildcard CORS header (Access-Control-Allow-Origin: *)",
                f"Access-Control-Allow-Origin: {acao}",
                "Any third-party website can read responses from this endpoint via browser fetch/XHR.",
                "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted frontend origins.",
                f"curl -sI -H 'Origin: https://evil.example' {final_url}",
                scanned_version,
            )
        )

    server_hdr = lower_keys.get("server", "")
    powered_by = lower_keys.get("x-powered-by", "")
    if powered_by or re.search(r"/\d+\.\d+", server_hdr):
        disclosed = "; ".join(x for x in (f"Server: {server_hdr}" if server_hdr else "", f"X-Powered-By: {powered_by}" if powered_by else "") if x)
        findings.append(
            _make_finding(
                "web.header.version-disclosure",
                "other",
                "low",
                host,
                "Server / technology version disclosed in HTTP headers",
                disclosed,
                "Exposing exact server/framework versions helps attackers target known CVEs for that release.",
                "Disable Server version tokens (e.g. server_tokens off; in nginx) and remove X-Powered-By.",
                f"curl -sI {final_url} | grep -iE 'server|x-powered-by'",
                scanned_version,
            )
        )

    for cookie in headers.get_list("set-cookie"):
        cl = cookie.lower()
        cookie_name = cookie.split("=", 1)[0].strip()
        missing = [
            flag
            for flag in ("httponly", "secure", "samesite")
            if flag not in cl
        ]
        if missing:
            findings.append(
                _make_finding(
                    "web.cookie.missing-flags",
                    "access_control",
                    "medium",
                    host,
                    f"Cookie '{cookie_name}' missing security flag(s): {', '.join(missing)}",
                    cookie[:180],
                    "Cookies missing HttpOnly/Secure/SameSite are exposed to XSS theft, HTTP interception, or CSRF.",
                    "Set HttpOnly; Secure; SameSite=Lax (or Strict) on session and auth cookies.",
                    f"Inspect Set-Cookie header via: curl -sI {final_url} | grep -i set-cookie",
                    scanned_version,
                )
            )

    return findings


_BODY_SECRET_RE = re.compile(
    r"(ghp_[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{20,}|"
    r"(?:SUPABASE_SERVICE_ROLE_KEY|FIREBASE_PRIVATE_KEY|STRIPE_SECRET_KEY)\s*[:=]\s*['\"][^'\"]{12,}['\"])"
)


def _check_js_bundles(
    client: httpx.Client,
    html: str,
    base_origin: str,
    final_url: str,
    host: str,
    scanned_version: str,
) -> list[Finding]:
    """Passively fetch up to 6 same-origin <script src=...> bundles and scan for leaked secrets."""
    findings: list[Finding] = []
    hostname = host.split(":")[0]
    seen_urls: set[str] = set()
    bundle_urls: list[str] = []

    for m in re.finditer(r"""<script\b[^>]*\bsrc=['"]([^'"]+)['"]""", html[:100000], re.IGNORECASE):
        src = m.group(1).strip()
        if not src or src.startswith("data:"):
            continue
        if src.startswith("//"):
            full = f"{urlparse(final_url).scheme}:{src}"
        elif src.startswith("/"):
            full = f"{base_origin.rstrip('/')}{src}"
        elif src.startswith(("http://", "https://")):
            full = src
        else:
            full = f"{base_origin.rstrip('/')}/{src.lstrip('./')}"

        p = urlparse(full)
        if (p.hostname or "") != hostname:
            continue
        if full not in seen_urls:
            seen_urls.add(full)
            bundle_urls.append(full)
        if len(bundle_urls) >= 6:
            break

    for b_url in bundle_urls:
        try:
            r = client.get(b_url, follow_redirects=False)
            if r.status_code != 200:
                continue
            sec_m = _BODY_SECRET_RE.search(r.text[:200000])
            if sec_m:
                tok = sec_m.group(1)
                masked = f"{tok[:6]}...{tok[-4:]}" if len(tok) > 12 else "***"
                b_path = urlparse(b_url).path or "/"
                findings.append(
                    _make_finding(
                        "web.bundle.exposed-secret",
                        "secret",
                        "critical",
                        f"{host}{b_path}",
                        "Secret / API key leaked in frontend JavaScript bundle",
                        f"Found credential pattern ({masked}) in {b_path}",
                        "Frontend JS bundles are downloaded by every visitor; anyone can extract this key via browser DevTools.",
                        "Remove the secret from frontend env/code, move API calls to a backend route, and rotate the exposed key.",
                        f"Open DevTools -> Network/Sources -> {b_url}",
                        scanned_version,
                    )
                )
                break
        except httpx.HTTPError:
            continue
    return findings


def _discover_same_origin_routes(html: str, base_origin: str, host: str, limit: int = 10) -> list[str]:
    """Collect up to `limit` high-signal same-origin routes from HTML links."""
    hostname = host.split(":")[0]
    priority_kw = ("login", "signin", "sign-in", "signup", "register", "admin", "dashboard", "contact", "reset", "api", "account", "profile")
    candidates: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r"""href=['"]([^'"#?]+)['"]""", html[:100000], re.IGNORECASE):
        href = m.group(1).strip()
        if href.startswith("/"):
            full = f"{base_origin.rstrip('/')}{href}"
        elif href.startswith(("http://", "https://")) and urlparse(href).hostname == hostname:
            full = href
        else:
            continue
        path_lower = urlparse(full).path.lower()
        if path_lower in ("", "/") or any(path_lower.endswith(ext) for ext in (".css", ".js", ".png", ".jpg", ".svg", ".ico")):
            continue
        if full not in seen and any(kw in path_lower for kw in priority_kw):
            seen.add(full)
            candidates.append(full)
        if len(candidates) >= limit:
            break
    return candidates


def compute_web_grade(findings: list[Finding]) -> tuple[str, int]:
    """Compute a 0-100 posture score and letter grade (A+ to F) from observed findings."""
    weights = {"critical": 30, "high": 20, "medium": 10, "low": 4, "info": 1}
    penalty = sum(weights.get(f.severity, 5) for f in findings if not f.suppressed and not f.dismissed)
    score = max(0, 100 - penalty)
    if score >= 95:
        return "A+", score
    if score >= 85:
        return "A", score
    if score >= 75:
        return "B", score
    if score >= 60:
        return "C", score
    if score >= 40:
        return "D", score
    return "F", score


def _check_html_body(body: str, final_url: str, host: str, scanned_version: str) -> list[Finding]:
    """Passively inspect the fetched HTML/JS response for leaked secrets, debug traces, mixed content, and form risks."""
    findings: list[Finding] = []
    sample = body[:50000]

    # 1. Exposed API keys / tokens in client HTML or inline JS
    sec_match = _BODY_SECRET_RE.search(sample)
    if sec_match:
        tok = sec_match.group(1)
        masked = f"{tok[:6]}...{tok[-4:]}"
        findings.append(
            _make_finding(
                "web.body.exposed-secret",
                "secret",
                "critical",
                host,
                "Secret / API key exposed in public HTML or frontend JS",
                f"Found token pattern: {masked}",
                "Anyone visiting your site can view page source / DevTools and steal this credential.",
                "Move the key to server-side environment variables, proxy requests through your backend, and rotate the exposed key.",
                f"View page source at {final_url} (Ctrl+U / DevTools)",
                scanned_version,
            )
        )

    # 2. Framework debug / stack-trace leakage
    debug_markers = (
        ("You're seeing this error because you have <code>DEBUG = True</code>", "Django DEBUG=True"),
        ("Werkzeug Debugger", "Flask/Werkzeug interactive debugger"),
        ("<b>Fatal error</b>:", "PHP Fatal error"),
        ("Application error: a client-side exception", "Unhandled frontend error"),
    )
    for marker, label in debug_markers:
        if marker in sample:
            findings.append(
                _make_finding(
                    "web.body.debug-leak",
                    "other",
                    "high",
                    host,
                    f"Production page leaks {label} details",
                    f"Matched debug marker: {marker[:80]}",
                    "Detailed error pages expose internal file paths, stack traces, and configuration to attackers.",
                    "Disable debug mode in production (DEBUG=False / FLASK_DEBUG=0 / display_errors=Off) and serve a generic 500 page.",
                    f"curl -s {final_url} | grep -i debug",
                    scanned_version,
                )
            )
            break

    # 3. Mixed content on HTTPS pages
    if final_url.startswith("https://") and re.search(r"""<(?:script|iframe|form)\b[^>]*(?:src|action)=['"]http://""", sample, re.IGNORECASE):
        findings.append(
            _make_finding(
                "web.body.mixed-content",
                "other",
                "medium",
                host,
                "Mixed content: HTTPS page loads script/iframe/form over plain HTTP",
                "Found http:// resource or form action inside HTTPS page",
                "Scripts or forms loaded over HTTP can be tampered with on the network even when the main page uses HTTPS.",
                "Change all http:// script, iframe, and form URLs to https:// or relative paths.",
                f"Inspect <script src='http://...'> / <form action='http://...'> in {final_url}",
                scanned_version,
            )
        )

    # 4. POST forms without visible CSRF token
    for form_m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", sample, re.IGNORECASE | re.DOTALL):
        attrs, inner = form_m.group(1), form_m.group(2)
        if re.search(r"""method=['"]?post\b""", attrs, re.IGNORECASE):
            if not re.search(r"(csrf|xsrf|_token|authenticity_token)", inner, re.IGNORECASE):
                findings.append(
                    _make_finding(
                        "web.body.form-no-csrf",
                        "access_control",
                        "medium",
                        host,
                        "HTML POST form missing visible CSRF token",
                        f"<form {attrs.strip()[:80]}> without csrf/xsrf/_token input",
                        "Without a CSRF token (and SameSite cookies), another site could trick logged-in users into submitting this form.",
                        "Add your framework's CSRF token inside the form (e.g. {% csrf_token %} in Django, CSRFProtect in Flask).",
                        f"Submit a cross-origin POST to the form action on {host}",
                        scanned_version,
                    )
                )
                break

    # 5. Password input served over unencrypted HTTP
    if not final_url.startswith("https://") and re.search(r"""<input\b[^>]*type=['"]?password\b""", sample, re.IGNORECASE):
        findings.append(
            _make_finding(
                "web.body.password-over-http",
                "secret",
                "critical",
                host,
                "Password login form served over unencrypted HTTP",
                "<input type='password'> found on plain HTTP page",
                "User passwords submitted over HTTP are sent in cleartext and can be captured by anyone on the network.",
                "Serve all login/auth pages exclusively over HTTPS and redirect HTTP to HTTPS.",
                f"Submit login form over http:// on {host}",
                scanned_version,
            )
        )

    # 6. External CDN scripts without Subresource Integrity (SRI)
    for script_m in re.finditer(r"""<script\b([^>]*\bsrc=['"]https?://[^'"]+['"][^>]*)>""", sample, re.IGNORECASE):
        attrs = script_m.group(1)
        src_m = re.search(r"""src=['"](https?://[^'"]+)['"]""", attrs, re.IGNORECASE)
        if src_m and host.split(":")[0] not in src_m.group(1) and "integrity=" not in attrs.lower():
            findings.append(
                _make_finding(
                    "web.body.missing-sri",
                    "other",
                    "low",
                    host,
                    "External CDN <script> missing Subresource Integrity (SRI)",
                    src_m.group(1)[:120],
                    "If the external CDN is compromised, malicious JavaScript will execute in every visitor's browser.",
                    "Add integrity='sha384-...' and crossorigin='anonymous' to external <script> tags.",
                    f"Inspect <script src='{src_m.group(1)[:60]}'> in page source",
                    scanned_version,
                )
            )
            break

    return findings


def _check_exposed_paths(client: httpx.Client, base_origin: str, host: str, scanned_version: str) -> list[Finding]:
    """Strictly passive check for accidentally exposed dotfiles, backups, debug info, or API schemas."""
    findings: list[Finding] = []
    checks = [
        (
            "/.env",
            "web.exposure.dotenv",
            "critical",
            "Exposed .env file publicly accessible",
            lambda body: bool(re.search(r"(?m)^[A-Z0-9_]{3,}\s*=\s*\S+", body)) and "<html" not in body.lower(),
            "Publicly readable .env files leak database passwords, API keys, and session secrets.",
            "Block dotfile access in your web server (e.g. location ~ /\\. { deny all; }) and rotate exposed keys.",
        ),
        (
            "/.git/HEAD",
            "web.exposure.git-dir",
            "critical",
            "Exposed .git repository metadata publicly accessible",
            lambda body: "ref: refs/" in body or bool(re.match(r"^[0-9a-f]{40}\s*$", body.strip())),
            "Anyone can download your .git directory and reconstruct the entire application source code.",
            "Deny public access to /.git in your web server / reverse proxy and remove .git from webroot.",
        ),
        (
            "/.DS_Store",
            "web.exposure.ds-store",
            "medium",
            "Exposed macOS .DS_Store file publicly accessible",
            lambda body: "Bud1" in body[:16],
            ".DS_Store leaks directory and file names on your server, helping attackers map hidden files.",
            "Delete .DS_Store from webroot and block dotfiles in your web server config.",
        ),
        (
            "/phpinfo.php",
            "web.exposure.phpinfo",
            "high",
            "Exposed phpinfo() diagnostic page publicly accessible",
            lambda body: "PHP Version" in body and "phpinfo()" in body,
            "phpinfo() leaks PHP version, server paths, loaded modules, and environment variables.",
            "Remove phpinfo.php from production immediately.",
        ),
        (
            "/openapi.json",
            "web.exposure.openapi",
            "info",
            "Public OpenAPI/Swagger schema exposed at /openapi.json",
            lambda body: '"openapi"' in body[:300] or '"swagger"' in body[:300],
            "Public API schemas reveal every internal endpoint, parameter, and data model to attackers.",
            "Disable or require authentication for /openapi.json and /docs in production.",
        ),
    ]
    for path, rule_id, sev, title, validator, explanation, remediation in checks:
        url = base_origin.rstrip("/") + path
        try:
            resp = client.get(url, follow_redirects=False)
            if resp.status_code == 200 and validator(resp.text[:2000]):
                findings.append(
                    _make_finding(
                        rule_id,
                        "secret",
                        sev,
                        f"{host}{path}",
                        title,
                        f"HTTP 200 OK at {url}",
                        explanation,
                        remediation,
                        f"GET {url}",
                        scanned_version,
                    )
                )
        except httpx.HTTPError:
            continue
    return findings


def audit_domain(
    raw_target: str,
    cfg: Config,
    progress_cb: Callable[[str, str], None] | None = None,
) -> ScanReport:
    """Run a passive, non-destructive HTTP/TLS security posture audit on an authorized domain/URL."""
    def emit(event: str, msg: str) -> None:
        if progress_cb:
            progress_cb(event, msg)

    start = time.monotonic()
    url = normalize_web_url(raw_target)
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    hostname = parsed.hostname or host
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    scanned_version = f"web:{url}"

    emit("scanners_start", f"Running passive HTTP/TLS security audit on {url} (headers, TLS, cookies, CORS, exposures)...")
    findings: list[Finding] = []
    status = "ok"
    message = f"Audited {url}"
    ai_res = AIReviewResult("skipped", [], "No AI API keys set; passive HTTP/TLS checks only")
    captured_headers = ""
    captured_pages: list[str] = []
    final_url = url

    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            try:
                resp = client.get(url)
            except httpx.HTTPError as https_exc:
                if url.startswith("https://"):
                    http_fallback = "http://" + url[len("https://"):]
                    emit("scanners_start", f"HTTPS failed ({https_exc}); checking plain HTTP at {http_fallback}...")
                    resp = client.get(http_fallback)
                else:
                    raise

            final_url = str(resp.url)
            final_parsed = urlparse(final_url)
            base_origin = f"{final_parsed.scheme}://{final_parsed.netloc}"
            captured_headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            captured_pages.append(f"--- PAGE {final_url} (HTTP {resp.status_code}) ---\n{resp.text[:4000]}")

            if final_parsed.scheme == "https":
                findings.extend(_check_tls(final_parsed.hostname or hostname, final_parsed.port or 443, final_url, scanned_version))
            findings.extend(_check_headers(resp.headers, final_url, host, scanned_version))
            findings.extend(_check_html_body(resp.text, final_url, host, scanned_version))
            findings.extend(_check_js_bundles(client, resp.text, base_origin, final_url, host, scanned_version))
            for route_url in _discover_same_origin_routes(resp.text, base_origin, host):
                try:
                    r_sub = client.get(route_url)
                    r_final = str(r_sub.url)
                    captured_pages.append(f"--- PAGE {r_final} (HTTP {r_sub.status_code}) ---\n{r_sub.text[:2500]}")
                    for bf in _check_html_body(r_sub.text, r_final, f"{host}{urlparse(r_final).path}", scanned_version):
                        if not any(ef.rule_id == bf.rule_id and ef.file == bf.file for ef in findings):
                            findings.append(bf)
                except httpx.HTTPError:
                    continue
            findings.extend(_check_exposed_paths(client, base_origin, host, scanned_version))
    except httpx.HTTPError as exc:
        status = "error"
        message = f"Could not reach {url}: {exc}"

    dur_ms = int((time.monotonic() - start) * 1000)
    sr = ScannerResult(name="web-audit", status=status, findings=findings, duration_ms=dur_ms, message=message)
    emit("scanner_done", f"web-audit: {status} ({dur_ms}ms, {len(findings)} finding(s))")

    if status == "ok" and cfg.ai_enabled and discover_ai_providers(cfg):
        pages_blob = "\n\n".join(captured_pages)[:16000]
        summary_doc = (
            f"# Hosted Website Multi-Page Snapshot: {final_url}\n"
            f"# HTTP Response Headers:\n{captured_headers}\n\n"
            f"# Passive Audit Findings ({len(findings)}):\n"
            + "\n".join(f"- [{f.severity}] {f.title}: {f.evidence}" for f in findings)
            + f"\n\n# Inspected Pages ({len(captured_pages)}):\n{pages_blob}\n"
        )
        with tempfile.TemporaryDirectory() as td:
            snap_path = os.path.join(td, "hosted_site_snapshot.html")
            with open(snap_path, "w", encoding="utf-8") as fh:
                fh.write(summary_doc)
            web_target = ScanTarget(
                root=td,
                files=["hosted_site_snapshot.html"],
                version=scanned_version,
            )
            ai_res = run_ai_review(
                web_target,
                findings,
                cfg,
                progress_cb=progress_cb,
                stack_guidance=(
                    f"HOSTED WEBSITE AUDIT GUIDELINE for {final_url} ({len(captured_pages)} page(s) inspected):\n"
                    "TASK A (Transport & TLS): Check HTTPS enforcement, HSTS, and mixed content across all pages.\n"
                    "TASK B (Headers, Cookies & CORS): Check CSP, X-Frame-Options, nosniff, Permissions-Policy, Cache-Control, cookie flags, and CORS.\n"
                    "TASK C (Exposures & Debug Leaks): Check for exposed .env/.git/config/debug traces across all inspected pages.\n"
                    "TASK D (Forms & Client JS): Check all POST forms for CSRF tokens, password fields over HTTP, and leaked secrets in HTML/JS.\n"
                    "TASK E (Grounded Fixes Only): Cite exact observed URLs/headers/HTML lines and provide concrete server/app fixes without guessing."
                ),
            )
        for af in ai_res.findings:
            af.scanned_version = scanned_version
            if not any(df.title.lower() == af.title.lower() for df in findings):
                findings.append(af)

    findings.sort(key=lambda f: (-sev_rank(f.severity), f.file, f.title))
    blocked, reasons = evaluate_policy(findings, [sr], cfg)
    return ScanReport(
        target_root=url,
        scanned_version=scanned_version,
        files_scanned=[url],
        partially_staged_files=[],
        findings=findings,
        scanner_results=[sr],
        ai_result=ai_res,
        duration_ms=int((time.monotonic() - start) * 1000),
        policy_fail_on=cfg.fail_on,
        policy_blocked=blocked,
        block_reasons=reasons,
    )

