"""Project stack detection and stack-specific rule/prompt selection."""

from __future__ import annotations

import json
import os
import re

from vibegate.scanners.base import ScanTarget
from vibegate.scanners.semgrep import RULES_PATH as BASE_SEMGREP_RULES

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

SUPPORTED_STACKS = ("django", "flask", "fastapi", "express")

STACK_LABELS = {
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "express": "Express",
}

_STACK_AI_GUIDANCE = {
    "django": (
        "This is a Django project; check views for request.user ownership checks "
        "(e.g., get_object_or_404(Model, pk=id, owner=request.user)), @login_required / LoginRequiredMixin, "
        "@csrf_exempt, DEBUG=True, ALLOWED_HOSTS=['*'], and raw SQL (.extra() / RawSQL)."
    ),
    "flask": (
        "This is a Flask project; check routes for session/current_user authentication and ownership checks, "
        "abort(403)/abort(404), SECRET_KEY handling, render_template_string SSTI, and debug=True."
    ),
    "fastapi": (
        "This is a FastAPI project; check endpoints for Depends(get_current_user) authentication and "
        "resource ownership checks, HTTPException(status_code=403), Pydantic validation, and CORS allow_origins=['*']."
    ),
    "express": (
        "This is an Express.js project; check routes for auth middleware (req.user) and resource ownership checks, "
        "res.status(403), CORS/Helmet configuration, open redirects, and SQL/NoSQL injection."
    ),
}


def _read_root_manifest(target: ScanTarget, filename: str) -> str:
    """Read a root-level manifest file from target files or target.root on disk."""
    for rel in target.files:
        if os.path.basename(rel) == filename:
            content = target.read(rel)
            if content:
                return content
    if target.root:
        path = os.path.join(target.root, filename)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except OSError:
                return ""
    return ""


def _has_root_file(target: ScanTarget, filename: str) -> bool:
    if any(os.path.basename(rel) == filename for rel in target.files):
        return True
    if target.root and os.path.isfile(os.path.join(target.root, filename)):
        return True
    return False


def _package_json_has_dep(pkg_text: str, dep: str) -> bool:
    if not pkg_text:
        return False
    try:
        data = json.loads(pkg_text)
        if isinstance(data, dict):
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                deps = data.get(section)
                if isinstance(deps, dict) and dep in deps:
                    return True
            return False
    except json.JSONDecodeError:
        pass
    return bool(re.search(rf'["\']{re.escape(dep)}["\']\s*:', pkg_text))


def _manifest_has_python_pkg(manifest_text: str, pkg: str) -> bool:
    if not manifest_text:
        return False
    return bool(re.search(rf"(?im)(?:^|[\s\"'=<>~\[,]){re.escape(pkg)}(?:$|[\s\"'=<>~\]\[,;])", manifest_text))


def detect_stacks(target: ScanTarget) -> list[str]:
    """Detect web frameworks/stacks present in the scanned target or repo root."""
    detected: list[str] = []

    req_txt = _read_root_manifest(target, "requirements.txt")
    pyproject_toml = _read_root_manifest(target, "pyproject.toml")
    py_manifest = f"{req_txt}\n{pyproject_toml}"
    pkg_json = _read_root_manifest(target, "package.json")

    py_contents: list[str] = []
    js_contents: list[str] = []
    for rel in target.files:
        ext = os.path.splitext(rel)[1].lower()
        if ext == ".py":
            py_contents.append(target.read(rel))
        elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            js_contents.append(target.read(rel))

    py_blob = "\n".join(py_contents)
    js_blob = "\n".join(js_contents)

    # Django
    if (
        _has_root_file(target, "manage.py")
        or any(os.path.basename(f) == "settings.py" for f in target.files)
        or _manifest_has_python_pkg(py_manifest, "django")
        or re.search(r"(?m)^\s*(?:from|import)\s+django\b", py_blob)
    ):
        detected.append("django")

    # Flask
    if _manifest_has_python_pkg(py_manifest, "flask") or re.search(r"(?m)^\s*(?:from|import)\s+flask\b", py_blob):
        detected.append("flask")

    # FastAPI
    if _manifest_has_python_pkg(py_manifest, "fastapi") or re.search(r"(?m)^\s*(?:from|import)\s+fastapi\b", py_blob):
        detected.append("fastapi")

    # Express
    if _package_json_has_dep(pkg_json, "express") or re.search(
        r"""(?:require\(\s*['"]express['"]\s*\)|from\s+['"]express['"])""", js_blob
    ):
        detected.append("express")

    return detected


def stack_rule_paths(stacks: list[str]) -> list[str]:
    """Return Semgrep rule config paths: base rules plus any matching stack rule packs."""
    configs = [BASE_SEMGREP_RULES]
    for stack in stacks:
        candidate = os.path.join(RULES_DIR, f"{stack}.yml")
        if os.path.isfile(candidate) and candidate not in configs:
            configs.append(candidate)
    return configs


def stack_ai_guidance(stacks: list[str]) -> str:
    """Return framework-specific AI review instructions for the detected stacks."""
    lines = [_STACK_AI_GUIDANCE[s] for s in stacks if s in _STACK_AI_GUIDANCE]
    return "\n".join(lines)

