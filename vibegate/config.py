"""Repository-level configuration loaded from .vibegate.toml."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field

from vibegate.models import SEVERITIES

CONFIG_FILE = ".vibegate.toml"

DEFAULT_TOML = """\
# VibeGate configuration
[policy]
# Block the commit when a non-suppressed finding is at or above this severity.
fail_on = "high"            # critical | high | medium | low | info
# AI findings are candidates, not confirmed vulnerabilities. Set true to let them block.
ai_findings_block = false
# Block when a scanner is missing, errors, or times out (otherwise only warn).
block_on_scanner_error = false

[scanners]
enabled = ["gitleaks", "semgrep", "osv-scanner"]
timeout_seconds = 90

[ai]
# Optional AI authorization review. Needs GEMINI_API_KEY; disable with --no-ai or VIBEGATE_NO_AI=1.
enabled = true
model = "gemini-2.5-flash"
timeout_seconds = 20
max_files = 4
max_chars = 16000

[verify]
# Optional test command the developer may choose to run after applying a patch.
# test_command = "python -m pytest -q"
"""


@dataclass
class Config:
    fail_on: str = "high"
    ai_findings_block: bool = False
    block_on_scanner_error: bool = False
    scanners: list[str] = field(default_factory=lambda: ["gitleaks", "semgrep", "osv-scanner"])
    scanner_timeout: int = 90
    ai_enabled: bool = True
    ai_model: str = "gemini-2.5-flash"
    ai_timeout: int = 20
    ai_max_files: int = 4
    ai_max_chars: int = 16000
    test_command: str | None = None
    source_file: str | None = None


def _load_dotenv(paths: list[str]) -> None:
    """Load simple KEY=VALUE pairs from .env files without overwriting existing env vars."""
    for env_path in paths:
        if not os.path.isfile(env_path):
            continue
        with open(env_path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and val and key not in os.environ:
                    os.environ[key] = val


def load_config(root: str | None) -> Config:
    pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [os.path.join(pkg_root, ".env"), os.path.join(os.getcwd(), ".env")]
    if root:
        candidates.append(os.path.join(root, ".env"))
    _load_dotenv(candidates)

    cfg = Config()
    if root:
        path = os.path.join(root, CONFIG_FILE)
        if os.path.isfile(path):
            with open(path, "rb") as fh:
                data = tomllib.load(fh)
            cfg.source_file = path
            pol = data.get("policy", {})
            sc = data.get("scanners", {})
            ai = data.get("ai", {})
            ver = data.get("verify", {})
            cfg.fail_on = pol.get("fail_on", cfg.fail_on)
            cfg.ai_findings_block = bool(pol.get("ai_findings_block", cfg.ai_findings_block))
            cfg.block_on_scanner_error = bool(pol.get("block_on_scanner_error", cfg.block_on_scanner_error))
            cfg.scanners = list(sc.get("enabled", cfg.scanners))
            cfg.scanner_timeout = int(sc.get("timeout_seconds", cfg.scanner_timeout))
            cfg.ai_enabled = bool(ai.get("enabled", cfg.ai_enabled))
            cfg.ai_model = ai.get("model", cfg.ai_model)
            cfg.ai_timeout = int(ai.get("timeout_seconds", cfg.ai_timeout))
            cfg.ai_max_files = int(ai.get("max_files", cfg.ai_max_files))
            cfg.ai_max_chars = int(ai.get("max_chars", cfg.ai_max_chars))
            cfg.test_command = ver.get("test_command") or None
    if cfg.fail_on not in SEVERITIES:
        raise ValueError(f"policy.fail_on must be one of {SEVERITIES}, got {cfg.fail_on!r}")
    if os.environ.get("VIBEGATE_NO_AI", "").lower() in ("1", "true", "yes"):
        cfg.ai_enabled = False
    if os.environ.get("VIBEGATE_AI_MODEL"):
        cfg.ai_model = os.environ["VIBEGATE_AI_MODEL"]
    return cfg

