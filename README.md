# VibeGate

A local-first security gate for AI-generated code. VibeGate scans your **staged** Git changes before a commit, combining deterministic scanners (**Gitleaks**, **Semgrep**, **OSV-Scanner**) with an optional **Gemini** authorization review for context-dependent access-control gaps (like IDORs).

VibeGate does not claim to prove code is secure; it helps catch high-signal issues early, explains them in plain English, lets you review diffs before applying a fix, and reruns the relevant check after a change.

## Setup

Create a virtual environment and install VibeGate:

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Install the deterministic scanners (macOS / Homebrew):

```bash
brew install gitleaks semgrep osv-scanner
```

Check your environment:

```bash
.venv/bin/vibegate doctor
```

## Usage

```bash
# Scan staged changes (interactive terminal review)
vibegate scan

# Scan all tracked/unignored files in CI mode with JSON output
vibegate scan --all --ci --json

# Disable AI review (deterministic scanners only)
vibegate scan --no-ai

# Install / uninstall the Git pre-commit hook
vibegate hook install
vibegate hook uninstall

# Create a .vibegate.toml config file
vibegate init
```

Optional AI authorization review uses `GEMINI_API_KEY`:

```bash
export GEMINI_API_KEY="your-key"
```

If `GEMINI_API_KEY` is not set or the API times out/is unavailable, VibeGate still runs all deterministic scanners and explicitly reports that AI review was skipped/unavailable.

## Safe staged-change & patch workflow

- **Staged-only scanning:** `vibegate scan` checks out the Git **index** (`git checkout-index`) into a temporary directory so scanners inspect what will actually be committed—not unstaged edits in your working tree.
- **Partial staging protection:** If a file is partially staged (`git add -p`), VibeGate flags it and refuses to auto-patch or auto-stage it.
- **Explicit patches & honest verification:** Supported deterministic findings (e.g., Python f-string SQL injection) show a unified diff and require confirmation before editing or staging. Afterward, VibeGate reruns the original scanner and reports precisely whether that rule still triggers (e.g., `no_longer_reproduces`), rather than claiming the file is "Verified Safe."

## Demo

`demo/` contains a small Flask app with four intentional issues:
1. A committed test token in `demo/app.py` (Gitleaks)
2. A Python f-string SQL injection in `demo/app.py` (Semgrep — with reviewable patch + rescan)
3. A missing ownership check on `DELETE /orders/<order_id>` in `demo/app.py` (AI authorization review)
4. Vulnerable packages in `demo/requirements.txt` (OSV-Scanner)

Run a non-interactive scan on `demo/`:

```bash
.venv/bin/vibegate scan demo --all --no-tui --no-ai
```
