#!/usr/bin/env sh
set -eu

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"
VIBEGATE_BIN="$VENV_DIR/bin/vibegate"

if [ ! -x "$VIBEGATE_BIN" ]; then
  echo "Setting up virtual environment in $VENV_DIR..."
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install -e "$ROOT_DIR[dev]"
fi

run_live_demo() {
  DEMO_TMP="$(mktemp -d "${TMPDIR:-/tmp}/vibegate-demo-XXXXXX")"
  trap 'rm -rf "$DEMO_TMP"' EXIT
  cp -R "$ROOT_DIR/demo/." "$DEMO_TMP/"
  mkdir -p "$DEMO_TMP/demo"
  cp "$ROOT_DIR/demo/app.py" "$DEMO_TMP/demo/app.py"
  touch "$DEMO_TMP/demo/__init__.py"
  git -C "$DEMO_TMP" init -q
  git -C "$DEMO_TMP" config user.email "demo@z-zone.dev"
  git -C "$DEMO_TMP" config user.name "Z-ZONE Demo"
  git -C "$DEMO_TMP" add app.py requirements.txt

  echo "=== [1/4] Scanning staged demo files (Before Auto-Patch) ==="
  "$VIBEGATE_BIN" scan "$DEMO_TMP" --staged --no-tui --deps || true

  echo ""
  echo "=== [2/4] Applying one-keystroke auto-fixes & re-staging ==="
  "$VIBEGATE_BIN" scan "$DEMO_TMP" --staged --auto-fix --deps --no-ai

  echo ""
  echo "=== [3/4] Re-scanning staged files (After Auto-Patch) ==="
  "$VIBEGATE_BIN" scan "$DEMO_TMP" --staged --no-tui --deps --no-ai || true

  echo ""
  echo "=== [4/4] Running functional tests on patched app ==="
  cp "$DEMO_TMP/app.py" "$DEMO_TMP/demo/app.py"
  PYTHONPATH="$DEMO_TMP" "$VENV_DIR/bin/pytest" -q "$DEMO_TMP/test_app.py"
}

if [ "$#" -gt 0 ]; then
  case "$1" in
    demo)
      run_live_demo
      exit 0
      ;;
    scan|hook|init|doctor|rules|suppressions|audit|-h|--help|--version)
      exec "$VIBEGATE_BIN" "$@"
      ;;
    *)
      TARGET="$1"
      shift
      exec "$VIBEGATE_BIN" scan "$TARGET" --all "$@"
      ;;
  esac
fi

"$VENV_DIR/bin/python" - <<'PY'
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from vibegate.ui import print_banner

console = Console()
print_banner(console)

menu = Table.grid(padding=(0, 2))
menu.add_column(style="bold cyan", justify="right", no_wrap=True)
menu.add_column(style="bold white", no_wrap=True)
menu.add_column(style="dim")
menu.add_row("1)", "Git Repository URL", "Clone temporarily, scan all files, then delete clone")
menu.add_row("2)", "Local Project Folder", "Scan a local or downloaded directory")
menu.add_row("3)", "Single Local File", "Scan an unuploaded file on your system")
menu.add_row("4)", "Enable Git Protection", "Activate automatic pre-commit & pre-push hooks globally")
menu.add_row("5)", "Disable Git Protection", "Deactivate global pre-commit & pre-push hooks")
menu.add_row("6)", "Hosted Website Audit", "Check live domain (.com/.in) TLS, headers, JS bundles & exposures")

console.print(Panel(menu, title="[bold magenta]Choose a Target or Action[/bold magenta]", box=box.ROUNDED, border_style="cyan", expand=False))
PY
printf "Choose [1-6] or paste a Git URL / domain / path: "
IFS= read -r CHOICE
CHOICE="$(printf '%s' "$CHOICE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
case "$CHOICE" in
  1)
    printf "Enter Git repository URL: "
    IFS= read -r TARGET
    ;;
  2)
    printf "Enter local folder path: "
    IFS= read -r TARGET
    ;;
  3)
    printf "Enter local file path: "
    IFS= read -r TARGET
    ;;
  4)
    exec "$VIBEGATE_BIN" hook install --global --which all
    ;;
  5)
    exec "$VIBEGATE_BIN" hook uninstall --global
    ;;
  6)
    printf "Enter domain or URL you own/are authorized to audit (e.g. https://myapp.com): "
    IFS= read -r TARGET
    exec "$VIBEGATE_BIN" audit "$TARGET"
    ;;
  *)
    TARGET="$CHOICE"
    ;;
esac

TARGET="$(printf '%s' "$TARGET" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
if [ -z "$TARGET" ]; then
  echo "No target provided."
  exit 2
fi

exec "$VIBEGATE_BIN" scan "$TARGET" --all
