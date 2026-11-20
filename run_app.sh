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
    scan|hook|init|doctor|rules|suppressions|-h|--help|--version)
      exec "$VIBEGATE_BIN" "$@"
      ;;
    *)
      TARGET="$1"
      shift
      exec "$VIBEGATE_BIN" scan "$TARGET" --all "$@"
      ;;
  esac
fi

cat <<'EOF'
 __     ___ _           ____       _       
 \ \   / (_) |__   ___ / ___| __ _| |_ ___ 
  \ \ / /| | '_ \ / _ \ |  _ / _` | __/ _ \
   \ V / | | |_) |  __/ |_| | (_| | ||  __/
    \_/  |_|_.__/ \___|\____|\__,_|\__\___|
                              by team Z-ZONE
EOF
echo "Scan a target for vulnerabilities:"
echo "  1) Git repository URL (clones temporarily, scans all files, then deletes the clone)"
echo "  2) Local project folder / downloaded directory"
echo "  3) Single local file path (e.g. an unuploaded file on your system)"
echo "  4) Check environment & scanners (doctor)"
echo "  5) List built-in security rules (rules)"
echo "  6) Run 90-second live demo (demo)"
echo "  7) Enable automatic Git commit & push protection (install hooks in a repo)"
printf "Choose [1-7] or paste a Git URL / path directly: "
IFS= read -r CHOICE
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
    exec "$VIBEGATE_BIN" doctor
    ;;
  5)
    exec "$VIBEGATE_BIN" rules
    ;;
  6)
    run_live_demo
    exit 0
    ;;
  7)
    printf "Enter local Git repository path (default: .): "
    IFS= read -r REPO_PATH
    exec "$VIBEGATE_BIN" hook install "${REPO_PATH:-.}" --which all
    ;;
  *)
    TARGET="$CHOICE"
    ;;
esac

if [ -z "$TARGET" ]; then
  echo "No target provided."
  exit 2
fi

exec "$VIBEGATE_BIN" scan "$TARGET" --all
