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

if [ "$#" -gt 0 ]; then
  case "$1" in
    scan|hook|init|doctor|-h|--help|--version)
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
printf "Choose [1/2/3] or paste a Git URL / path directly: "
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
  *)
    TARGET="$CHOICE"
    ;;
esac

if [ -z "$TARGET" ]; then
  echo "No target provided."
  exit 2
fi

exec "$VIBEGATE_BIN" scan "$TARGET" --all
