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
  exec "$VIBEGATE_BIN" "$@"
fi

# Default: scan staged changes if any exist, otherwise scan the working tree.
if git -C "$ROOT_DIR" diff --cached --quiet --exit-code 2>/dev/null; then
  exec "$VIBEGATE_BIN" scan --all
else
  exec "$VIBEGATE_BIN" scan
fi

