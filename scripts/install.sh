#!/bin/sh
# Install "When nothing else is left" (the `thread` command) for the current user. macOS and Linux.
# No administrator rights, nothing outside your home folder.
#
#   sh install.sh                      install or upgrade from the latest source
#   sh install.sh path/or/url.whl      install a specific wheel, zip or URL
#   sh install.sh --uninstall          remove the program (your saved threads are NOT touched)
#
# Environment: THREADVAULT_SOURCE (what to install), THREADVAULT_APP (where the program lives,
# default ~/.local/share/threadvault), THREADVAULT_BIN (where `thread` is linked, default ~/.local/bin).
set -eu

APP_DIR="${THREADVAULT_APP:-${XDG_DATA_HOME:-$HOME/.local/share}/threadvault}"
BIN_DIR="${THREADVAULT_BIN:-$HOME/.local/bin}"
DEFAULT_SOURCE="https://github.com/ugnedirm/kai-nieko-kito-nelieka-mums/archive/refs/heads/main.zip"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
  # Take down the start-at-login service first, if one was set up.
  [ -x "$APP_DIR/venv/bin/thread" ] && "$APP_DIR/venv/bin/thread" setup --remove >/dev/null 2>&1 || true
  rm -f "$BIN_DIR/thread"
  rm -rf "$APP_DIR"
  say "Removed the program. Your saved threads were not touched (default folder: ~/.threadvault)."
  exit 0
fi

SOURCE="${1:-${THREADVAULT_SOURCE:-$DEFAULT_SOURCE}}"

# Find a Python that is new enough (3.11 or newer).
PY=""
for candidate in python3.13 python3.12 python3.11 python3; do
  if command -v "$candidate" >/dev/null 2>&1 &&
     "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    PY="$candidate"; break
  fi
done
[ -n "$PY" ] || die "Python 3.11 or newer is needed. Install it from https://www.python.org/downloads/ and run this again."

say "Installing into $APP_DIR (using $($PY --version 2>&1))..."
mkdir -p "$APP_DIR" "$BIN_DIR"
"$PY" -m venv "$APP_DIR/venv" || die "could not create a virtual environment"
"$APP_DIR/venv/bin/python" -m pip install --quiet --upgrade pip

if [ -f "$SOURCE" ]; then
  "$APP_DIR/venv/bin/python" -m pip install --quiet --upgrade "${SOURCE}[recommended]"
else
  "$APP_DIR/venv/bin/python" -m pip install --quiet --upgrade "threadvault[recommended] @ ${SOURCE}"
fi

ln -sf "$APP_DIR/venv/bin/thread" "$BIN_DIR/thread"
say ""
"$BIN_DIR/thread" --version
say ""
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say "Note: $BIN_DIR is not on your PATH. Add this line to your shell profile (~/.zshrc or ~/.bashrc):"
     say "  export PATH=\"$BIN_DIR:\$PATH\""
     say "" ;;
esac
say "Next:"
say "  1. thread setup          (creates your vault and starts it at every login)"
say "  2. Install the browser extension (Chrome Web Store / Firefox Add-ons, or the zip from the release page)"
say "  3. Click the extension icon, press 'Connect to my vault', then 'Allow'"
