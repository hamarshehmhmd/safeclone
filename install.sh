#!/bin/sh
# safeclone installer: curl -fsSL https://raw.githubusercontent.com/hamarshehmhmd/safeclone/main/install.sh | sh
# Installs the safeclone CLI with uv tool > pipx > a private venv in ~/.local/share/safeclone. Safe to re-run.
# Env: SAFECLONE_REF=<git ref> (default main)
set -eu
REF="${SAFECLONE_REF:-main}"
SRC="git+https://github.com/hamarshehmhmd/safeclone@${REF}"
say() { printf 'safeclone-install: %s\n' "$*"; }
die() { say "error: $*" >&2; exit 1; }

if command -v uv >/dev/null 2>&1; then
  say "installing with uv tool ($SRC)"
  uv tool install --force "$SRC" >/dev/null 2>&1 || die "uv tool install failed"
  BIN="$(uv tool dir --bin 2>/dev/null || echo "$HOME/.local/bin")"
elif command -v pipx >/dev/null 2>&1; then
  say "installing with pipx ($SRC)"
  pipx install --force "$SRC" >/dev/null
  BIN="${PIPX_BIN_DIR:-$HOME/.local/bin}"
else
  PY=""
  for c in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
      PY="$c"; break
    fi
  done
  [ -n "$PY" ] || die "need Python >= 3.9 (or uv / pipx) on PATH"
  command -v git >/dev/null 2>&1 || die "need git to install from GitHub"
  VENV="$HOME/.local/share/safeclone/venv"
  say "installing into $VENV with $PY"
  "$PY" -m venv "$VENV"
  "$VENV/bin/python" -m pip install -q --upgrade "$SRC"
  BIN="$HOME/.local/bin"
  mkdir -p "$BIN"
  ln -sf "$VENV/bin/safeclone" "$BIN/safeclone"
fi

EXE="$BIN/safeclone"
[ -x "$EXE" ] || EXE="$(command -v safeclone || true)"
[ -n "$EXE" ] && [ -x "$EXE" ] || die "install finished but the safeclone command was not found"
say "installed $("$EXE" --version) at $EXE"
