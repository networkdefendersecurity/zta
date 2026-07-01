#!/usr/bin/env bash
# Tears down a workspace created by setup_canary.sh: kills the local canary
# HTTP server and removes the scratch workspace + its disposable bare remote.
set -euo pipefail

WORKDIR="${1:?usage: teardown_canary.sh <workdir-printed-by-setup_canary.sh>}"

if [[ -f "$WORKDIR/.canary_http.pid" ]]; then
  pid="$(cat "$WORKDIR/.canary_http.pid")"
  kill "$pid" 2>/dev/null || true
fi

rm -rf "$WORKDIR" "$WORKDIR/../zta-redteam-remote.git"
echo "==> Removed $WORKDIR and its disposable remote"
