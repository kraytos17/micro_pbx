#!/bin/bash
# Convenience wrapper for the sipp interop suite (pytest-based).
# Usage: ./interop.sh [--slow] [pytest args...]
#   ./interop.sh             fast set (S1,S3,S4+S5,S6,S7), ~5s
#   ./interop.sh --slow      + S8 Timer-B 408, ~40s extra
#   ./interop.sh -k s4       select scenarios by name substring
#   ./interop.sh --collect-only -q   list scenarios without running
# Any other args pass straight through to pytest. Logs archive to
# interop/logs/<timestamp>/ with an interop/logs/latest symlink.
#
# Run this suite serially (never alongside `zig test`): both emit real
# UDP on loopback and sipp aborts on stray datagrams (see conftest.py).
set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "interop.sh: missing required tool: $1" >&2
        exit 1
    }
}

need uv
need sipp
need zig

ARGS=()
for a in "$@"; do
    if [ "$a" = "--slow" ]; then
        ARGS+=(--run-slow)
    else
        ARGS+=("$a")
    fi
done

cd "$ROOT/interop"
# uv run syncs the venv automatically; no separate install step.
if [ ${#ARGS[@]} -eq 0 ]; then
    exec uv run pytest
else
    exec uv run pytest "${ARGS[@]}"
fi
