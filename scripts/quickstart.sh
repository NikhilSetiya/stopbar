#!/usr/bin/env bash
# make quickstart (CS-198): run the README's end-to-end quickstart block
# (between <!-- quickstart:begin --> and <!-- quickstart:end -->) verbatim, so
# the README can't drift from what works. Run by scripts/e2e.sh and the required
# CI `go` job. It runs in a scratch directory standing in for the clone (sdk/
# and examples/ link to this checkout), with the given binaries on PATH, and
# echoes each line as it runs (set -v). Its own additions: a trap that stops
# the block's background jobs if a step fails, a check that ports 7777 and 8545
# are free, and, after the block, the SDK examples against a fresh init.
# Usage: scripts/quickstart.sh [PATH/TO/stopbard PATH/TO/stopbar]   (default: builds them)
# Needs anvil and cast (Foundry); without them it skips, except under CI.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"
if ! command -v anvil >/dev/null || ! command -v cast >/dev/null; then
  [[ -z "${CI:-}" ]] || { echo "FAIL quickstart: anvil/cast missing in CI"; exit 1; }
  echo "SKIP quickstart: anvil not installed (brew install foundry). CI runs it."; exit 0
fi
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir "$T/bin"
if [[ $# -eq 2 ]]; then
  ln -s "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")" "$T/bin/stopbard"
  ln -s "$(cd "$(dirname "$2")" && pwd)/$(basename "$2")" "$T/bin/stopbar"
else
  go build -o "$T/bin/" ./cmd/stopbard ./cmd/stopbar
fi
python3 -c 'import socket, sys
for p in (7777, 8545):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: s.bind(("127.0.0.1", p))
    except OSError: sys.exit(f"FAIL quickstart: port {p} is in use (the README uses 7777 for stopbard, 8545 for anvil)")'

mkdir "$T/clone"
ln -s "$REPO/sdk" "$REPO/examples" "$T/clone/"
{
  echo "trap 'kill \$(jobs -p) 2>/dev/null || true' EXIT; set -v"
  sed -n '/^<!-- quickstart:begin/,/^<!-- quickstart:end/p' README.md | sed '1,2d;$d' | sed '$d'
} >"$T/block.sh"
grep -q 'stopbar audit verify' "$T/block.sh" || { echo "FAIL quickstart: README block not found"; exit 1; }
(cd "$T/clone" && PATH="$T/bin:$PATH" bash -euo pipefail "$T/block.sh")
echo "ok   README quickstart: init, anvil, stopbard, agent (allow + broadcast, escalate, CS-2026-0011, CS-2026-0008), 2-of-2 approve, reject, T3 deny, audit verify"

# The SDK examples run against an init deployment too (wallet and approver keys from init).
cd "$T" && PATH="$T/bin:$PATH" stopbar init --dir "$T/ex" >"$T/ex.out"
PATH="$T/bin:$PATH" stopbard -config "$T/ex/stopbard.json" -listen 127.0.0.1:0 >"$T/ex.addr" 2>"$T/ex.log" &
PID=$!
trap 'kill $PID 2>/dev/null || true; rm -rf "$T"' EXIT
for _ in $(seq 50); do grep -q 'listening on' "$T/ex.addr" && break; sleep 0.1; done
export STOPBAR_URL="http://$(sed -n 's/.*listening on //p' "$T/ex.addr")" STOPBAR_TENANT=demo \
  STOPBAR_KEY="$(grep -om1 'stopbar_sk_[A-Za-z0-9_-]*' "$T/ex.out")" \
  STOPBAR_WALLET="$(grep -om1 'gatekeeper wallet 0x[0-9a-fA-F]*' "$T/ex.out" | cut -d' ' -f3)" \
  STOPBAR_APPROVER_KEY_1="$T/ex/approver-1.key" STOPBAR_APPROVER_KEY_2="$T/ex/approver-2.key"
PY=python3; [[ -x "$REPO/sdk/python/.venv/bin/python" ]] && PY="$REPO/sdk/python/.venv/bin/python"  # approvals need 'cryptography'
PYTHONPATH="$REPO/sdk/python" "$PY" "$REPO/sdk/python/examples/protect_agent.py"
echo "ok   SDK example (Python) against an init deployment"
