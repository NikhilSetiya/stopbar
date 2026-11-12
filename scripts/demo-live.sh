#!/usr/bin/env bash
# make demo-live — a real DeepSeek agent (Together) driving AgentKit through
# Stopbar in gatekeeper mode on a Base fork. Spends real Together money, hard-
# capped at $1. Needs Anvil (Foundry) and the Together key in the keychain.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> build"
go build -o bin/stopbard ./cmd/stopbard
go build -o bin/stopbar ./cmd/stopbar

if ! command -v anvil >/dev/null; then
  echo "demo-live needs Anvil (Foundry): https://getfoundry.sh" >&2
  exit 1
fi

W=research/walletagent
if [[ ! -x "$W/.venv/bin/python" ]]; then
  python3 -m venv "$W/.venv"
  "$W/.venv/bin/pip" -q install -r "$W/requirements.lock"
fi
# The demo uses the published SDK (CS-182): install it editable from the repo so
# `import stopbar` resolves. The wallet extra's deps (agentkit, web3) are already
# in requirements.lock, so the core install is enough.
"$W/.venv/bin/pip" -q install -e sdk/python >/dev/null

exec "$W/.venv/bin/python" "$W/demo_live.py"
