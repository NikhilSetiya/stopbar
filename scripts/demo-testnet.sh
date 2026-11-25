#!/usr/bin/env bash
# make demo-testnet — scripted (no model, no real money) run of the Stopbar
# gatekeeper + chain enricher against LIVE Base Sepolia over a public RPC.
# It needs the funded wallet key in research/walletagent/results/testnet-wallet.key
# and refuses to run without it (NEW_TESTNET_WALLET=1 creates a new one to fund),
# No Anvil and no Together key needed.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> build"
go build -o bin/stopbard ./cmd/stopbard
go build -o bin/stopbar ./cmd/stopbar

W=research/walletagent
if [[ ! -x "$W/.venv/bin/python" ]]; then
  python3 -m venv "$W/.venv"
  "$W/.venv/bin/pip" -q install -r "$W/requirements.lock"
fi
# web3 (in requirements.lock) brings eth_account; the demo talks to stopbard over
# plain HTTP, so the SDK/wallet extras are not required here.

exec "$W/.venv/bin/python" "$W/demo_testnet.py"
