#!/usr/bin/env bash
# SDK gate (CS-181/182/183), run by scripts/e2e.sh and the required CI `go` job.
# Both SDKs' unit tests (mock server, shared encoding fixtures), then each SDK's
# example agent end to end against real stopbards (-dev-world, auth on): a
# gatekeeper one (holds the wallet) and, for the TypeScript example's own
# commit/release, an advisory one. Allow + signed tx; a Grok-pattern encoded
# injection labelled decoded and denied; escalations polled, approved and
# rejected with two Ed25519 approver keys (CS-151, 2-of-2: one signature is
# not enough) over the real CS-105/152 routes; commit,
# release and CONFLICT. Then each run's audit log must verify offline.
# Usage: scripts/e2e_sdk.sh PATH/TO/stopbard PATH/TO/stopbar   (needs node >= 20, npm)
set -euo pipefail
cd "$(dirname "$0")/.."
STOPBARD=$1 CLI=$2
T="$(mktemp -d)"
PIDS=()
trap 'kill ${PIDS[@]+"${PIDS[@]}"} 2>/dev/null || true; rm -rf "$T"' EXIT

echo "--- python SDK: unit tests"
P=sdk/python
[[ -x "$P/.venv/bin/python" ]] || { python3 -m venv "$P/.venv" && "$P/.venv/bin/pip" -q install -e "$P[dev]"; }
"$P/.venv/bin/python" -m pytest -q "$P/tests"

echo "--- typescript SDK: unit tests (node:test), npm pack"
(cd sdk/typescript && { [[ -d node_modules ]] || npm ci --no-audit --no-fund; } && npm test --silent && npm pack --dry-run --silent >/dev/null)

echo "--- stopbard: dev world, gatekeeper, auth on"
cat >"$T/world.json" <<'EOF'
{"balances": {"ETH": "10"}, "prices_usd": {"ETH": "3500"},
 "known_destinations": ["0x000000000000000000000000000000000000b0b0"],
 "limits": [{"scope": "wallet", "window": "24h", "max_usd": "50000", "max_count": 10}]}
EOF
# Anvil test account 0: a public test key, never funded (the examples' WALLET).
(umask 077; printf 'stopbar-dev-wallet-secp256k1-v1\nac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n' >"$T/wallet")
key() { # agent scopes -> secret on stdout, record in $T/rec.<agent>
  "$CLI" keygen api-key --tenant demo --agent "$1" --scopes "$2" 2>"$T/sec" | grep -v '^#' >"$T/rec.$1"
  grep -o 'stopbar_sk_[A-Za-z0-9_-]*' "$T/sec"
}
AGENT_KEY="$(key wallet-agent evaluate)"
python3 -c 'import json,sys; print(json.dumps([json.load(open(f)) for f in sys.argv[1:]]))' "$T"/rec.* >"$T/keys.json"
# Two approvers (CS-151): private keys stay in $T, stopbard gets the public halves.
for who in alice bob; do
  "$CLI" approver keygen "$T/approver-$who.key" | sed -n 's/^public_key[^:]*: *//p' >"$T/approver-$who.pub"
done
python3 -c 'import json,sys; print(json.dumps({"approvers": [{"id": w, "tenant": "demo", "owner": {"agent_id": w},
  "public_key": open(sys.argv[1] + "/approver-" + w + ".pub").read().strip()} for w in ("alice", "bob")]}))' "$T" >"$T/approvers.json"
start() { # name extra-flags... -> address in $T/addr-<name> (not a subshell: PIDS must stick)
  local n=$1; shift
  "$STOPBARD" -listen 127.0.0.1:0 -dev-world "$T/world.json" -tenant demo -auth-keys "$T/keys.json" \
    -approvers "$T/approvers.json" -approval-quorum 2 -state-dir "$T/state-$n" "$@" >"$T/out-$n" 2>"$T/log-$n" &
  PIDS+=($!)
  for _ in $(seq 50); do grep -q 'listening on' "$T/out-$n" 2>/dev/null && break; sleep 0.1; done
  sed -n 's/.*listening on //p' "$T/out-$n" | grep . >"$T/addr-$n" || { echo "stopbard ($n) did not start"; cat "$T/log-$n"; exit 1; }
}
start gatekeeper -dev-wallet "$T/wallet"
start advisory
GK="$(cat "$T/addr-gatekeeper")" ADV="$(cat "$T/addr-advisory")"
export STOPBAR_URL="http://$GK" STOPBAR_ADVISORY_URL="http://$ADV" STOPBAR_KEY="$AGENT_KEY" STOPBAR_TENANT=demo \
  STOPBAR_APPROVER_KEY_1="$T/approver-alice.key" STOPBAR_APPROVER_KEY_2="$T/approver-bob.key"

echo "--- typescript example vs live stopbard"
node sdk/typescript/dist/examples/protect-agent.js
echo "--- python example vs live stopbard"
PYTHONPATH="$P" "$P/.venv/bin/python" "$P/examples/protect_agent.py"  # the venv has the 'approver' extra

for n in gatekeeper advisory; do
  url="$STOPBAR_URL"; [[ $n == advisory ]] && url="$STOPBAR_ADVISORY_URL"
  python3 -c 'import sys,urllib.request; sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1]).read())' "$url/v1/keys" >"$T/jwks-$n.json"
done
kill -TERM "${PIDS[@]}"; wait "${PIDS[@]}" || true
PIDS=()
for n in gatekeeper advisory; do
  "$CLI" audit verify --state-dir "$T/state-$n" --keys "$T/jwks-$n.json" --require-covered
done
echo "ok   SDK examples (TypeScript, Python) end to end"
