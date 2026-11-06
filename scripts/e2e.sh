#!/usr/bin/env bash
# End-to-end evaluation gate. Run after every build step (`make e2e`).
# Mirrors CI, then runs every deeper end-to-end check that exists so far.
# Extend it in the same change that adds a pipeline stage.
set -euo pipefail
cd "$(dirname "$0")/.."

# The toolchain comes from go.mod (go/toolchain lines); GOTOOLCHAIN=auto fetches it.
printf '==> toolchain: %s\n' "$(go version)"

step() { printf '\n==> %s\n' "$*"; }

step gofmt
test -z "$(gofmt -l . | tee /dev/stderr)"
step vet;   go vet ./...
step build; go build ./...
if cc --version >/dev/null 2>&1; then
  step "test (race)"; go test -race -count=1 ./...
else
  step "test (NO RACE: C toolchain unavailable; on macOS run 'sudo xcodebuild -license')"
  CGO_ENABLED=0 go test -count=1 ./...
fi
step "fuzz smoke (canonicaliser, gateway, EVM decoder)"
go test -run='^$' -fuzz=FuzzTransformIdempotent -fuzztime="${FUZZTIME:-10s}" ./internal/canon/
go test -run='^$' -fuzz=FuzzEvaluate -fuzztime="${FUZZTIME:-10s}" ./internal/gateway/
go test -run='^$' -fuzz=FuzzDecode -fuzztime="${FUZZTIME:-10s}" ./internal/decode/evm/

step "policy: starter pack validates and combines (CS-007)"
go test -count=1 -run 'TestSpike' ./internal/policy/
go test -run='^$' -bench=BenchmarkSpikeEvaluate -benchtime=20000x ./internal/policy/ | grep Benchmark

step "decision token v1: vectors fresh and verify (CS-008)"
go test -count=1 -run 'TestDecisionTokenVectors|TestPayloadHash' ./internal/decision/

step "engine: fail-closed matrix, invariants, gateway wiring (CS-104)"
go test -race -count=1 ./internal/engine/

step "trusted core is stdlib-only (canon, decision, model)"
bad="$(go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./internal/canon ./internal/decision ./internal/model | grep -v '^github.com/NikhilSetiya/stopbar/' || true)"
[[ -z "$bad" ]] || { echo "FAIL third-party imports in the trusted core: $bad"; exit 1; }
echo "ok   no third-party imports"

step "audit: chain, checkpoints, tamper (edit a byte, delete, reorder, truncate) fail verify (CS-171/172)"
go test -race -count=1 ./internal/audit/

step "corpus + spec fixtures against schemas"
python3 scripts/validate_corpus.py

step "binaries"
BIN="$(mktemp -d)"
trap 'kill "${PID:-}" 2>/dev/null || true; rm -rf "$BIN"' EXIT
go build -o "$BIN/" ./cmd/...
"$BIN/stopbar" version
"$BIN/stopbard" -version

step "gateway over HTTP (CS-101)"
if "$BIN/stopbard" -listen 0.0.0.0:0 >/dev/null 2>&1; then
  echo "FAIL stopbard accepted a non-loopback listen address without auth"; exit 1
fi
echo "ok   non-loopback listen refused"
"$BIN/stopbard" -listen 127.0.0.1:0 >"$BIN/out" 2>"$BIN/log" &
PID=$!
for _ in $(seq 50); do grep -q 'listening on' "$BIN/out" 2>/dev/null && break; sleep 0.1; done
ADDR="$(sed -n 's/.*listening on //p' "$BIN/out")"
[[ -n "$ADDR" ]] || { echo "stopbard did not start"; cat "$BIN/log"; exit 1; }
python3 scripts/e2e_gateway.py "http://$ADDR"
kill -TERM "$PID"; wait "$PID" && echo "ok   graceful shutdown on SIGTERM (exit 0)"
PID=

step "tool calls through live stopbard: session taint from the frozen trust map (CS-502)"
python3 scripts/e2e_toolcall.py "$BIN/stopbard" research/agentdojo/policies/banking

step "research harness: unit tests + free dry run vs live stopbard on the frozen bundle (CS-503)"
H=research/agentdojo
[[ -x "$H/.venv/bin/python" ]] || { python3 -m venv "$H/.venv" && "$H/.venv/bin/pip" -q install -r "$H/requirements.lock"; }
(cd "$H" && .venv/bin/python -m unittest discover -s tests -q)
echo '{"limits_disabled": true}' > "$BIN/pilot-world.json"
"$BIN/stopbard" -listen 127.0.0.1:0 -dev-world "$BIN/pilot-world.json" -policies "$H/policies/banking" -state-dir "$BIN/pilot-state" >"$BIN/pilot-out" 2>"$BIN/pilot-log" &
PID=$!
for _ in $(seq 50); do grep -q 'listening on' "$BIN/pilot-out" 2>/dev/null && break; sleep 0.1; done
PADDR="$(sed -n 's/.*listening on //p' "$BIN/pilot-out")"
(cd "$H" && .venv/bin/python -m harness.run --dry-run --limit 3 --stopbard "http://$PADDR" --out "$BIN/pilot-results" >/dev/null)
python3 - "$BIN/pilot-results" <<'PY'
import glob, json, sys
d = glob.glob(sys.argv[1] + "/*_dry-run")[0]
run = json.load(open(d + "/run.json"))
calls = [json.loads(l) for l in open(d + "/A2/calls.jsonl")]
done = [json.loads(l)["user_task"] for l in open(d + "/progress.jsonl")]
assert all(s["enforced_bundle_hash"] == run["frozen_bundle_hash"] for s in run["segments"]), "A2 not on the frozen bundle"
assert calls and not any(c["infra_error"] for c in calls), "gate infra errors"
assert len(done) == 3, f"expected 3 finished user tasks, got {done}"
for arm in ("A0", "A2"):
    eps = [json.loads(l) for l in open(f"{d}/{arm}/episodes.jsonl")]
    assert {e["user_task"] for e in eps} == set(done), f"{arm} episodes don't match finished tasks"
    traces = glob.glob(f"{d}/agentdojo_logs/*-{arm}/banking/*/*/*.json")
    assert len(traces) == len(eps), f"{arm}: {len(traces)} traces for {len(eps)} episodes (arms must not share trace paths)"
print(f"ok   dry run: A0+A2 interleaved, {len(calls)} gated calls on frozen bundle {run['frozen_bundle_hash'][:19]}…, 0 infra errors")
PY
kill -TERM "$PID"; wait "$PID" || true
PID=

step "wallet agent: unit tests + AgentKit -> StopbarWalletProvider -> stopbard (gatekeeper) -> Anvil (CS-512/513)"
W=research/walletagent
if command -v anvil >/dev/null; then
  [[ -x "$W/.venv/bin/python" ]] || { python3 -m venv "$W/.venv" && "$W/.venv/bin/pip" -q install -r "$W/requirements.lock"; }
  (cd "$W" && .venv/bin/python -m unittest discover -s tests -q)
  "$W/.venv/bin/python" "$W/e2e_wallet.py" "$BIN/stopbard"
else
  echo "SKIP wallet agent e2e: anvil not installed (brew install foundry). This stage is local-only; CI does not run it."
fi

step "corpus attacks through live stopbard: real engine + policy, dev stubs (CS-111/112)"
python3 scripts/e2e_corpus.py "$BIN/stopbard" "$BIN/stopbar"

# Tool pins; keep in step with .github/workflows/ci.yml.
GOLANGCI_LINT=v2.15.0
GOVULNCHECK=v1.9.0

# Lint is required: a skipped lint let a CI failure through once. A stale
# binary (e.g. v1) fails too, since its findings differ from CI's.
PATH="$(go env GOPATH)/bin:$PATH"
if ! golangci-lint --version 2>/dev/null | grep -q "version ${GOLANGCI_LINT#v} "; then
  echo "golangci-lint ${GOLANGCI_LINT} required (CI version). Install from the repo root:"
  echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT}"
  exit 1
fi
step golangci-lint; golangci-lint run
if [[ "${OFFLINE:-0}" != 1 ]]; then
  step govulncheck; go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK}" ./...
fi

# Pending stages, enabled as they land:
#   CS-121+     replace dev stubs with real limiter/enrichers; replay stays green
#   CS-191..193 full corpus replay (test/replay)

printf '\nE2E OK\n'
