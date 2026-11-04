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
step "fuzz smoke (canonicaliser, gateway)"
go test -run='^$' -fuzz=FuzzTransformIdempotent -fuzztime="${FUZZTIME:-10s}" ./internal/canon/
go test -run='^$' -fuzz=FuzzEvaluate -fuzztime="${FUZZTIME:-10s}" ./internal/gateway/

step "policy: starter pack validates and combines (CS-007)"
go test -count=1 -run 'TestSpike' ./internal/policy/
go test -run='^$' -bench=BenchmarkSpikeEvaluate -benchtime=20000x ./internal/policy/ | grep Benchmark

step "decision token v1: vectors fresh and verify (CS-008)"
go test -count=1 -run 'TestDecisionTokenVectors|TestPayloadHash' ./internal/decision/

step "corpus + spec fixtures against schemas"
python3 scripts/validate_corpus.py

step "binaries"
BIN="$(mktemp -d)"
trap 'kill "${PID:-}" 2>/dev/null || true; rm -rf "$BIN"' EXIT
go build -o "$BIN/" ./cmd/...
"$BIN/stopbar"
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
#   CS-161/162  real signer + adapter verifier pass spec/vectors/decision-token-v1.json
#   CS-104      corpus requests through stopbard assert expected outcome, not 503
#   CS-171      audit chain verify over the replay run
#   CS-191..193 full corpus replay (test/replay)

printf '\nE2E OK\n'
