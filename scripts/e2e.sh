#!/usr/bin/env bash
# End-to-end evaluation gate. Run after every build step (`make e2e`).
# Mirrors CI, then runs every deeper end-to-end check that exists so far.
# Extend it in the same change that adds a pipeline stage.
set -euo pipefail
cd "$(dirname "$0")/.."

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
step "fuzz smoke (canonicaliser)"
go test -run='^$' -fuzz=FuzzTransformIdempotent -fuzztime="${FUZZTIME:-10s}" ./internal/canon/

step "policy: starter pack validates and combines (CS-007)"
go test -count=1 -run 'TestSpike' ./internal/policy/
go test -run='^$' -bench=BenchmarkSpikeEvaluate -benchtime=20000x ./internal/policy/ | grep Benchmark

step "decision token v1: vectors fresh and verify (CS-008)"
go test -count=1 -run 'TestDecisionTokenVectors|TestPayloadHash' ./internal/decision/

step "corpus + spec fixtures against schemas"
python3 scripts/validate_corpus.py

step "binaries start"
go run ./cmd/stopbard
go run ./cmd/stopbar

# Lint is required: a skipped lint let a CI failure through once.
PATH="$(go env GOPATH)/bin:$PATH"
command -v golangci-lint >/dev/null || {
  echo "golangci-lint missing. Install the CI version:"
  echo "  GOTOOLCHAIN=local go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8"
  exit 1
}
step golangci-lint; golangci-lint run
if [[ "${OFFLINE:-0}" != 1 ]]; then
  step govulncheck; GOTOOLCHAIN=local go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
fi

# Pending stages, enabled as they land:
#   CS-161/162  real signer + adapter verifier pass spec/vectors/decision-token-v1.json
#   CS-101/104  POST every corpus request to a running stopbard, assert outcome
#   CS-171      audit chain verify over the replay run
#   CS-191..193 full corpus replay (test/replay)

printf '\nE2E OK\n'
