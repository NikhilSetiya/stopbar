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
#   CS-101/104  POST every corpus request to a running stopbard, assert outcome
#   CS-171      audit chain verify over the replay run
#   CS-191..193 full corpus replay (test/replay)

printf '\nE2E OK\n'
