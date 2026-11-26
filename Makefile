.PHONY: build test fuzz vet fmt check e2e demo demo-live demo-testnet bench
build: ; go build ./...
demo: ; ./scripts/demo.sh
demo-live: ; ./scripts/demo-live.sh
demo-testnet: ; ./scripts/demo-testnet.sh
test: ; go test -race -count=1 ./...
fuzz: ; go test -run='^$$' -fuzz=FuzzTransformIdempotent -fuzztime=60s ./internal/canon/
vet: ; go vet ./...
fmt: ; gofmt -w .
check: vet test
e2e: ; ./scripts/e2e.sh
# CS-197: component micro-benchmarks, then the sidecar load harness (docs/benchmarks.md).
bench:
	go test -run='^$$' -bench=. -benchmem ./internal/canon ./internal/decision ./internal/decode/evm ./internal/policy ./internal/limiter ./internal/audit
	go build -o bin/ ./cmd/stopbard ./scripts/bench
	sync # flush the build's dirty pages first, so kernel writeback does not land mid-run
	bin/bench -stopbard bin/stopbard -rate $(or $(RATE),1000) -duration $(or $(DURATION),60s)
