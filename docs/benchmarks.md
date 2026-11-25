# Benchmarks (CS-197)

Latency and throughput of the `stopbard` sidecar against the PRD's targets:

| ID | Requirement | Target |
|---|---|---|
| NFR-1 | Allow-path latency added | p99 < 25 ms (sidecar), < 50 ms (networked) |
| NFR-2 | Throughput (single node) | ≥ 1,000 evaluations/sec |

(Quoted verbatim from [PRD §8](PRD.md).) The acceptance bar for CS-197 is p99 < 25 ms for the sidecar at 1,000 requests/s.

**Status: the official run has not happened yet.** The official numbers come only from the `bench` workflow on a GitHub-hosted runner, or from an idle machine whose specs are written down here. Every number below says where it was measured. Numbers from a loaded machine are never evidence that a target is met.

## What is measured

`make bench` runs two things:

1. **Component micro-benchmarks** (`testing.B`, next to the code): JCS canonicalisation, `PayloadHash`, the EVM decoder, Cedar evaluation of the starter bundle, limiter `Reserve`, decision-token signing, and one durable audit append.
2. **The load harness** (`scripts/bench`, stdlib only). It starts a real `stopbard` configured the way a sidecar runs:
   - `-dev-world` engine: the real gateway, engine, Cedar starter bundle, limiter, decision signer and audit log. Prices and balances come from the static dev stub.
   - Authentication on (`-auth-keys`). Every request carries a bearer API key.
   - Gatekeeper mode (`-dev-wallet`). Every allow is verified by the adapter, which consumes the token and signs the transaction; the harness checks that `signed_tx` is present.
   - A persistent `-state-dir`, so every bbolt commit is fsynced. That covers the nonce, the reservation with its audit record, the spent token, the commit, and the escalate and deny records.
   - Caps on: a per-transaction wallet cap, a 1h wallet cap and a tenant circuit breaker. They are sized so a run never reaches them, but every allow still reserves and commits.

   The harness drives `POST /v1/evaluate` **open loop** at a constant rate. Requests go out on a fixed schedule whether or not earlier ones have answered, and latency runs from each request's *scheduled* send time. A stall therefore shows up in the tail instead of being hidden by coordinated omission. The mix is 80% allow, 10% escalate and 10% deny, using corpus shapes: a small transfer to a known destination, CS-2026-0002 (whole balance, which escalates on `large-share-of-balance`) and CS-2026-0010 (a Safe delegatecall, denied by `delegatecall`). Every request gets a fresh nonce and `issued_at`, as `scripts/corpus_template.py` does for the corpus replay. Any response whose status and outcome differ from the expected 200/202/403 counts as an error. The first 5 s are warm-up and are not measured.

```bash
make bench                              # micro-benchmarks + 1,000 rps for 60 s
make bench RATE=1000 DURATION=120s      # longer run
go run ./scripts/bench -h               # harness flags (rate, duration, warm-up, mix, -state-dir to keep state and logs)
```

The official run is `gh workflow run bench.yml` (or Actions → bench → Run workflow), which runs `make bench` on `ubuntu-latest` and prints the runner's CPU, memory and disk first. CI's required `go` job runs only a 5-second, 100 rps **correctness smoke** of the harness. It fails on any wrong outcome or error and is not a latency gate.

## Results

### Official

Not run yet. After this lands, run the `bench` workflow and record its p50/p90/p99/p99.9/max, error rate and run link here.

### Component micro-benchmarks

Measured on a dev machine under load from other builds, so **not official**. They are shown because per-call CPU costs are an order of magnitude apart from the fsync cost, and that gap is what the conclusions below rest on. Hardware: Apple M3, 8 cores, 16 GB, macOS 26.6.2, Go 1.26.11.

| Benchmark | Time/op | Allocs/op |
|---|---|---|
| `canon.BenchmarkTransform` (EVM request fixture) | 34 µs | 711 |
| `decision.BenchmarkPayloadHash` | 15 µs | 292 |
| `decision.BenchmarkSign` (v2 token, Ed25519) | 40 µs | 476 |
| `evm.BenchmarkDecode/transfer` | 1.0 µs | 26 |
| `evm.BenchmarkDecode/safe_multisend` | 7.5 µs | 78 |
| `policy.BenchmarkEvaluate/allow` (starter bundle) | 8.2 µs | 135 |
| `policy.BenchmarkEvaluate/escalate` | 10 µs | 137 |
| `limiter.BenchmarkReserve` (in memory) | 4.6 µs | 80 |
| `audit.BenchmarkAppend` (one fsynced bbolt transaction) | **6.2 ms** | 411 |

Everything except the durable write costs tens of microseconds. One fsynced transaction costs milliseconds.

### Harness: dev machine under load, not official

Same Apple M3 laptop, with six other agents building and testing on it (load average 20–34 on 8 cores). These runs informed the engineering below. They say nothing about whether the targets are met.

- At 5 rps (no queueing), an allow took **27 ms p50**. On macOS, Go's `File.Sync` issues `F_FULLFSYNC`, which flushes the drive's cache and costs about 6 ms per bbolt commit on this machine. An allow needs four sequential durable commits: the nonce, the reservation and its decision record, the spent token, and the commit. That puts the floor at about 25 ms before any queueing. **On macOS with full fsync, NFR-1's 25 ms p99 cannot be met by this design, idle or not.** Linux `fdatasync` on a local SSD is typically far cheaper; the official Linux run will show by how much.
- Before the change below, the service collapsed at about **50 rps** (p50 about 1 s): every component held its own lock across its fsync, so writes from all requests queued one fsync at a time.
- After the change, the same machine under the same load kept up at 200 rps (p99 214 ms, no errors) and still saturated at 1,000 rps. Load from other processes was enough to saturate it at 1,000 rps even with fsync turned off entirely, which was a diagnostic build only. So these runs cannot separate this design's limit from the machine's.

## Profile findings and what changed

A goroutine dump under load (SIGQUIT) showed almost every request blocked on a mutex in front of an fsync: the nonce store's, the limiter's, the audit log's, and finally bbolt's single writer. CPU was not the bottleneck; the micro-benchmarks above agree. The fix keeps every durability guarantee:

- **Group commit in `internal/store`.** `DB.Update` still returns only after its own transaction is committed and fsynced. Writers that arrive while an fsync is in flight are committed together in the next transaction, and a lone writer commits at once with no added delay. Each writer's state change and audit record stay in the same transaction. If the group fails (a writer errs or panics, or the commit or fsync fails), nothing in it is written and each writer is re-run alone, so its result is its own. `TestGroupCommitIsolatesFailures` and `TestGroupCommitFailureFailsEveryCaller` cover this: after an injected commit failure, every writer in the group gets the error and nothing is on disk.
- **No lock held across an fsync** in the nonce store, the limiter or the audit log, so their writes can share a group:
  - The nonce store marks a key *pending* before writing it. A concurrent duplicate is refused (fail closed), and a key reports fresh only once it is durable.
  - The limiter *holds* capacity before the write (counted at once, so concurrent checks are conservative), gives it back if the write fails, and frees released capacity only after the release is durable. An operation on an ID whose write is in flight waits for that write. The concurrency property test now also runs against a slow store that fails one write in ten, and no cap is ever exceeded (`TestConcurrentReservationsNeverExceedCaps`).
  - The audit log's own mutex was redundant: the chain head is read inside the write transaction.

Not changed: fail-closed mapping, one transaction per audit record and its state change, and fsync on every commit (`NoSync` stays off). See LLD §7.3a and §11.

## Gap statement

- **NFR-1 (p99 < 25 ms sidecar):** unverified on Linux until the official run. Not achievable on macOS with `F_FULLFSYNC`: the floor is four sequential full fsyncs, about 25 ms on an Apple M3.
- **NFR-2 (≥ 1,000 evaluations/sec):** unverified until the official run.
