# Benchmarks (CS-197)

Latency and throughput of the `stopbard` sidecar against the PRD's targets:

| ID | Requirement | Target |
|---|---|---|
| NFR-1 | Allow-path latency added | p99 < 25 ms (sidecar), < 50 ms (networked) |
| NFR-2 | Throughput (single node) | ≥ 1,000 evaluations/sec |

(Quoted verbatim from [PRD §8](PRD.md).) The acceptance bar for CS-197 is p99 < 25 ms for the sidecar at 1,000 requests/s.

**Status: neither target is met at 1,000 rps.** On a GitHub-hosted runner the sidecar answers every request correctly at 1,000 rps (0 errors), but p99 is 155 ms to 3.2 s, depending on the run and its length. At 500 rps for 30 s, p99 was 15.7 ms. Official numbers come only from CI runners or from an idle machine whose specs are written down here, and every number below says where it was measured. Numbers from a loaded machine are never evidence that a target is met.

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

### Official: GitHub-hosted runner

Environment for every run below: `ubuntu-latest` (image ubuntu-26.04, 20261116.202.1), 4 vCPU AMD EPYC 9V74, 15 GiB RAM, Azure VM disk (`/dev/root`, ext4), Linux 7.0.0-1020-azure, Go 1.26.11. The harness and `stopbard` share the runner. Mix 80/10/10 allow/escalate/deny, 5 s warm-up not measured, configuration as above. The stopbard code is the same in all three runs (commit 4083bd4; later commits changed only the harness's report and directory handling). The runs were made from a scratch branch, because a `workflow_dispatch` workflow can be dispatched only once it is on `main`.

| Run | Rate, duration | p50 | p90 | p99 | p99.9 | max | errors |
|---|---|---|---|---|---|---|---|
| [45664030674](https://github.com/NikhilSetiya/stopbar/actions/runs/45664030674) (`make bench`) | 1,000 rps, 60 s | 11.18 ms | 41.99 ms | **1,080.54 ms** | 1,366.93 ms | 1,528.77 ms | 0 / 60,000 |
| [45806473199](https://github.com/NikhilSetiya/stopbar/actions/runs/45806473199) (sweep) | 250 rps, 30 s | 5.03 ms | 31.43 ms | 554.80 ms | 697.27 ms | 745.48 ms | 0 / 7,500 |
| same run | 500 rps, 30 s | 10.33 ms | 12.73 ms | **15.72 ms** | 85.41 ms | 107.75 ms | 0 / 15,000 |
| same run | 750 rps, 30 s | 15.72 ms | 20.69 ms | 58.25 ms | 103.48 ms | 126.51 ms | 0 / 22,500 |
| same run | 1,000 rps, 30 s | 33.34 ms | 51.42 ms | **155.02 ms** | 195.09 ms | 244.56 ms | 0 / 30,000 |
| [45807052850](https://github.com/NikhilSetiya/stopbar/actions/runs/45807052850) (4 back-to-back runs) | 1,000 rps, 60 s each | 516–1,971 ms | 1.75–2.86 s | **2.33–3.23 s** | 2.55–3.49 s | 2.78–3.75 s | 24 / 240,000 (first run only) |

How to read this:

- **Correctness held at every rate.** All 375,000 requests got the expected outcome, except 24 in the first run of 45807052850. Those 24 allows were answered 403 deny while the service was seconds behind. That is the designed fail-closed behaviour when a stage times out (the reason codes were not captured in that run).
- **Runners vary a lot.** The 250 rps run had a 4-second stall (seconds 20–23 of the run), and 45807052850 was much slower than the other two runs.
- **At 1,000 rps the service falls behind as the state file grows.** In the 60 s runs, latency per second climbs steadily after about 15–20 s (the harness prints which seconds the tail comes from). The queue grows, so the sustained service rate on these runners is below 1,000/s once the file reaches a few hundred MB. 45807052850 also compared bbolt's `NoFreelistSync` + map freelist with the default: no difference (p99 2.33–2.40 s against 2.35–3.23 s), so the freelist is not the cause, and the option was not adopted.

### Component micro-benchmarks

The official column is the GitHub-hosted runner from run [45664030674](https://github.com/NikhilSetiya/stopbar/actions/runs/45664030674) (environment above). The M3 column was measured on a dev machine under load from other builds, so it is **not official**. It is shown only because the fsync cost on macOS differs so much. M3: Apple M3, 8 cores, 16 GB, macOS 26.6.2, Go 1.26.11.

| Benchmark | CI runner (official) | Apple M3 (dev machine under load, not official) | Allocs/op |
|---|---|---|---|
| `canon.BenchmarkTransform` (EVM request fixture) | 48.6 µs | 34 µs | 711 |
| `decision.BenchmarkPayloadHash` | 20.1 µs | 15 µs | 292 |
| `decision.BenchmarkSign` (v2 token, Ed25519) | 54.6 µs | 40 µs | 476 |
| `evm.BenchmarkDecode/transfer` | 1.4 µs | 1.0 µs | 26 |
| `evm.BenchmarkDecode/safe_multisend` | 4.9 µs | 7.5 µs | 78 |
| `policy.BenchmarkEvaluate/allow` (starter bundle) | 9.8 µs | 8.2 µs | 135 |
| `policy.BenchmarkEvaluate/escalate` | 9.8 µs | 10 µs | 137 |
| `limiter.BenchmarkReserve` (in memory) | 7.3 µs | 4.6 µs | 80 |
| `audit.BenchmarkAppend` (one fsynced bbolt transaction) | **0.28 ms** | **6.2 ms** | 411 |

Everything except the durable write costs tens of microseconds. One fsynced bbolt transaction costs 0.28 ms on the Linux runner (`fdatasync`) and 6.2 ms on macOS (`F_FULLFSYNC`).

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

## Where the remaining time goes

Each request writes about 5.2 KB of audit records (measured with `stopbar audit export` over a harness run): request 1.0 KB, allow decision 3.8 KB plus commit 0.5 KB, escalate 3.0 KB, deny 5.3 KB. The decision records carry the full request, decision and enriched context. It also writes random-keyed entries to the nonce, spent-token, reservation and pending-escalation B+trees. bbolt is copy-on-write, so each random insert rewrites a leaf page and its parents. The file grows about 10 KB per request (353 MB after 35,000 requests in the sweep), and the pages written per commit grow with it. Every allow pays four commits in sequence. CPU per request is about 0.2 ms (micro-benchmarks above), so the limit is the volume of durable writes on the runner's disk, not computation.

Options not taken here, because each changes a design decision rather than tuning the implementation: fewer sequential commits per allow (for example, writing the spent token and the commit together), smaller decision records (the audit content is specified in LLD §11), or a storage engine with an append-only log. Each would need its own task and design review.

## Gap statement

- **NFR-1 (p99 < 25 ms sidecar): not met at 1,000 rps.** On the GitHub-hosted runner, p99 at 1,000 rps was 155 ms (30 s), 1,081 ms (60 s), and 2.3–3.2 s (60 s, slower runner). It was met at 500 rps for 30 s (15.7 ms). On macOS with `F_FULLFSYNC` it cannot be met even when idle: the floor is four sequential full fsyncs, about 25 ms on an Apple M3.
- **NFR-2 (≥ 1,000 evaluations/sec): not demonstrated as sustained.** Every request was answered with no errors in two of the three 1,000 rps runs, but the growing latency in the 60 s runs shows the sustained service rate on this runner is below 1,000/s once the state file is a few hundred MB.
- The `bench` workflow (`gh workflow run bench.yml`, available once merged) reruns the official measurement. Record any new run here with its link.
