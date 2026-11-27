# Benchmarks (CS-197)

Latency and throughput of the `stopbard` sidecar against the PRD's targets:

| ID | Requirement | Target |
|---|---|---|
| NFR-1 | Allow-path latency added | p99 < 25 ms (sidecar), < 50 ms (networked) |
| NFR-2 | Throughput (single node) | ≥ 1,000 evaluations/sec |

(Quoted verbatim from [PRD §8](PRD.md).) The bar for CS-197 is p99 < 25 ms for the sidecar at 1,000 requests/s, sustained for 60 s, together with ≥ 1,000 evaluations/s.

## Status

On a GitHub-hosted Linux runner:

- **NFR-2 is met.** In each of the three official 60 s runs, 1,000 requests/s were answered on schedule with 0 errors, and at most 163 requests were ever in flight.
- **NFR-1 p99: met in 2 of 3 runs on a shared runner; tail from noisy neighbours.** p99 was 23.19 ms, 21.13 ms and **28.22 ms** (run 45859183281). That is the whole claim: it is not shown to hold on every run.
- On macOS with full fsync, the earlier four-commit design could not get under about 25 ms even when idle. The current design measured 23.4 ms p99 there, but only on a dev machine, so that number is not official.

Official numbers come only from GitHub-hosted runners or from an idle machine whose specs are written here. Every number below says where it was measured. A number from a loaded machine is never evidence that a target is met.

## What is measured

`make bench` runs two things:

1. **Component micro-benchmarks** (`testing.B`, next to the code): JCS canonicalisation, `PayloadHash`, the EVM decoder, Cedar evaluation of the starter bundle, limiter `Reserve`, decision-token signing, and one durable audit append.
2. **The load harness** (`scripts/bench`, stdlib only). It starts a real `stopbard` configured the way a sidecar runs:
   - `-dev-world` engine: the real gateway, engine, Cedar starter bundle, limiter, decision signer and audit log. Prices and balances come from the static dev stub.
   - Authentication on (`-auth-keys`): every request carries a bearer API key.
   - Gatekeeper mode (`-dev-wallet`): every allow is verified by the adapter, which consumes the token and signs the transaction. The harness checks that `signed_tx` is present.
   - A persistent `-state-dir`, so every commit is fsynced.
   - Caps on: a per-transaction wallet cap, a 1 h wallet cap and a tenant circuit breaker. They are sized so a run never reaches them, but every allow still reserves and commits.

   The harness drives `POST /v1/evaluate` **open loop** at a constant rate. Requests go out on a fixed schedule whether or not earlier ones have answered, and latency runs from each request's *scheduled* send time, so a stall shows up in the tail instead of being hidden by coordinated omission.

   The mix is 80% allow, 10% escalate and 10% deny, using corpus shapes:
   - allow: a small transfer to a known destination;
   - escalate: CS-2026-0002, the whole balance, which escalates on `large-share-of-balance`;
   - deny: CS-2026-0010, a Safe delegatecall, denied by `delegatecall`.

   Every request gets a fresh nonce and `issued_at`, as `scripts/corpus_template.py` does for the corpus replay. A response whose status and outcome are not the expected 200/202/403 counts as an error, and its reason codes are printed. The first 5 s are warm-up and are not measured. The harness also prints which seconds the tail comes from.

```bash
make bench                              # micro-benchmarks, then 1,000 rps for 60 s
make bench RATE=1000 DURATION=120s      # a longer run
go run ./scripts/bench -h               # harness flags (rate, duration, warm-up, mix, -state-dir to keep state and logs)
```

`make bench` builds both binaries and runs `sync` before the load starts, so kernel writeback of the build does not land in the middle of the run. The official measurement is the `bench` workflow (`gh workflow run bench.yml`, or Actions → bench → Run workflow). It runs `make bench` on `ubuntu-latest` and first prints the runner's CPU, memory and disk. CI's required `go` job runs only a 5 s, 100 rps **correctness smoke** of the harness. It fails on any wrong outcome or error and is not a latency gate.

### Official method (later)

These runs were made on a shared 4-vCPU GitHub runner, where the harness and `stopbard` compete for CPU and the disk is shared with other tenants. The official method for a release claim is:
- a dedicated machine (not a shared VM) running only `stopbard`;
- a separate load-generator host running `scripts/bench` against it over the network (the harness needs a mode that targets a remote `stopbard`, which it does not have yet: CS-199);
- the hardware, kernel, file system and disk recorded with the numbers.

Until such a run exists, the numbers here are shared-runner numbers and are labelled as such.

## Results

### Official: GitHub-hosted runner, current code

Run [45859183281](https://github.com/NikhilSetiya/stopbar/actions/runs/45859183281). Environment:
- Runner: `ubuntu-latest` (image ubuntu-26.04, 20261116.202.1), 4 vCPU Intel Xeon Platinum 8573C, 15 GiB RAM, Azure VM disk (ext4).
- Go 1.26.11. The harness and `stopbard` share the runner.
- Run 1 is `make bench`; runs 2 and 3 repeat the harness straight after it, on the same runner.

| Run | Rate, duration | p50 | p90 | p99 | p99.9 | max | errors | max in flight |
|---|---|---|---|---|---|---|---|---|
| 1 (`make bench`) | 1,000 rps, 60 s | 5.25 ms | 13.04 ms | **23.19 ms** | 63.72 ms | 113.54 ms | 0 / 60,000 | 114 |
| 2 | 1,000 rps, 60 s | 5.27 ms | 12.65 ms | **21.13 ms** | 37.26 ms | 58.79 ms | 0 / 60,000 | 58 |
| 3 | 1,000 rps, 60 s | 5.21 ms | 13.19 ms | **28.22 ms** | 114.14 ms | 163.42 ms | 0 / 60,000 | 163 |

The same code on a different runner, run [45858269289](https://github.com/NikhilSetiya/stopbar/actions/runs/45858269289) (4 vCPU AMD EPYC 7763, before `make bench` synced): p99 21.17 ms and 253.22 ms. The 253 ms run is the first run on that runner, and its tail is one stall at seconds 21–22. The same pattern hit the first run on several fresh runners before `sync` was added (see the history below).

### Component micro-benchmarks

The official column is the runner from run 45859183281 (environment above). The M3 column was measured on a dev machine under load from other builds, so it is **not official**. It is shown only because the fsync cost on macOS is so different. M3: Apple M3, 8 cores, 16 GB, macOS 26.6.2, Go 1.26.11.

| Benchmark | CI runner (official) | Apple M3 (dev machine under load, not official) | Allocs/op |
|---|---|---|---|
| `canon.BenchmarkTransform` (EVM request fixture) | 103.5 µs | 34 µs | 711 |
| `decision.BenchmarkPayloadHash` | 25.0 µs | 15 µs | 292 |
| `decision.BenchmarkSign` (v2 token, Ed25519) | 61.8 µs | 40 µs | 474 |
| `evm.BenchmarkDecode/transfer` | 1.7 µs | 1.0 µs | 26 |
| `evm.BenchmarkDecode/safe_multisend` | 6.2 µs | 7.5 µs | 78 |
| `policy.BenchmarkEvaluate/allow` (starter bundle) | 11.8 µs | 8.2 µs | 135 |
| `policy.BenchmarkEvaluate/escalate` | 11.8 µs | 10 µs | 137 |
| `limiter.BenchmarkReserve` (in memory) | 7.9 µs | 4.6 µs | 83 |
| `audit.BenchmarkAppend` (one fsynced bbolt transaction) | **0.43 ms** | **6.2 ms** | 422 |

Everything except the durable write costs tens of microseconds, about 0.2 ms of CPU per evaluation in total. What decides latency is the durable write: how many there are per request and how much each one writes.

### History: how the numbers got here (all GitHub-hosted, `ubuntu-latest`, 4 vCPU)

| Code | Run | Runner CPU | 1,000 rps, 60 s: p99 per run | errors |
|---|---|---|---|---|
| Four commits per allow, group commit | [45664030674](https://github.com/NikhilSetiya/stopbar/actions/runs/45664030674) | EPYC 9V74 | 1,080.54 ms | 0 |
| same | [45807052850](https://github.com/NikhilSetiya/stopbar/actions/runs/45807052850) | — | 2.33–3.23 s (4 runs) | 24 allow→deny (run 1) |
| same, plus the limiter in-flight fix, reason codes captured | [45813524617](https://github.com/NikhilSetiya/stopbar/actions/runs/45813524617) | Xeon 6975P-C | 345.23 ms, 21.65 ms | 0 |
| One transaction per evaluation, smaller records | [45854833633](https://github.com/NikhilSetiya/stopbar/actions/runs/45854833633) | EPYC 9V45 | 239.58 ms, 9.08 ms | 0 |
| same | [45855371799](https://github.com/NikhilSetiya/stopbar/actions/runs/45855371799) | EPYC 9V74 | 1,154 ms, 1,535 ms, 1,760 ms | 0 |
| same | [45856103978](https://github.com/NikhilSetiya/stopbar/actions/runs/45856103978) | EPYC 7763 | 272.95 ms, 30.43 ms | 0 |
| plus time-ordered state keys | [45857475500](https://github.com/NikhilSetiya/stopbar/actions/runs/45857475500) | EPYC 7763 | 28.28, 28.18, 28.57 ms | 0 |
| plus filled pages (current code) | [45858269289](https://github.com/NikhilSetiya/stopbar/actions/runs/45858269289) | EPYC 7763 | 253.22 ms (first run, stall at 21–22 s), 21.17 ms | 0 |
| current code, `make bench` with `sync` | [45859183281](https://github.com/NikhilSetiya/stopbar/actions/runs/45859183281) | Xeon Platinum 8573C | 23.19, 21.13, 28.22 ms | 0 |

Older sweep at 30 s per rate, four-commit code ([45806473199](https://github.com/NikhilSetiya/stopbar/actions/runs/45806473199), EPYC 9V74): p99 15.72 ms at 500 rps and 155.02 ms at 1,000 rps.

The runner hardware varies from run to run and so does the result. On the EPYC 9V74 runner (45855371799), one transaction per evaluation still gave over 1 s p99. That runner type was not drawn again after the later storage changes, so they are unmeasured on it.

## The allow→deny cases

Run 45807052850 answered 24 allows with 403 deny. That run kept no stopbard logs, so its own reason codes are lost. The rerun with reason codes captured (45813524617) had none. The cause was established from the stopbard logs of local runs that overloaded the same code and showed the same symptom:
- 1,821 and 69 entries `fail closed … FAIL_CLOSED_LIMITER … timed out after 1s: context deadline exceeded`;
- 398 entries `release after failed allow path … timed out after 1s`.

The limiter stage's `Reserve` included the durable write of the reservation and its decision record. When the fsync queue was more than a second deep, the engine's 1 s stage timeout fired and the engine denied the request, which is the designed fail-closed behaviour (LLD §12). The best-effort release timed out too, so the reservation lapsed with its TTL, which is conservative. This was not a bug in the decision logic. It was write load pushing a stage past its budget.

With one transaction per evaluation, no stage waits for the disk any more. The unit commits after the engine has finished, with no stage timeout around it. A failed commit answers 500 and records nothing. So this path no longer fires because of write load.

## What changed and why (ADR 0009)

The profile showed that CPU is cheap and every durable write is expensive. In order:

1. **Group commit** (`store.DB.Update`). Writers that arrive while an fsync is in flight share the next transaction. Each caller returns only after its own transaction is fsynced. If a group fails, nothing in it is written and each writer is re-run alone.
2. **No lock held across an fsync.** The nonce store, the limiter and the audit log use in-memory holds that are rolled back if the write fails. Before this, throughput collapsed at about 50 rps on macOS.
3. **One transaction per evaluation** (`store.Unit`).
   - These writes of one `/v1/evaluate` commit together, with one fsync: the nonce and request record; the reservation, pending escalation or deny record; the spent token; and the commit or release.
   - The answer is written only after the unit is durable. A failed unit writes nothing, rolls back every in-memory hold and answers 500.
   - Before this, an allow waited for four fsyncs in a row.
4. **Smaller decision records.** The decision record no longer repeats the request, which stays in the request record. Audit bytes per request went from 5.2 KB to 3.7 KB. Audit hash v1 is unchanged.
5. **Time-ordered state keys.** Nonces and spent tokens are keyed by expiry and reservations by creation, so inserts append instead of rewriting a random leaf page each. Expired entries are compacted from the front, inside the unit. The audit log is never compacted. Entries in the old layout are migrated on open.
6. **Filled pages** (`FillPercent`) in the append-ordered buckets. The state file after 65,000 requests went from 520 MB to 369 MB.
7. **`sync` before the run** in `make bench`. This is measurement hygiene, not a product change.

Tried and not adopted: bbolt `NoFreelistSync` with the map freelist. It wrote about 5–15% fewer bytes, with no p99 difference within run-to-run noise (45856103978, 45858269289).

Unchanged: fail-closed mapping, every audit record in the same transaction as its state change, fsync on every commit (`NoSync` stays off), and the limiter's cap property under concurrency, which is now also tested against a slow store that fails one write in ten.

## Gap statement

- **NFR-2 (≥ 1,000 evaluations/s): met** on the GitHub-hosted runner. Each of three 60 s runs at 1,000 rps kept the schedule with 0 errors.
- **NFR-1 (p99 < 25 ms sidecar): met in 2 of 3 runs on a shared runner; tail from noisy neighbours** (23.19 ms, 21.13 ms, 28.22 ms). The tail is a few seconds per run with requests over 100 ms, on a shared 4-vCPU VM where the harness competes with `stopbard`. A dedicated-machine run (Official method, above) has not been made.
- **Bytes written per request.** About 42 KB per request still reaches the disk: about 2.7 GB for 65,000 requests in 45858269289. The audit records themselves are 3.7 KB; the rest is bbolt rewriting each touched B+tree path on every commit. Reducing that further would mean a different storage engine (an append-only log), which is a separate design decision.
- **Runner variance.** On one runner type (EPYC 9V74), earlier code gave p99 over 1 s, and the latest storage changes are unmeasured there.
- **macOS:** 23.4 ms p99 at 1,000 rps on the M3 dev machine with full fsync, under moderate load (load average about 3.6). This is not official.
