# ADR 0009: One state transaction per evaluation, group commit, smaller decision records

- Status: **Accepted**
- Date: 2026-11-26
- Task: CS-197 (issue #49), benchmarks against NFR-1/NFR-2
- Builds on: LLD §7.3a (limiter durability), LLD §11 (each audit record in the same transaction as its state change)

## Context

The CS-197 load harness drives a real sidecar `stopbard` (auth on, gatekeeper signing, persistent state dir) at 1,000 rps. Profiling it showed that the cost was durable writes, not CPU: an evaluation costs about 0.2 ms of CPU. Every fsynced bbolt commit costs 0.28 ms on a GitHub Linux runner and 6.2 ms on macOS (`F_FULLFSYNC`). The evaluate path made several separate durable commits, one after another:

- An allow made four: the nonce with its request record, the reservation with its decision record, the gatekeeper's spent token, and the commit with its commit record.
- A deny or an escalate made two.

Each component also held its own lock across its fsync, so the writes of all requests queued one fsync at a time. Throughput collapsed at about 50 rps on macOS. Group commit and moving fsync out of the locks fixed throughput. But each allow still waited for four fsync cycles, and p99 at 1,000 rps on Linux was 155 ms to 3 s. When the queue got deep, the limiter stage exceeded the engine's 1 s stage timeout and allows were denied with `FAIL_CLOSED_LIMITER`. That is designed fail-closed behaviour, but it was caused by write load.

Each request also wrote about 5.2 KB of audit records. The decision record repeated the full request twice: once as `request`, and again inside the enriched `context`.

## Decision

1. **Group commit (`store.DB.Update`).** Writers that arrive while an fsync is in flight share the next transaction, and a lone writer commits at once. Each caller returns only after its own transaction is committed and fsynced. If a group fails, nothing in it is written and each writer is re-run alone, so its result is its own.

2. **One evaluation, one transaction (`store.Unit`).**
   - The gateway opens a unit for each `/v1/evaluate` and puts it in the request context. Every state write of that evaluation joins it:
     - the nonce and its request record;
     - the reservation and its decision record, or the pending escalation and its decision record, or the deny record;
     - the gatekeeper's spent token;
     - the commit or release and its record;
     - best-effort compaction of expired nonces and of limiter records past retention.
   - The unit commits in one transaction, through group commit, with one fsync.
   - **The gateway writes the answer only after the unit is durable.** If the unit fails, nothing of the evaluation is on disk. Every component rolls back what it held in memory:
     - the nonce is unspent again;
     - the held capacity is given back;
     - committed state is reverted.
   - In that case the caller gets HTTP 500 `INTERNAL`, never the decision. `stopbar_state_write_failures_total` counts it, and a high-severity log line is written. No signed transaction or token ever leaves for a write that did not land.
   - Every audit record is still written in the same transaction as the state change it describes. Now that is also the same transaction as the rest of its evaluation.

3. **Holds instead of locks.**
   - Components no longer hold a lock across a write.
   - The nonce store marks a key pending, so a concurrent duplicate is refused.
   - The limiter holds capacity from the moment it is checked. Sweep skips entries with a write in flight. A failed write gives capacity back, and a release frees capacity only once it is durable.
   - An operation on an ID whose write is in flight waits for it, unless the write is in the caller's own unit (reserve, then commit or release, in one evaluation).
   - A write that arrives after its unit has committed runs on its own, so nothing is dropped. This covers a component that outlived its stage timeout.

4. **Smaller decision records.** Decision records no longer carry `request`. The request record has it, written with the consumed nonce in the same transaction or, for an approval, earlier in the chain. The decision carries `request_id` and `payload_hash`. The enriched `context` drops its copy of the request. On the harness mix this takes audit bytes per request from 5.2 KB to 3.7 KB.
   - **Audit hash v1 is unchanged**, because the hash covers whatever the body is. Old and new logs verify with the same `stopbar audit verify`, and records written before this change are untouched.

5. **Compaction is of state only.** It covers expired nonces and limiter records past retention, and it rides in the unit. The hash-chained audit log is never compacted. No checkpoint or archive scheme is specified for it.

## Consequences

- **An allow pays one fsync wait instead of four.** On macOS, a dev machine (not official) went from about 27 ms p50 at 5 rps to about 11 ms p50 and 23 ms p99 at 1,000 rps. The official Linux numbers are in `docs/benchmarks.md`.
- **The nonce is durable when the evaluation commits, not before the engine runs.** It is still consumed in memory before evaluation (as pending), so a concurrent replay is refused. A replay after a crash cannot succeed for any request that was answered, because the answer waits for the unit. A request whose unit failed was never answered, and it can be re-sent with the same nonce. Nothing was signed or recorded for it.
- **Approve, reject, commit/release over HTTP and contact edits do not use a unit.** Each of their writes still commits on its own (group-committed).
- **Write functions must change nothing outside the transaction**, because a group may run them twice. Components apply their in-memory effects in the after callbacks.
- Tests cover these guarantees:
  - store: a unit is one transaction; a failed write or a failed commit fails every write of the unit and writes nothing; late writes still land; group-commit isolation;
  - limiter: reserve and commit in one unit, rolled back together; capacity held while a commit is in flight; the concurrency property against a slow store that fails one write in ten; compaction never touches the audit log;
  - gateway: a failed unit answers 500, writes nothing and leaves the nonce reusable.
