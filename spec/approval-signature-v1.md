# Approval signature — v1

Status: draft (CS-151; escalation object v2 by CS-153). Decisions: [ADR 0005](../docs/adr/0005-signed-approvals.md),
[ADR 0010](../docs/adr/0010-approval-policy-binding.md) (escalation approvals bind the policy bundle).

This document versions each signed object separately (§11). Current versions:
escalation approval **v2** (§2), breaker reset v1 (§3), contact approval v1 (§3a).

A signed approval is Stopbar's replacement for API-key approval (issue #32). It
is a human (or second-agent) countersignature, made with an **approver key**
that is separate from every API key, over the exact thing being decided: which
escalation, which payload, under which policy bundle, approve or reject, and until when. The engine never
trusts an approval it cannot verify against a configured approver key, and
never counts two approvals from the same key as two.

The key words MUST, MUST NOT and SHOULD are used as in RFC 2119.

## 1. Design choices

| Choice | Why |
|---|---|
| Ed25519, separate key space from API keys and decision keys | An API key is a bearer secret with no signature; it authenticates a *request*, not a *decision*. A compromised API key must not be able to approve anything (LLD §10.3's "separately tagged files" rule extends to approver keys: an approver key file can never be loaded as a decision key file or vice versa). |
| Sign the object directly, not a JWS | There is no key rotation mid-flow and no third party ever parses the envelope without also holding the object (unlike a decision token, which an adapter must parse generically). A domain-separated raw Ed25519 signature is simpler and just as auditable. |
| Domain-separated signing input | `sign(domain || JCS(object))`. The domain string names the object kind and version, so an escalation-approval signature can never verify as a breaker-reset signature (or a decision-token, or an audit checkpoint signature) even if the JSON shapes ever coincided. |
| `kid` carried outside the signed bytes | `kid` is a lookup hint, not a claim: swapping it under a valid signature does not change which key verification actually uses, because Ed25519 verification is keyed. A swapped `kid` just fails against the wrong public key. |
| Expiry bound at verification time, not issuance time | The object carries no `iat`. A verifier with a trustworthy clock enforces `now < expiry ≤ now + 1h` **when it checks the signature**, so a signature cannot be pre-dated to stay valid indefinitely, and "how long ago it was signed" never has to be tracked or trusted. |
| Quorum state is pure and storage-agnostic | `Tally` (§5) takes votes and returns a resolution; it persists nothing. Whatever stores pending escalations or breaker trips (`internal/store`, bbolt) owns durability; `Tally` owns only the counting rule, so it is identical for escalation approvals and breaker resets. |

## 2. Escalation approval object (v2)

```json
{"decision":"approve","escalation_id":"<id>","expiry":1700000000,"payload_hash":"sha256:<hex>","policy_bundle_hash":"sha256:<hex>"}
```

JCS-canonical, exactly these five members:

| Field | Type | Meaning |
|---|---|---|
| `escalation_id` | string | The pending escalation this approval is for. |
| `payload_hash` | string | `sha256:<hex>` of the JCS-canonical action, recomputed by the engine at re-run time (decision-token-v2 §2). Binds the approval to the exact transaction, not to whatever the approver was shown. |
| `policy_bundle_hash` | string | `sha256:<hex>` of the policy bundle the engine is running (`policy.Bundle.Hash`, the same value a decision's `policy_bundle_hash` carries). `GET /v1/approvals/{id}` returns it. Binds the approval to the policy it was given under: a vote counts only while the engine's active bundle hash is still this value. |
| `decision` | string | `approve` or `reject`. Nothing else. |
| `expiry` | int | Unix seconds. The signature counts for nothing at or after this instant. |

**A policy change invalidates the votes already cast.** The active bundle is
what decided this escalates, and what the quorum's re-run (LLD §9 step 5) will
evaluate under. An approver who signed under bundle H agreed to H's rules
(which escalation reasons exist, what an approval waives, which caps deny), not
to a later bundle's. So:

- An envelope whose `policy_bundle_hash` is not the active bundle is refused
  (§6 step 8, `POLICY_CHANGED`); it is audited and changes no state.
- A stored vote counts toward quorum only while its `policy_bundle_hash` equals
  the active bundle (§9). The engine compares them every time it replays the
  stored votes, including after a restart on a different bundle, since pending
  escalations and their votes survive restarts in the state file. Votes that no
  longer match are discarded, and listed (`invalidated_votes`) in the audit
  record of the write that discards them: the next accepted vote on that
  escalation. Approvers re-sign against the new hash.
- A vote stored before v2 has no `policy_bundle_hash` and so never counts.

### 2.1 Escalation approval object v1 (superseded, never accepted)

```json
{"decision":"approve","escalation_id":"<id>","expiry":1700000000,"payload_hash":"sha256:<hex>"}
```

The four v1 members are as in §2 without `policy_bundle_hash`, signed under the
domain tag `"stopbar-approval-escalation-v1\n"`. Because it carries no policy
binding, a verifier MUST NOT accept a v1 escalation envelope once v2 exists:
`stopbard` reconstructs only the v2 object under the v2 tag, so a v1 signature
fails §6 step 4 (`BAD_SIGNATURE`) whatever fields are posted alongside it.

## 3. Breaker reset object

```json
{"decision":"reset","expiry":1700000000,"tenant":"acme","trip_request_id":"req_123"}
```

JCS-canonical, exactly these four members:

| Field | Type | Meaning |
|---|---|---|
| `tenant` | string | The tenant whose circuit breaker is being reset. |
| `trip_request_id` | string | `BreakerStatus.trip_request_id`: the request that tripped it. Binds the reset to *this* trip, not a later one for the same tenant. |
| `decision` | string | Always `reset`. Carried for symmetry with §2 and so a reset signature can never be read as an escalation decision even if the domain tag were ignored. |
| `expiry` | int | Unix seconds, same rule as §2. |

## 3a. Contact approval object

Approves a pending destination-registry addition (CS-134, LLD §6.4).

```json
{"address":"0x7a25a1c4e3b2d1f09876543210fedcba98760c21","contact_id":"ct_123","decision":"approve","expiry":1700000000,"tenant":"acme"}
```

JCS-canonical, exactly these five members:

| Field | Type | Meaning |
|---|---|---|
| `tenant` | string | The tenant whose registry the entry is in. |
| `contact_id` | string | `Contact.id` of the pending addition. |
| `address` | string | `Contact.address`, lowercase as stored. Binds the signature to the address the approver saw, not only to an id. |
| `decision` | string | Always `approve`. A pending addition is turned down by removing it, which needs no quorum. |
| `expiry` | int | Unix seconds, same rule as §2. |

## 4. Signature

```
signature = Ed25519(priv, domain || JCS(object))
```

- Escalation approval domain (v2): the 31 ASCII bytes `"stopbar-approval-escalation-v2\n"`. (v1, §2.1, used `"stopbar-approval-escalation-v1\n"` and is no longer accepted.)
- Breaker reset domain: the 34 ASCII bytes `"stopbar-approval-breaker-reset-v1\n"`.
- Contact approval domain: the 28 ASCII bytes `"stopbar-approval-contact-v1\n"`.

This is deliberately not a JWS: there is one fixed algorithm (Ed25519), the
verifier already has the object (it is reconstructing it from current state,
not reading it out of the envelope), and the domain tag already does the job
`typ` does for decision tokens.

### 4.1 Wire envelope

The object's own fields, plus:

| Field | Type | Meaning |
|---|---|---|
| `kid` | string | RFC 7638 JWK thumbprint of the approver's Ed25519 public key (`decision.Kid`, reused — same thumbprint construction as decision keys, different key space). |
| `sig` | string | Unpadded base64url signature, 64 bytes decoded. |

## 5. Approver keys

- **Generation**: `stopbar approver keygen <file>` writes an Ed25519 private key tagged `"stopbar-approver-key-ed25519-v1\n"`, mode 0600. The tag differs from the decision key's (`"stopbar-decision-key-ed25519-v1\n"`) and the wallet key's, so no file can be loaded as the wrong kind.
- **Configuration**: `stopbard` is given the approver *public* keys only (a config file of `{id, tenant, owner, public_key}` entries, or an equivalent flag):

  ```json
  {"approvers": [
    {"id": "alice", "tenant": "acme", "owner": {"key_id": "ak_alice"}, "public_key": "<b64url>"},
    {"id": "bob",   "tenant": "acme", "owner": {"agent_id": "bob-agent"}, "public_key": "<b64url>"}
  ]}
  ```

  `id` is an operator-assigned label for logs and audit records; it is never trusted for lookup. The key actually used to verify a signature is found by **`kid`, recomputed from the configured public key**, exactly as `/v1/keys` entries are (decision-token-v2 §3.1): a mislabelled `id` cannot borrow another key's identity. **`owner` is required** on every entry — at least one of `agent_id` or `key_id` MUST be set, naming the requester identity this approver key is also bound to (§7). Config loading refuses an entry with neither field set, and refuses two entries that share a `kid` even across different `id`s or tenants.
- **Never an API key.** An API key has no public/private key pair and cannot produce an Ed25519 signature; `VerifyEscalation`/`VerifyBreakerReset` only ever look a `kid` up in the configured approver set, which API keys are never added to.

## 6. Verification (escalation approval)

A verifier is given: the configured approver set for the tenant, the escalation's *current* `{escalation_id, payload_hash}` (recomputed at re-run time, never taken from the approval itself), the active policy bundle hash, the requester's identity — both its `key_id` and `agent_id`, from the authenticated requester the escalation was created with — for the self-approval check, a clock, and the envelope to check. It MUST run these checks in order and stop at the first failure.

| # | Check | Error code |
|---|---|---|
| 1 | `kid` is in the configured approver set | `UNKNOWN_KEY` |
| 2 | That key's configured tenant equals the escalation's tenant | `WRONG_TENANT` |
| 3 | `sig` is strict unpadded base64url, 64 bytes decoded | `MALFORMED` |
| 4 | Ed25519 verifies over `domain \|\| JCS(object)`. **No field below is trusted before this passes.** | `BAD_SIGNATURE` |
| 5 | `decision` is `approve` or `reject` | `BAD_DECISION` |
| 6 | `escalation_id` equals the escalation being resolved | `WRONG_ESCALATION_ID` |
| 7 | `payload_hash` equals the one just recomputed from the action about to be re-run | `PAYLOAD_MISMATCH` |
| 8 | `policy_bundle_hash` is non-empty and equals the active policy bundle's hash | `POLICY_CHANGED` |
| 9 | `now < expiry` | `EXPIRED` |
| 10 | `expiry ≤ now + 1h` | `EXPIRY_TOO_FAR_AHEAD` |
| 11 | If `decision` is `approve`: the key is not bound (§7) to the escalation's requester | `SELF_APPROVAL` |

A signature that fails any check counts for nothing: it is not a vote, live or expired, and is not stored. Step 6 is also what makes a replayed signature from one escalation worthless on another — `escalation_id` simply will not match.

## 7. Self-approval

A requester MUST NOT approve its own escalation (separation of duties). Because approver keys and API keys are different credential types, the binding is explicit and **mandatory**: every configured approver entry has an `owner` naming the requester identity it also represents, via `agent_id`, `key_id`, or both (§5). Step 11 refuses the approval with `SELF_APPROVAL`, regardless of quorum otherwise being met, when **either**:

- `owner.key_id` is set and equals the escalation's requester `key_id`, or
- `owner.agent_id` is set and equals the escalation's requester `agent_id`.

Either match alone is enough; the two checks are independent, not both required. This does not depend on an optional field being configured: `owner` is required at load time (§5), so a deployment can never have an approver entry that is silently exempt from the self-approval check — at worst, its `owner` names an identity that happens never to also be a requester, and the check then simply never fires for that key.

## 8. Verification (breaker reset)

Same shape, over the §3 object, given the tenant and its breaker's current `trip_request_id`:

| # | Check | Error code |
|---|---|---|
| 1 | `kid` is in the configured approver set | `UNKNOWN_KEY` |
| 2 | That key's configured tenant equals the tenant being reset | `WRONG_TENANT` |
| 3 | `sig` is strict unpadded base64url, 64 bytes decoded | `MALFORMED` |
| 4 | Ed25519 verifies over `domain \|\| JCS(object)` | `BAD_SIGNATURE` |
| 5 | `decision` is `reset` | `BAD_DECISION` |
| 6 | `tenant` equals the tenant being reset | `WRONG_TENANT` |
| 7 | `trip_request_id` equals the breaker's current trip | `WRONG_TRIP` |
| 8 | `now < expiry` | `EXPIRED` |
| 9 | `expiry ≤ now + 1h` | `EXPIRY_TOO_FAR_AHEAD` |

There is no self-reset rule: a breaker trip has no single "requester" to exclude.

## 8a. Verification (contact approval)

Over the §3a object, given the stored pending entry (tenant, id, address) and its requester's `key_id` and `agent_id`:

| # | Check | Error code |
|---|---|---|
| 1 | `kid` is in the configured approver set | `UNKNOWN_KEY` |
| 2 | That key's configured tenant equals the entry's tenant | `WRONG_TENANT` |
| 3 | `sig` is strict unpadded base64url, 64 bytes decoded | `MALFORMED` |
| 4 | Ed25519 verifies over `domain \|\| JCS(object)` | `BAD_SIGNATURE` |
| 5 | `decision` is `approve` | `BAD_DECISION` |
| 6 | `tenant` equals the entry's tenant | `WRONG_TENANT` |
| 7 | `contact_id` and `address` equal the stored entry's | `WRONG_CONTACT` |
| 8 | `now < expiry` | `EXPIRED` |
| 9 | `expiry ≤ now + 1h` | `EXPIRY_TOO_FAR_AHEAD` |
| 10 | The key is not bound (§7) to the entry's requester | `SELF_APPROVAL` |

The quorum is the escalation quorum (`-approval-quorum`), counted by §9's rules.

## 9. Quorum (M-of-N)

All three flows resolve the same way, via `approval.Tally`:

- **Reject wins immediately: a single-approver veto, by design.** One valid `reject`, from any one configured approver, resolves the escalation as rejected outright — it needs no quorum of its own and is not outvoted by however many `approve` votes are already held, even a full quorum's worth. This is deliberately asymmetric with approval (which needs `M` distinct votes): it is the fail-closed direction. Escalation exists because the engine was not confident enough to allow outright; requiring agreement to let it through but only one dissent to stop it keeps that posture — a single approver can always fall back to denying, but no minority can force an allow past an objection. (A breaker reset and a contact approval have no reject; a vote is either cast or not. A contact addition is turned down by removing it.)
- **`M` distinct OWNERS, never double-counted — not `M` distinct keys.** `Tally` dedupes on the matched key's `owner` (§5), not on `kid`. Two keys configured with the exact same `owner` (both `agent_id` and `key_id` equal, including both empty) are the same owner and count once between them: one person holding two approver key files cannot satisfy a 2-of-N quorum alone. The owner identity is deliberately an **exact** match of the whole `owner` object (`agent_id + "\x00" + key_id` as a canonical string) — not the either-field match §7's self-approval check uses — because quorum dedup only merges entries an operator configured identically on purpose; it never guesses that two differently-configured entries are "probably" the same person. `M` is the configured quorum (`MinQuorumProduction` = 2; `stopbard` refuses to start with a lower quorum unless run with `-dev-world`). A second valid vote whose owner already holds a live vote is refused (`ErrDuplicateVote`); it does not add a second count, and it does not replace the first — this covers both "the same key voted twice" and "a different key with the same owner voted."
- **A vote owned by the escalation's requester never counts, as defence in depth.** `Tally` is constructed with the requester's `key_id`/`agent_id` to exclude (`NewTally(required, excludeKeyID, excludeAgentID)`; both `""` for a breaker reset, which has no requester, §8). `Add` runs the same either-field check as §7's `SELF_APPROVAL` and refuses such a vote the same way, even though `VerifyEscalation` should already have refused it before it ever reached `Tally` — this is a second, independent enforcement point, not the primary one.
- **Escalation votes are bound to the policy bundle.** Before replaying an escalation's stored votes into `Tally`, the caller drops every vote whose `policy_bundle_hash` (carried on `Vote`) is not the active bundle's, and audits them (§2). `Tally` itself stays pure and does not know about bundles. Breaker-reset and contact votes carry no bundle hash (ADR 0010).
- **Votes expire.** A vote's own `expiry` (§2/§3) bounds how long it counts. `Tally` discards expired votes before counting toward `M`, so an owner whose vote expired may vote again (a fresh signature, not a resurrected one).
- **Once resolved, stays resolved.** After `Tally` returns a non-pending resolution (quorum met, or a reject), every later `Add` is refused (`ErrAlreadyResolved`) rather than re-opening or re-counting. This is what makes "approve after reject" and "approve after the quorum already executed" refusals rather than silent no-ops.

### 9.1 Alerting on a veto

A single-approver veto is unusual enough to page on, and the record of who cast it must survive the decision it reversed. `Tally` itself never logs, counts or writes anything (it stays pure); when `Add` returns `Resolution{Outcome: Rejected, Veto: &v}`, the caller (Step B's engine/gateway wiring) is expected to, in this order:

1. Call `Alerts.Veto(tenant, kind, v)` — a high-severity structured log line (`severity=high`, `alert=approval_reject`) naming `v.Kid` and `v.Owner`, and the `stopbar_approval_rejects_total{tenant,kind}` counter (`kind` is `VetoKindEscalation` or `VetoKindBreakerReset`). `Alerts` is constructed once (`NewAlerts`) and shared for the deployment's lifetime, the same way `internal/limiter`'s breaker counters are; `Alerts.Counters()` feeds `/metrics` the same way `Limiter.Counters()` already does.
2. Write `VetoAuditEntry(tenant, kind, v)` (a `model.AuditEntry{Type: model.AuditApproval, ...}` carrying `v.Owner`, not only `v.Kid`) in the **same transaction** as the state change the veto causes — deleting the pending escalation, or leaving a breaker open — per LLD §11's rule that every audit record is written with the state change it describes.

## 10. Threats addressed

| Threat | Defence |
|---|---|
| A stolen or guessed API key used to approve or reject | API keys are never in the approver set; `UNKNOWN_KEY` at step 1 either way. |
| A valid approval replayed on a different, later escalation for the same tenant | §6 step 6: `escalation_id` is bound and checked. |
| A valid breaker-reset signature replayed on the *next* trip for the same tenant | §8 step 7: `trip_request_id` is bound and checked. |
| A contact approval moved to a different (look-alike) address or entry | §8a step 7: both `contact_id` and `address` are bound and checked. |
| A vote cast under one policy bundle counted after the bundle changed (a loosened policy approved under, or a tightened one bypassed with, votes given for the old rules) | §2 / §6 step 8: the object binds `policy_bundle_hash`; a stored vote counts only while it is the active bundle, and an old-bundle envelope is refused `POLICY_CHANGED`. |
| A v1 (unbound) escalation signature submitted after v2 | §2.1: only the v2 object under the v2 tag is ever verified; a v1 signature is `BAD_SIGNATURE`. |
| A stale approval used long after signing, or a signature pre-dated to stay valid forever | §6/§8 steps 8–9: checked at verification time, bounded to a 1-hour window, with no `iat` to trust. |
| The same approver counted twice toward quorum, including by holding a second approver key file | `Tally` dedupes by `owner`, not `kid` (§9): a second live vote whose owner already holds one is refused (`ErrDuplicateVote`), whether it is the same key or a different key configured with the same owner. |
| A compromised requester signs its own approval with a stolen or colluding approver key | §7: an approver key whose required `owner` matches the requester's `key_id` or `agent_id` is refused at step 11, independent of quorum. |
| An approval, reset or contact signature read as another kind, or as a decision token / audit checkpoint | Domain separation (§4): each signing input starts with a distinct, versioned tag. |
| A decision reached, then "re-approved" after it changed (quorum met, then a late reject; or executed, then approved again) | `Tally`'s `ErrAlreadyResolved` (§9): the first resolution is final. |

## 11. Versioning

Any change to an object's fields, the domain tags, or the verification order bumps the object's own version (`-v1` → `-v2` in its domain tag) and both versions are specified side by side, as for decision tokens. The escalation approval object is at v2 (§2, adding `policy_bundle_hash`; v1 in §2.1, no longer accepted). The breaker reset (§3) and contact approval (§3a) objects are unchanged at v1. The document keeps its `-v1` name and its vector file, which hold each object at its current version.

Test vectors: [`vectors/approval-signature-v1.json`](vectors/approval-signature-v1.json), generated and checked by `internal/approval/vectors_test.go` (`go test ./internal/approval -run TestApprovalSignatureVectors -update`). They include negative vectors for every check in §6, §8 and §8a, and a v1 escalation signature (§2.1), which must be refused.
