# ADR 0010: Escalation approvals bind the policy bundle (approval object v2)

- Status: **Accepted**
- Date: 2026-11-27
- Task: CS-153
- Amends: [ADR 0005](0005-signed-approvals.md) (signed approvals)
- Spec: [`spec/approval-signature-v1.md`](../../spec/approval-signature-v1.md) §2, §2.1, §6, §9, §11

## Context

An escalation approval (ADR 0005) signs `{escalation_id, payload_hash, decision, expiry}`. Nothing in it says which policy the approver approved under. Votes are stored with the pending escalation and survive a restart, and the quorum's re-run (LLD §9 step 5) evaluates under whatever bundle is loaded then.

So an approver could vote under bundle H1, the operator could restart `stopbard` on H2, and that vote would still count toward a quorum completed under H2. H2 may have different escalation reasons, a different meaning for `context.approvals`, or a looser cap. The approver agreed to H1's rules, not H2's. In the worst case, a compromised operator (T3) or a careless one (T2) loosens policy while an escalation is pending and completes the quorum with votes that were given for a stricter policy.

`stopbard` loads the bundle once, at startup (`policy.Load`). There is no runtime reload, and CS-115 (signed activation with cooling-off) is not built yet. In practice, then, the bundle changes when `stopbard` restarts on a different bundle.

## Decision

1. **The escalation approval object gains `policy_bundle_hash`.** It is the active bundle's hash (`policy.Bundle.Hash`, the same value every decision's `policy_bundle_hash` carries). `GET /v1/approvals/{id}` returns it, and the CLI and both SDKs sign it.

2. **This is a breaking change, versioned per the spec's own rule (§11).** A field change bumps the object's version. The escalation object is now **v2**, with domain tag `"stopbar-approval-escalation-v2\n"`. v1 is specified next to it (§2.1) and marked superseded.

3. **v1 escalation envelopes are not accepted.** They carry no policy binding, so accepting them would keep the gap open. The verifier rebuilds only the v2 object under the v2 tag, so a v1 signature fails at the signature check (`BAD_SIGNATURE`). A conformance vector pins this. Old CLIs and SDKs must upgrade to approve or reject.

4. **A vote counts only while its bundle is the active one.**
   - Verification gains step 8: `policy_bundle_hash` is non-empty and equals the engine's active bundle hash, or the result is `POLICY_CHANGED`. The engine reports this as deny `APPROVAL_SIG_POLICY_CHANGED`, audited, with no state change.
   - Each stored `Vote` records the bundle it was signed against. Before replaying stored votes into `approval.Tally`, the engine drops those whose bundle is not the active one. This comparison runs on every replay, so it covers a restart on a new bundle.
   - Dropped votes are listed as `invalidated_votes` in the audit record of the write that removes them: the next accepted vote, veto or resolution on that escalation. A refused envelope writes nothing but its refusal record, so a retry after a policy change "changes no state".
   - Votes stored before v2 have no bundle hash and are dropped the same way. The escalation itself stays pending and can still be approved with fresh v2 signatures.
   - `Tally` stays pure: it does not know about bundles.

5. **Breaker-reset and contact approvals stay at v1, unbound.**
   - A breaker reset approves reopening a tenant's traffic after a specific trip (`trip_request_id`). Policy plays no part in deciding it. The engine does not re-evaluate anything on reset, and every request after the reset is evaluated under whatever bundle is loaded then. Binding the reset to a bundle would add a restart race without protecting anything.
   - A contact approval approves one address into the destination registry, checked against the registry's similarity rule, not against Cedar policy. Its effect, "this destination is known", is an input that every later evaluation reads under the current bundle.
   - In both cases a policy change alters how later requests are judged, but it does not change what the approver agreed to. Neither object changes.

6. **Where a bundle can change, the check is already wired.** The engine reads the active hash through `engine.Policy.Hash()` on every vote, not once at startup. When runtime activation lands (CS-115), swapping the bundle behind that interface invalidates pending votes with no further change.

## Consequences

- Approvers re-sign after any policy change, including a whitespace or comment edit, because the bundle hash covers file bytes. That is deliberate: the hash is the only identity a policy has.
- Pending escalations keep working across an upgrade of `stopbard`: their votes are dropped (and audited) and approvers sign again.
- The same envelope submitted twice still executes once. Before quorum, a second vote from the same owner is `409 DUPLICATE_VOTE`. After quorum, any vote is `409 ALREADY_RESOLVED`. Neither issues a second token or signed transaction (tests in `internal/engine/approval_policy_test.go`, and `scripts/e2e_lifecycle.py` over HTTP across a real restart).
- Threat-model row: HLD §8 "Approval outlives the policy it was given under".
