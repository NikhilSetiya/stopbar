# ADR 0003: Decision token v2 binds the authenticated requester identity

- Status: **Accepted**
- Date: 2026-11-23
- Task: CS-103, increment 2 of 3
- Spec: [`spec/decision-token-v2.md`](../../spec/decision-token-v2.md) (v1 stays frozen: [`spec/decision-token-v1.md`](../../spec/decision-token-v1.md))

## Context

CS-103 increment 1 (#113) made identity come from authentication alone: an API
key now, mTLS/SPIFFE later. The gateway rejects a body whose `tenant` or
`actor.agent_id` disagrees with the credential, and every audit record carries
the identity. The decision token did not. A v1 token says *what* may be signed
(payload, tenant, nonce, adapter), not *who asked*. Inside one tenant, an allow
token taken from a response, a log or a shared queue was as good for any caller
as for the one it was issued to, and an adapter had no way to tell.

v1 froze at v0.1.0-alpha, so its claim set cannot be amended in place
(v1 freeze rule).

## Decision

1. **New version, side by side.** `spec/decision-token-v2.md` has v1's twelve
   claims plus `auth_method`, `key_id` and `agent_id`, with `v` = 2 and `typ` =
   `stopbar-decision-v2+jws`. The payload binding is unchanged. v1's spec and
   vectors are not edited.
2. **The identity comes from auth, never the body.** The engine passes the
   authenticated `auth.Identity` to the signer explicitly (`Signer.Sign(ctx,
   requester, req, d)`). The signer refuses an identity that is malformed or
   whose tenant is not the request's. With auth off (loopback only) the token
   says `auth_method` = `none`, with empty key and agent IDs.
3. **The adapter checks the identity of the request it signs.**
   `Verifier.Verify(token, action, identity)` adds step 7d (`WRONG_IDENTITY`),
   after issuer, audience and tenant and before time, outcome and payload. The
   gatekeeper passes the identity the gateway authenticated, or, for an approved
   escalation, the requester stored with the pending record (now the full
   `auth.Identity`, not only its key ID). An approved token binds the requester,
   never the approver.
4. **v2 only.** The signer issues v2 only, and the production verifier and
   gatekeeper adapter accept v2 only. A v1 token fails step 1 (`typ`), and a v1
   claim set under the v2 `typ` fails step 5. A test checks that no token in the
   frozen v1 vectors verifies.

## Consequences

- A token is bound to one authenticated caller as well as to one transaction.
  Stealing an allow token gains nothing unless the thief can also authenticate
  as the caller it was issued to and submit the exact same transaction.
- This holds against T3 only as far as the credential does. A compromised
  requester that holds its own API key is still that caller. Caps, allowlists,
  the circuit breaker and gatekeeper mode remain the controls that hold there.
- No verifier outside this repository exists yet. The Python SDK treats the
  token as opaque and needs no change. A future external verifier implements
  v2 against `spec/vectors/decision-token-v2.json`.
- Pending escalations persisted by an earlier build carried only the
  requester's key ID. They live in a bucket the new build never reads
  (`pending_escalations_v1`; records now go to `pending_escalations_v2`), so an
  escalation pending across the upgrade cannot be approved and must be
  resubmitted. It fails closed rather than being signed with no requester.
- Increment 3 (mTLS / SPIFFE) adds an authenticator. It needs no token change:
  `auth_method` = `mtls` and `key_id` = the SPIFFE ID are already specified.
