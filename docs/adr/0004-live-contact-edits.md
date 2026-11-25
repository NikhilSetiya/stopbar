# ADR 0004: Live destination-registry edits, with approval and cooling-off

- Status: **Accepted**; the approval mechanism (decision 1) is superseded by [ADR 0005](0005-signed-approvals.md)
- Date: 2026-11-24
- Task: CS-134 (builds on CS-133; FR-IR-2, FR-POL-5)
- Design: LLD §4.1 (`/v1/contacts`), §6.4

## Context

CS-133 put the per-tenant destination registry in the state file and edited it
only offline (`stopbar contacts --state-dir`). The argument was the trust
boundary: registering a destination loosens policy (the address stops being
`new_destination`, and the look-alike check starts protecting it), so it should
need the operator's state directory, not a requester credential. Otherwise a
compromised requester (T3) could allowlist its own address.

The price was operational. stopbard holds the bbolt lock, so every contact
change meant stopping the service. In practice that pushes operators toward
seeding wide allowlists up front, which is worse.

## Decision

Move registry edits onto the authenticated API and make the loosening direction
safe by construction rather than by file access:

1. **Additions are two-party and delayed.** `POST /v1/contacts` (`contacts`
   scope) records a *pending* entry. It counts for nothing until a different
   identity approves it (`POST /v1/contacts/{id}/approve`, `approve` scope;
   self-approval refused with `SELF_APPROVAL` and audited), and then only from
   `active_from = approval + cooling-off` (default 24h, `-contact-cooling-off`).
   The cooling-off runs from the approval, so a late approval cannot activate
   at once. Until then the enricher treats the address as new: policy and the
   unknown-destination soft caps do not change.
2. **The approver sees poisoning.** Each request is checked against every
   existing entry, active and pending, with the enricher's similarity rule.
   Every match (address and label) is stored on the pending record, written in
   its audit record, and shown by `GET /v1/contacts` and the CLI.
3. **Removals are immediate.** Tightening never waits.
4. **Activation uses the server clock.** No clock override in stopbard. Tests
   inject a clock into the registry only.
5. **Every change is audited in the same transaction** (`contact_request`,
   `contact_approval`, `contact_removal`).
6. **The offline path is removed.** If it stayed, it would bypass 1–3.

## Consequences

- **The threat tier rating changes.** A single compromised `contacts` key (T3)
  can now only *propose*. To activate an address it also needs a distinct
  approver key, and it stays visible for the cooling-off window, where anyone
  with a `contacts` key can remove it. A compromised approver plus requester
  pair still gets through after the window. This is the same bar as escalation
  approvals, and it is weaker than requiring host access. Deployments that want
  more should issue the `approve` scope to humans only. CS-151 signed
  owner-quorum approvals will raise it to M-of-N Ed25519 signatures. The
  approval call site is kept thin for that move.
- `destinations_v1` (CS-133) entries are not migrated. They read as unknown,
  which only tightens policy. `-dev-world` re-seeds its own as already active,
  since the operator's world file stands in for the approval.
- The contacts API needs `-auth-keys`. Without auth it answers 503, because
  separation of duties needs identities.
