# Audit record hash — v1

Status: draft (CS-006). Implemented in `internal/canon/hash.go`. Freezes at the first tagged release, like `decision-token-v1`: later changes bump `v`.

Every audit record links to its predecessor:

```
hash = "sha256:" + hex( SHA-256( JCS( {
  "v":         1,
  "seq":       <uint64>,
  "ts":        <RFC 3339 string, hashed verbatim>,
  "type":      <request|decision|approval|policy_change|commit|release|override|auth_reject|destination_change|breaker|contact_request|contact_approval|contact_removal>,
  "body":      <event object>,
  "prev_hash": <previous record's hash, or GENESIS>
} ) ) )

GENESIS = "sha256:" + 64 × "0"
```

`JCS` is RFC 8785. Hashing a canonical object, rather than concatenating
`prev_hash || jcs(body) || seq || ts` as LLD §3.5 originally sketched, removes
field-boundary ambiguity: two different tuples can never produce the same preimage.

Constraints:

- `seq` must stay below 2^53 (JCS serialises numbers as IEEE-754 doubles).
- `ts` is hashed as the exact string stored; verifiers must not re-format it.
- Monetary values inside `body` are decimal strings, never JSON numbers.
- `v` is bumped for any change to the preimage. Verifiers reject unknown versions.
- `body` is opaque to the hash. Changing what a record type puts in its body
  does not change the preimage format, so it needs no new `v`. CS-197 (ADR 0009)
  dropped the repeated request from `decision` bodies (it stays in the `request`
  record). Logs written before and after that change verify alike under v1, and
  the existing test vectors are unchanged.

Test vectors: `internal/canon/jcs_test.go` (RFC 8785 Appendix B numbers, §3.2.2
example, §3.2.3 key ordering; cross-checked against V8 `JSON.stringify` on
200,000 random doubles).
