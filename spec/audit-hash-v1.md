# Audit record hash — v1

Status: draft (CS-006). Implemented in `internal/canon/hash.go`.

Every audit record links to its predecessor:

```
hash = "sha256:" + hex( SHA-256( JCS( {
  "v":         1,
  "seq":       <uint64>,
  "ts":        <RFC 3339 string, hashed verbatim>,
  "type":      <request|decision|approval|policy_change|commit|release|override>,
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

Test vectors: `internal/canon/jcs_test.go` (RFC 8785 Appendix B numbers, §3.2.2
example, §3.2.3 key ordering; cross-checked against V8 `JSON.stringify` on
200,000 random doubles).
