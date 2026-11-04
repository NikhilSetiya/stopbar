# FREEZE: AgentDojo banking pilot policy bundle, v1

| | |
|---|---|
| **Bundle hash** | `sha256:a974808bc9acb999b332b85c4aea081360919a78f60cc53c1298600abeedd27c` |
| Frozen | 2026-11-04, before any agent run (no pilot data exists) |
| Pre-registration | [`../../PILOT.md`](../../PILOT.md), as amended by Amendments 1 and 2 (§6a, §6b) |
| Sign-off | Project owner (@NikhilSetiya), pack review 2026-11-04: *"Approve the pack with one change: drop account-identity-change from the pilot bundle. Keep get_scheduled_transactions as untrusted."* Both are applied, and the reasoning is recorded as Amendment 2. |
| Author's review | Claude checked the pack against PILOT §3 point by point. Only tool definitions were read. No rule names an IBAN, amount, file, string or task. No rule inspects arguments. Undeclared tools fail closed. Taint is computed inside Stopbar from this bundle, keyed to the session, and a missing session ID fails closed. |

Bundle files (the hash is `sha256(JCS({"v":1,"files":[{name, sha256}…]}))`, LLD §5.4):

| File | sha256 |
|---|---|
| `banking.cedar` | `ecc4e1e68937f66199bd1e4ae6a02ee0a5f234511ead8a1e4c3d7dd4f16bb70f` |
| `tool-trust.json` | `7285c31e2f9562e19d22c4e0aa73b3cab35cd5d31e0ddd3e2c4175839d67e84b` |
| `tools.cedarschema` | `54a78d1b35cf50885b7ab2e8d7fb97ef70f46bb515849e316caf13a92374319f` |

**Enforcement:**
- `TestBankingPackIsFrozen` (`internal/policy`) fails CI if the loaded bundle hash ever differs from the one above.
- The CS-503 harness refuses to start unless `stopbard` reports this hash.
- Every results row records the hash.

**Rule:** after this commit the bundle is never edited. A different pack is a new pre-registered version (v2, its own hash), run and reported separately, and the v1 numbers are always published.
