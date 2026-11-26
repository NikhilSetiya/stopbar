# ADR 0008: Address checksum phrase v1, a frozen format

- Status: **Accepted**
- Date: 2026-11-26
- Task: CS-143 (issue #29, FR-IR-3)
- Related: LLD §6.3, `internal/render`

## Context

Approvers sign over a `payload_hash` they cannot read, so they check the
rendered intent instead. Address poisoning beats a visual check of an address:
a vanity generator finds an address with the same first and last 4 hex digits
in about 2^32 keys, which takes seconds on one GPU, and wallets show only
those digits. LLD §6.3 calls for a 6-word checksum phrase derived from the
full address. Approvers compare the phrase across sessions, devices and tools
(the CLI, the API's `rendered` field, later Slack and signing pages, other
people's clients), so its derivation is an interface. Changing it silently
would leave approvers comparing phrases that no longer mean the same thing.

## Decision

**Checksum phrase v1** is defined exactly as follows. `render.Phrase` is the
reference implementation.

1. **Input:** an EVM address, `0x` followed by 40 hex digits. Anything else has
   no phrase. Hex case is ignored, so EIP-55 checksummed and lowercase forms
   give the same phrase.
2. **Hash:** `H = sha256(D || A)`, where `D` is the 27 ASCII bytes
   `stopbar-address-checksum-v1` followed by one zero byte, and `A` is the 20
   raw address bytes (not the hex text).
3. **Bits:** the first 66 bits of `H`, big-endian, split into six 11-bit
   groups.
4. **Words:** each group indexes the **BIP-39 English wordlist** (2048 words,
   unique in their first four letters), embedded verbatim from bitcoin/bips.
   The file's sha256 is
   `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`, which
   `TestWordlist` pins.
5. **Output:** the six words, lowercase, separated by single spaces. They are
   displayed after the shortened address as `0x9f30…0c21 [six words]`.
6. **Vectors (pinned by `TestPhrase`):**
   - `0x9f30000000000000000000000000000000000c21` → `quality warrior impose six whisper blame`
   - `0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed` → `guess daughter search shine spike mountain`

**Any change** to the domain string, the hash, the bit selection, the word
count, the wordlist or the input normalisation is a **new, versioned format**:
a new domain string (`…-v2`), a new ADR, and a rendering that names the
version. v1 output never changes.

**Approvers must compare all six words.** Every word carries 11 independent
bits. Matching two words costs an attacker only 2^22 extra keys on top of the
2^32 visual match, which is feasible, so a partial comparison is not a check.

## Work factors

Assume a GPU vanity generator doing about 10^9 secp256k1 keys per second:

| Attacker goal | Work | Time on one GPU |
|---|---|---|
| Same first and last 4 hex digits (what poisoning does today) | 2^32 | seconds |
| Same 6-word phrase as one target | 2^66 ≈ 7.4×10^19 | ≈ 2,300 years |
| Same visible digits **and** same phrase | 2^98 | infeasible |
| Same visible digits and 2 matching words | 2^54 | ≈ 7 months; feasible for a funded attacker, hence the all-six-words rule |

The look-alike test (`TestLookAlikePhrases`) covers several addresses. For
each one it checks every single-digit change and 2,000 variants with the same
first and last 4 hex digits. Each variant shares at most 2 of 6 words with its
target, and no two variants collide.

## Consequences

- The phrase is a human check that complements the automated
  `similar_destination` flag (LLD §6.4). Neither replaces the other.
- Other clients (SDKs, signing pages) can show the same phrase by
  implementing the five steps above and checking the vectors.
- 66 bits suits a check a human makes in seconds, not an authenticator. The
  signature over `payload_hash` remains what authorizes the action.
