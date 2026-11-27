# ADR 0007: Off-chain signature requests are gated like the transactions they authorise

- Status: **Accepted**
- Date: 2026-11-25
- Task: CS-514
- Spec: [`spec/decision-token-v2.md`](../../spec/decision-token-v2.md) §2.4–2.5, LLD §6.1a

## Context

Until now wallet providers refused `eth_signTypedData` and `personal_sign`
outright, because Stopbar could not gate them. That left a gap and a
usability cost. A signed Permit2 `PermitSingle` or EIP-2612 `Permit` is as
good as an on-chain approval: the spender submits it and pulls the tokens. A
signed Seaport order is a transfer that anyone can fill. These are the
standard drainer flows ("sign to log in"), and none of them is a
transaction, so a transaction firewall never sees them. The refusal kept
agents safe but also blocked legitimate off-chain flows (bounded permits for
swaps, sign-in messages).

The trusted core has two constraints. First, it is stdlib-only, and the
EIP-712 digest needs keccak-256, which the stdlib lacks. Second, the decoder
decides what policy sees, so it must not read a payload one way while the
signer hashes it another way.

## Decision

1. **Two action kinds.** `evm_typed_data` carries the EIP-712 payload exactly
   as `eth_signTypedData_v4` takes it (`typed_data: {types, primaryType,
   domain, message}`). `evm_personal_sign` carries the EIP-191 message bytes
   as 0x hex. Both carry `chain_id` and `from` and nothing else, so no
   transaction field and no tool field.
2. **Strict structural validation in `model`.** Every value must have the one
   JSON shape its declared EIP-712 type allows. Integers are decimal strings
   or JSON integers within ±2^53, never hex. Addresses are 20-byte hex,
   `bytesN` has exactly N bytes, and structs have exactly their declared
   members. Bare `uint`/`int` types are refused. `domain.chainId` is required
   and must equal `chain_id`: a signature without one is valid on every
   chain. Domain members are declared in the standard order and are never
   empty, since go-ethereum drops empty ones. The result is that one payload
   has one reading, shared by the stdlib decoder and the go-ethereum hasher.
3. **The binding covers bytes, never a digest.** `payload_hash` is SHA-256 of
   JCS(`{v:1, kind, chain_id, from, typed_data | message}`), so the core needs
   no keccak. The signer computes the EIP-712 or EIP-191 digest from the bound
   action only. The requester never supplies a digest. Before signing, the
   signer recomputes the digest from the canonical bytes that `payload_hash`
   covers and refuses any mismatch (`DIGEST_MISMATCH`). After signing, it
   requires the recovered signer to equal `from`.
4. **Decode into the on-chain intent with the same flags.** The decoder
   (`internal/decode/evm`, stdlib) matches a primary type by name, and the
   declared type definitions must equal the canonical ones exactly. A
   look-alike with the right name and different members is a decode error,
   and the engine fails closed.
   - EIP-2612 `Permit`, DAI `Permit` and Permit2 `PermitSingle`/`PermitBatch`
     map to `approve` with the on-chain `unlimited_approval` rule.
   - A Seaport `OrderComponents` maps to `transfer` of its offer.
   - Anything else (unknown typed data, or `personal_sign`) maps to a new
     Cedar action, `sign_message`. Unknown typed data is flagged
     `unknown_call` and rendered. `personal_sign` bytes that are not printable
     text are flagged `opaque`.
5. **Two new flags for what only an off-chain grant has.**
   - `long_expiry`: an approval usable more than 31 days ahead, or forever.
   - `zero_consideration`: a Seaport order that pays the signer nothing.

   The starter pack denies `zero_consideration` and escalates `long_expiry`.
6. **Gatekeeper answers with a signature.** An allow carries `signature`
   (65 bytes, v = 27/28) and `signing_hash`. The reservation is committed with
   the digest as its reference. Wallet providers route off-chain signing
   through Stopbar instead of refusing it.

## Consequences

- Permits and orders count against the same caps as their on-chain
  equivalents: an approval's units, and an order's offered asset priced as a
  transfer. A Seaport offer of an NFT needs the NFT priced. The devstub prices
  it from the world file. The chain enricher fails closed on it, because an
  ERC-721 has no `decimals()`. An unpriceable order is denied, never allowed.
- Typed data without `domain.chainId` (some sign-in schemes) is refused with
  `400`.
- Seaport `BulkOrder` and Permit2 `PermitTransferFrom` (SignatureTransfer)
  are not decoded yet. They are flagged `unknown_call`, so the starter pack
  escalates them. Follow-up: CS-515.
- Decision-token v2 is not yet frozen (no tagged release has issued it). The
  new kinds are additive: existing bindings and vectors are unchanged, and a
  verifier that predates this change refuses the new kinds (`ErrNoBinding`),
  which is safe.
