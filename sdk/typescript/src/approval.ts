// Signed approvals (CS-151, spec/approval-signature-v1.md): Ed25519 approver
// keys, separate from API keys, that countersign an escalation approve/reject
// or a breaker reset. Zero additional runtime dependencies: Node's built-in
// crypto module supports Ed25519 natively (Node >= 12).
//
// Key files use exactly Stopbar's tagged format
// (`stopbar-approver-key-ed25519-v1\n` + base64url seed), so a key this
// module writes loads with the Go CLI's `stopbar approver keygen` /
// `internal/approval.LoadKeyFile`, and vice versa.
//
// The two objects a signature covers are small, flat and fixed-shape (spec
// §2/§3): canonical() below sorts keys lexicographically and emits compact
// JSON with no extra whitespace, which is byte-identical to the Go core's
// `canon.Marshal` for the plain ASCII identifiers and decimal integers these
// objects carry — not a general RFC 8785 (JCS) implementation. The server
// independently re-canonicalises and verifies every signature; a
// canonicalisation mismatch here can only make a signature fail to verify
// (fail closed), never a forged one succeed.

import { closeSync, existsSync, openSync, readFileSync, statSync, writeSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";

export const APPROVE = "approve";
export const REJECT = "reject";
export const RESET = "reset";

const KEY_FILE_TAG = "stopbar-approver-key-ed25519-v1\n";

// DER prefixes for a raw 32-byte Ed25519 key (RFC 8410), the standard way to
// round-trip a raw seed/public key through Node's crypto module, which only
// accepts PKCS8 (private) / SPKI (public) wrapped keys.
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function privateKeyObject(seed: Buffer): KeyObject {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
}

function publicKeyFromSeed(seed: Buffer): Buffer {
  const der = createPublicKey(privateKeyObject(seed)).export({ format: "der", type: "spki" }) as Buffer;
  return der.subarray(der.length - 32);
}

/** Generates a fresh approver keypair. Returns the 32-byte private seed and
 * the 32-byte public key. The seed never leaves the caller's process except
 * via writeKeyFile, to a local file. */
export function generateKey(): { seed: Buffer; publicKey: Buffer } {
  const { privateKey } = generateKeyPairSync("ed25519");
  const der = privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
  const seed = Buffer.from(der.subarray(der.length - 32));
  return { seed, publicKey: publicKeyFromSeed(seed) };
}

/** Writes seed as a tagged approver key file, mode 0600. Refuses to
 * overwrite an existing file. */
export function writeKeyFile(path: string, seed: Buffer): void {
  if (existsSync(path)) throw new Error(`${path} already exists; refusing to overwrite a key`);
  const fd = openSync(path, "wx", 0o600);
  try {
    writeSync(fd, KEY_FILE_TAG + b64url(seed) + "\n");
  } finally {
    closeSync(fd);
  }
}

/** Reads an approver key written by writeKeyFile (or the Go CLI's
 * `stopbar approver keygen`). Refuses a file readable by anyone but its
 * owner, and any file that is not a tagged approver key. */
export function loadKeyFile(path: string): Buffer {
  const mode = statSync(path).mode & 0o777;
  if (mode & 0o077) throw new Error(`key file ${path} has mode ${mode.toString(8)}; must be 0600 or stricter`);
  const raw = readFileSync(path, "utf-8");
  if (!raw.startsWith(KEY_FILE_TAG)) throw new Error(`${path} is not a Stopbar approver key file`);
  const seed = Buffer.from(raw.slice(KEY_FILE_TAG.length).trim(), "base64url");
  if (seed.length !== 32) throw new Error(`${path}: malformed key`);
  return seed;
}

/** RFC 7638 JWK thumbprint, matching internal/decision.Kid and
 * internal/approval.Kid exactly (same construction, same key space as
 * decision keys — the key *files* stay separately tagged). */
export function kid(publicKey: Buffer): string {
  const jwk = `{"crv":"Ed25519","kty":"OKP","x":"${b64url(publicKey)}"}`;
  return b64url(createHash("sha256").update(jwk, "utf-8").digest());
}

function canonical(obj: Record<string, unknown>): Buffer {
  const ordered: Record<string, unknown> = {};
  for (const k of Object.keys(obj).sort()) ordered[k] = obj[k];
  return Buffer.from(JSON.stringify(ordered), "utf-8");
}

function signRaw(seed: Buffer, domain: string, obj: Record<string, unknown>): string {
  const msg = Buffer.concat([Buffer.from(domain, "utf-8"), canonical(obj)]);
  return b64url(cryptoSign(null, msg, privateKeyObject(seed)));
}

/** The wire envelope POSTed to /v1/approvals/{id}[/reject] (spec §2, §4.1). */
export interface SignedEscalation {
  escalation_id: string;
  payload_hash: string;
  policy_bundle_hash: string;
  decision: string;
  expiry: number;
  kid: string;
  sig: string;
}

/** The wire envelope POSTed to /v1/breakers/{tenant}/reset (spec §3, §4.1). */
export interface SignedBreakerReset {
  tenant: string;
  trip_request_id: string;
  decision: string;
  expiry: number;
  kid: string;
  sig: string;
}

/** Signs an escalation approve/reject envelope (spec §2, object v2).
 * policyBundleHash is the active bundle from GET /v1/approvals/{id}: the vote
 * counts only while Stopbar still runs that bundle. decision is APPROVE or
 * REJECT; expiry is Unix seconds, which the server refuses if not within
 * (now, now + 1h] of its own clock. */
export function signEscalation(
  seed: Buffer,
  params: { escalationId: string; payloadHash: string; policyBundleHash: string; decision: string; expiry: number },
): SignedEscalation {
  if (params.decision !== APPROVE && params.decision !== REJECT) {
    throw new Error(`decision must be "${APPROVE}" or "${REJECT}", got ${JSON.stringify(params.decision)}`);
  }
  const obj = {
    escalation_id: params.escalationId, payload_hash: params.payloadHash,
    policy_bundle_hash: params.policyBundleHash, decision: params.decision, expiry: params.expiry,
  };
  const sig = signRaw(seed, "stopbar-approval-escalation-v2\n", obj);
  return { ...obj, kid: kid(publicKeyFromSeed(seed)), sig };
}

/** Signs a breaker-reset envelope (spec §3). */
export function signBreakerReset(
  seed: Buffer,
  params: { tenant: string; tripRequestId: string; expiry: number },
): SignedBreakerReset {
  const obj = { tenant: params.tenant, trip_request_id: params.tripRequestId, decision: RESET, expiry: params.expiry };
  const sig = signRaw(seed, "stopbar-approval-breaker-reset-v1\n", obj);
  return { ...obj, kid: kid(publicKeyFromSeed(seed)), sig };
}
