// Tests for the approval module (CS-151): key files, kid, canonicalisation
// and signing. Parity with sdk/python/tests/test_approval.py.

import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, openSync, readFileSync, writeSync, closeSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { test } from "node:test";
import {
  APPROVE,
  generateKey,
  kid,
  loadKeyFile,
  signBreakerReset,
  signEscalation,
  writeKeyFile,
} from "stopbar";

function tmpFile(name = "approver.key"): string {
  return join(mkdtempSync(join(tmpdir(), "stopbar-test-")), name);
}

test("generateKey returns 32-byte seed and public key", () => {
  const { seed, publicKey } = generateKey();
  assert.equal(seed.length, 32);
  assert.equal(publicKey.length, 32);
});

test("writeKeyFile/loadKeyFile round-trip, mode 0600", () => {
  const { seed, publicKey } = generateKey();
  const path = tmpFile();
  writeKeyFile(path, seed);
  const mode = statSync(path).mode & 0o777;
  assert.equal(mode, 0o600);
  const loaded = loadKeyFile(path);
  assert.deepEqual(loaded, seed);
  const loadedPub = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicKey]),
    format: "der",
    type: "spki",
  });
  assert.ok(loadedPub); // just exercising that publicKey is a valid raw Ed25519 key
});

test("writeKeyFile refuses to overwrite an existing key", () => {
  const path = tmpFile();
  writeKeyFile(path, generateKey().seed);
  assert.throws(() => writeKeyFile(path, generateKey().seed));
});

test("loadKeyFile rejects loose permissions", () => {
  const path = tmpFile();
  writeKeyFile(path, generateKey().seed);
  chmodSync(path, 0o644);
  assert.throws(() => loadKeyFile(path));
});

test("loadKeyFile rejects the wrong tag", () => {
  const path = tmpFile("not-an-approver.key");
  const fd = openSync(path, "wx", 0o600);
  writeSync(fd, "stopbar-decision-key-ed25519-v1\nsomething\n");
  closeSync(fd);
  assert.throws(() => loadKeyFile(path));
});

test("kid is a deterministic RFC 7638 thumbprint", () => {
  const { publicKey } = generateKey();
  assert.equal(kid(publicKey), kid(publicKey));
  const other = generateKey();
  assert.notEqual(kid(other.publicKey), kid(publicKey));
});

test("signEscalation rejects an unknown decision", () => {
  const { seed } = generateKey();
  assert.throws(() => signEscalation(seed, { escalationId: "e", payloadHash: "h", policyBundleHash: "p", decision: "maybe", expiry: 1 }));
});

test("signEscalation/signBreakerReset carry the signer's kid", () => {
  const { seed, publicKey } = generateKey();
  const s = signEscalation(seed, { escalationId: "esc_1", payloadHash: "sha256:" + "a".repeat(64), policyBundleHash: "sha256:" + "b".repeat(64), decision: APPROVE, expiry: 4102444800 });
  assert.equal(s.kid, kid(publicKey));
  assert.ok(s.sig.length > 0);
  const r = signBreakerReset(seed, { tenant: "acme", tripRequestId: "req_1", expiry: 4102444800 });
  assert.equal(r.kid, kid(publicKey));
  assert.equal(r.decision, "reset");
});

test("the signature actually verifies with raw Ed25519 (and a tampered field does not)", () => {
  // Cross-checks against a hand-rolled verifier using the same domain
  // separation and canonicalisation the Go core uses
  // (spec/approval-signature-v1.md §4), so a bug here fails closed.
  const { seed, publicKey } = generateKey();
  const obj = { escalation_id: "esc_1", payload_hash: "sha256:" + "a".repeat(64), policy_bundle_hash: "sha256:" + "b".repeat(64), decision: APPROVE, expiry: 4102444800 };
  const s = signEscalation(seed, { escalationId: obj.escalation_id, payloadHash: obj.payload_hash, policyBundleHash: obj.policy_bundle_hash, decision: obj.decision, expiry: obj.expiry });

  const canonical = (o: Record<string, unknown>) => {
    const ordered: Record<string, unknown> = {};
    for (const k of Object.keys(o).sort()) ordered[k] = o[k];
    return Buffer.from(JSON.stringify(ordered));
  };
  const pubKeyObj = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicKey]),
    format: "der",
    type: "spki",
  });
  const msg = Buffer.concat([Buffer.from("stopbar-approval-escalation-v2\n"), canonical(obj)]);
  assert.ok(cryptoVerify(null, msg, pubKeyObj, Buffer.from(s.sig, "base64url")));

  const tamperedMsg = Buffer.concat([Buffer.from("stopbar-approval-escalation-v2\n"), canonical({ ...obj, escalation_id: "esc_2" })]);
  assert.equal(cryptoVerify(null, tamperedMsg, pubKeyObj, Buffer.from(s.sig, "base64url")), false);
});

test("signatures match the Go conformance vectors byte for byte", () => {
  // Ed25519 is deterministic: re-signing each OK vector with its key's seed
  // must reproduce spec/vectors/approval-signature-v1.json exactly.
  const vf = JSON.parse(readFileSync(new URL("../../../../spec/vectors/approval-signature-v1.json", import.meta.url), "utf8"));
  const seeds = new Map<string, Buffer>(vf.keys.map((k: { kid: string; seed_hex: string }) => [k.kid, Buffer.from(k.seed_hex, "hex")]));
  let checked = 0;
  for (const v of vf.escalations) {
    const e = v.envelope;
    if (v.result !== "OK" || !seeds.has(e.kid)) continue;
    const s = signEscalation(seeds.get(e.kid)!, { escalationId: e.escalation_id, payloadHash: e.payload_hash, policyBundleHash: e.policy_bundle_hash, decision: e.decision, expiry: e.expiry });
    assert.deepEqual(s, e, v.name);
    checked++;
  }
  for (const v of vf.breaker_resets) {
    const e = v.envelope;
    if (v.result !== "OK") continue;
    assert.deepEqual(signBreakerReset(seeds.get(e.kid)!, { tenant: e.tenant, tripRequestId: e.trip_request_id, expiry: e.expiry }), e, v.name);
    checked++;
  }
  assert.ok(checked >= 3);
});
