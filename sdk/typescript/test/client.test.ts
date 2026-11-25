// Client tests against a mock stopbard (an in-process HTTP server), so they
// need no running service. They exercise the real request shape, the label
// plumbing and the typed-error mapping for each outcome. Parity with
// sdk/python/tests/test_client.py.

import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { Client, StopbarAuthError, StopbarDenied, StopbarEscalated, StopbarRequestError, StopbarUnavailable, generateKey } from "stopbar";
import { client, evm, serve, servers, type Responder } from "./mock.js";

// A fresh approver key for the approve/reject tests below; its own
// signature shape and canonicalisation are covered in approval.test.ts.
const approver = generateKey();

test("allow returns the decision with signed tx", async () => {
  const m = await serve((_, b) => [200, { request_id: b.id, outcome: "allow", signed_tx: "0xdeadbeef" }]);
  const d = await client(m, { apiKey: "stopbar_sk_test" }).evaluate(evm(), { labels: ["untrusted_web"] });
  assert.equal(d.outcome, "allow");
  assert.equal(d.signedTx, "0xdeadbeef");
  const b = m.last.body;
  assert.equal(m.last.auth, "Bearer stopbar_sk_test");
  assert.equal(b.tenant, "demo");
  assert.equal(b.actor.agent_id, "wallet-agent");
  assert.deepEqual(b.provenance, { labels: ["untrusted_web"] });
  assert.equal(b.action.kind, "evm_tx");
  assert.equal(typeof b.action.value_wei, "string"); // never a JSON number
  assert.match(b.id, /^req_[0-9a-f]{32}$/);
  assert.ok(b.nonce.length >= 16);
  assert.match(b.issued_at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  assert.equal(b.ttl_seconds, 60);
});

test("evmTx binds every EIP-1559 field as a lowercase/decimal string", () => {
  const a = Client.evmTx({ chainId: 8453, from: "0xABCDEF" + "0".repeat(34), to: "0x" + "A".repeat(40), data: "0xA9059CBB",
    txNonce: "7", gasLimit: "21000", maxFeePerGas: "2", maxPriorityFeePerGas: "1" });
  assert.deepEqual(a, { kind: "evm_tx", chain_id: 8453, from: "0xabcdef" + "0".repeat(34), to: "0x" + "a".repeat(40),
    value_wei: "0", data: "0xa9059cbb", tx_type: 2, tx_nonce: "7", gas_limit: "21000", max_fee_per_gas: "2",
    max_priority_fee_per_gas: "1" });
});

test("deny rejects with StopbarDenied", async () => {
  const m = await serve((_, b) => [403, { request_id: b.id, outcome: "deny", reasons: [{ policy_id: "unlimited-approval", message: "" }] }]);
  await assert.rejects(client(m).evaluate(evm()), (e: unknown) =>
    e instanceof StopbarDenied && e.status === 403 && e.reasons.join() === "unlimited-approval");
});

test("escalate rejects with request id, then approve", async () => {
  const m = await serve((p, b, method) => {
    if (p.startsWith("/v1/approvals/") && method === "GET") {
      return [200, { escalation_id: p.split("/").pop(), payload_hash: "sha256:" + "a".repeat(64), tenant: "demo" }];
    }
    if (p.startsWith("/v1/approvals/")) {
      assert.equal(b.decision, "approve");
      assert.ok(b.kid && b.sig); // genuinely signed
      return [200, { request_id: p.split("/").pop(), outcome: "allow", signed_tx: "0xabc" }];
    }
    return [202, { request_id: b.id, outcome: "escalate", reasons: [{ policy_id: "large-share-of-balance", message: "" }] }];
  });
  const sb = client(m, { apiKey: "k" });
  const e = await sb.evaluate(evm()).catch((x: unknown) => x);
  assert.ok(e instanceof StopbarEscalated);
  assert.ok(e.requestId);
  assert.deepEqual(e.reasons, ["large-share-of-balance"]);
  const ok = await sb.approve(e.requestId, approver.seed);
  assert.equal(ok.outcome, "allow");
  assert.equal(ok.signedTx, "0xabc");
  assert.equal(m.last.path, `/v1/approvals/${e.requestId}`);
  assert.equal(m.last.method, "POST");
});

test("session labels are monotonic", async () => {
  const m = await serve((_, b) => [200, { request_id: b.id, outcome: "allow" }]);
  const s = client(m).session(["trusted_user"]);
  s.addLabel("untrusted_web").addLabel("untrusted_web"); // dedup
  s.labels.push("tampered"); // a copy: the session cannot be untainted from outside
  await s.evaluate(evm(), { labels: ["untrusted_onchain"] });
  assert.deepEqual(m.last.body.provenance.labels, ["trusted_user", "untrusted_web", "untrusted_onchain"]);
  assert.deepEqual(s.labels, ["trusted_user", "untrusted_web"]);
});

test("auth errors map to StopbarAuthError", async () => {
  for (const [status, code] of [[401, "UNAUTHENTICATED"], [403, "FORBIDDEN_SCOPE"]] as const) {
    const m = await serve(() => [status, { code }]);
    await assert.rejects(client(m).evaluate(evm()), StopbarAuthError);
  }
});

test("non-decision errors and malformed bodies fail closed", async () => {
  for (const [status, body] of [[503, { code: "ENGINE_UNAVAILABLE" }], [500, "not json"], [201, {}], [400, { code: "INVALID_REQUEST" }]] as const) {
    const m = await serve(() => [status, body]);
    await assert.rejects(client(m).evaluate(evm()), StopbarUnavailable, `HTTP ${status}`);
  }
});

test("unreachable fails closed", async () => {
  await assert.rejects(new Client("http://127.0.0.1:1", { timeoutMs: 1000 }).evaluate(evm()), StopbarUnavailable);
});

test("timeout fails closed", async () => {
  const srv = createServer(() => {}); // never answers
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const sb = new Client(`http://127.0.0.1:${(srv.address() as AddressInfo).port}`, { timeoutMs: 200 });
  await assert.rejects(sb.evaluate(evm()), StopbarUnavailable);
  srv.closeAllConnections();
});

test("commit and release settle the reservation", async () => {
  const m = await serve((p) => [200, { request_id: "req_1", state: p.endsWith("/commit") ? "committed" : "released" }]);
  const sb = client(m, { apiKey: "k" });
  assert.equal((await sb.commit("req_1", "0xabc")).state, "committed");
  assert.deepEqual([m.last.method, m.last.path, m.last.body], ["POST", "/v1/actions/req_1/commit", { tx_ref: "0xabc" }]);
  assert.equal((await sb.release("req_1", "user cancelled")).state, "released");
  assert.deepEqual([m.last.path, m.last.body], ["/v1/actions/req_1/release", { reason: "user cancelled" }]);
  await sb.release("req/../x"); // an id is one path segment, never a path
  assert.deepEqual([m.last.path, m.last.body], ["/v1/actions/req%2F..%2Fx/release", {}]);
  assert.equal(m.last.auth, "Bearer k");
});

test("lifecycle refusals are typed", async () => {
  for (const [status, code] of [[404, "NOT_FOUND"], [409, "CONFLICT"], [410, "RESERVATION_EXPIRED"], [400, "INVALID_REQUEST"]] as const) {
    const sb = client(await serve(() => [status, { code }]));
    await assert.rejects(sb.commit("req_1", "0xabc"), (e: unknown) => e instanceof StopbarRequestError && e.status === status && e.code === code);
    await assert.rejects(sb.poll("req_1"), StopbarRequestError);
  }
  await assert.rejects(client(await serve(() => [403, { code: "FORBIDDEN_SCOPE" }])).release("req_1"), StopbarAuthError);
  await assert.rejects(client(await serve(() => [500, { code: "INTERNAL" }])).commit("req_1", "0x1"), StopbarUnavailable);
});

test("poll reports the escalation state", async () => {
  for (const [status, state, allowed] of [[202, "pending", false], [200, "allowed", true], [403, "denied", false], [403, "expired", false]] as const) {
    const m = await serve(() => [status, { request_id: "req_1", state, decision: { request_id: "req_1", outcome: allowed ? "allow" : "deny", token: "t" } }]);
    const st = await client(m, { apiKey: "k" }).poll("req_1");
    assert.deepEqual([m.last.method, m.last.path, m.last.body], ["GET", "/v1/decisions/req_1", null]);
    assert.equal(st.state, state);
    assert.equal(st.allowed, allowed);
    assert.equal(st.decision?.outcome, allowed ? "allow" : "deny");
  }
});

// escalationToSign answers the GET /v1/approvals/{id} half of a mock, for
// any approve/reject test below.
function escalationToSign(method: string): [number, unknown] | undefined {
  if (method === "GET") return [200, { escalation_id: "req_1", payload_hash: "sha256:" + "a".repeat(64), tenant: "demo" }];
  return undefined;
}

test("reject resolves with the APPROVAL_REJECTED deny", async () => {
  const deny = { request_id: "req_1", outcome: "deny", reasons: [{ policy_id: "large-share-of-balance", message: "" }, { code: "APPROVAL_REJECTED", policy_id: "", message: "" }] };
  const m = await serve((_p, b, method) => escalationToSign(method) ?? (() => {
    assert.equal(b.decision, "reject");
    assert.ok(b.kid && b.sig);
    return [403, deny] as [number, unknown];
  })());
  const d = await client(m, { apiKey: "ops" }).reject("req_1", approver.seed);
  assert.deepEqual([m.last.method, m.last.path], ["POST", "/v1/approvals/req_1/reject"]);
  assert.equal(d.outcome, "deny");
  assert.deepEqual(d.reasons, ["large-share-of-balance", "APPROVAL_REJECTED"]);
});

test("reject refusals are typed", async () => {
  const self = { request_id: "req_1", outcome: "deny", reasons: [{ code: "APPROVAL_SELF_APPROVAL", policy_id: "", message: "" }] };
  const withGet = (postResult: [number, unknown]): Responder => (_p, _b, method) => escalationToSign(method) ?? postResult;
  await assert.rejects(client(await serve(withGet([403, self]))).reject("req_1", approver.seed), StopbarDenied);
  await assert.rejects(client(await serve(withGet([409, { code: "ALREADY_RESOLVED" }]))).reject("req_1", approver.seed), StopbarRequestError);
  await assert.rejects(client(await serve(withGet([403, { code: "FORBIDDEN_SCOPE" }]))).reject("req_1", approver.seed), StopbarAuthError);
  await assert.rejects(client(await serve(withGet([200, { outcome: "allow" }]))).reject("req_1", approver.seed), StopbarUnavailable);
});
