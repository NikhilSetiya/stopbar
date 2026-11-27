// Off-chain signature requests (CS-514): action builders and the decision's
// signature fields. Parity with sdk/python/tests/test_offchain.py.

import assert from "node:assert/strict";
import { test } from "node:test";
import { Client, type TypedData } from "stopbar";
import { client, serve } from "./mock.js";

const typed = {
  types: { EIP712Domain: [{ name: "name", type: "string" }, { name: "chainId", type: "uint256" }],
    Mail: [{ name: "n", type: "uint256" }, { name: "ok", type: "bool" }, { name: "raw", type: "bytes" }] },
  primaryType: "Mail",
  domain: { name: "x", chainId: 8453 },
  message: { n: 2n ** 200n, ok: true, raw: new Uint8Array([1, 2]) },
} as unknown as TypedData;

test("evmTypedData stringifies integers and hexes bytes", () => {
  const a = Client.evmTypedData({ chainId: 8453, from: "0x" + "A".repeat(40), typedData: typed });
  assert.equal(a.kind, "evm_typed_data");
  assert.equal(a.from, "0x" + "a".repeat(40));
  assert.deepEqual(a.typed_data?.message, { n: (2n ** 200n).toString(), ok: true, raw: "0x0102" });
  assert.equal(a.typed_data?.domain.chainId, "8453");
});

test("evmPersonalSign takes text, bytes or 0x hex", () => {
  const f = "0x" + "1".repeat(40);
  assert.equal(Client.evmPersonalSign({ chainId: 1, from: f, message: "hi" }).message, "0x6869");
  assert.equal(Client.evmPersonalSign({ chainId: 1, from: f, message: "0xABCD" }).message, "0xabcd");
  assert.equal(Client.evmPersonalSign({ chainId: 1, from: f, message: new Uint8Array([0, 255]) }).message, "0x00ff");
  assert.equal(Client.evmPersonalSign({ chainId: 1, from: f, message: "0xnot hex" }).message, "0x" + Buffer.from("0xnot hex").toString("hex"));
});

test("allow carries the signature and its digest", async () => {
  const m = await serve((_, b) => [200, { request_id: b.id, outcome: "allow", signature: "0x" + "ab".repeat(65), signing_hash: "0x" + "cd".repeat(32) }]);
  const d = await client(m).evaluate(Client.evmTypedData({ chainId: 8453, from: "0x" + "1".repeat(40), typedData: typed }));
  assert.equal(d.signature, "0x" + "ab".repeat(65));
  assert.equal(d.signingHash, "0x" + "cd".repeat(32));
  assert.equal(d.signedTx, undefined);
  assert.equal(m.last.body.action.typed_data.message.n, (2n ** 200n).toString());
});
