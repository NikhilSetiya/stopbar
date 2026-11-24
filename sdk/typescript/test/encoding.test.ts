// CS-183: the encoding detector, on the fixtures shared with the Python SDK
// (sdk/testdata/encodings.json), and the Session wiring that turns a hit in
// untrusted input into the 'decoded' label.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { detectEncodings, StopbarDenied } from "stopbar";
import { client, evm, serve } from "./mock.js";

// dist/test/encoding.test.js -> sdk/testdata
const F = JSON.parse(readFileSync(new URL("../../../testdata/encodings.json", import.meta.url), "utf8"));

for (const c of F.encoded) {
  test(`encoded: ${c.name} -> ${c.kinds}`, () => assert.deepEqual(detectEncodings(c.text), c.kinds));
}

for (const c of F.plain) {
  test(`plain: ${c.name} is not flagged`, () => assert.deepEqual(detectEncodings(c.text), []));
}

test("Grok-pattern fixture (CS-2026-0001) is labelled decoded", async () => {
  const g = F.grok;
  const m = await serve((_, b) => [403, { request_id: b.id, outcome: "deny", reasons: [{ policy_id: "taint-unknown-destination", message: "" }] }]);
  const s = client(m).session().add(g.text, g.label, { ref: g.ref });
  assert.deepEqual(s.labels, g.labels);
  await assert.rejects(s.evaluate(evm()), StopbarDenied);
  assert.deepEqual(m.last.body.provenance, {
    labels: g.labels,
    sources: [{ label: g.label, ref: g.ref }, { label: "decoded", ref: g.ref }],
  });
});

test("only untrusted input is scanned", async () => {
  const m = await serve(() => [200, {}]);
  const g = F.grok;
  assert.deepEqual(client(m).session().add(g.text, "trusted_user").labels, ["trusted_user"]);
  assert.deepEqual(client(m).session().add(F.plain[0].text, "untrusted_web").labels, ["untrusted_web"]);
  assert.deepEqual(client(m).session().add(g.text, "tool_output").labels, ["tool_output", "decoded"]);
});
