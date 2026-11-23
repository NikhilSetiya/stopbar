# Stopbar TypeScript SDK

An **intent firewall** for an AI agent's actions: nothing gets signed or executed
unless an independent policy engine (stopbard) in a separate trust domain clears
it first. This SDK is the in-process client agent builders use to send actions to
Stopbar and act on the decision. Parity with the Python SDK (`sdk/python`).

**Zero runtime dependencies**: it uses the global `fetch` (Node >= 20).

## Install

```bash
npm install stopbar
```

## Use

```ts
import { Client, StopbarDenied, StopbarEscalated } from "stopbar";

const sb = new Client("http://127.0.0.1:7777", {
  apiKey: "stopbar_sk_...",            // from `stopbar keygen api-key`
  tenant: "demo", agentId: "wallet-agent",
});

const action = Client.evmTx({
  chainId: 8453, from: myWallet, to: recipient, valueWei: "5000000000000000000",
  txNonce: "0", gasLimit: "21000", maxFeePerGas: "200000000", maxPriorityFeePerGas: "100000000",
});

try {
  const d = await sb.evaluate(action, { labels: ["untrusted_web"] });  // provenance taint
  await broadcast(d.signedTx);          // gatekeeper mode: Stopbar already signed it
} catch (e) {
  if (e instanceof StopbarDenied) console.log("forbidden:", e.reasons);        // 403, for any caller
  else if (e instanceof StopbarEscalated) {
    console.log("needs approval:", e.requestId);                               // 202, hold it for a human
    const approved = await operator.approve(e.requestId);                      // re-evaluates against current state
    await broadcast(approved.signedTx);
  } else throw e;                       // StopbarUnavailable / StopbarAuthError: fail closed
}
```

**The HTTP status alone is safe to act on:** 200 is allow and only allow, 202 is
escalate, 403 is deny. `evaluate` resolves with the `Decision` on an allow and
rejects with a typed error otherwise, so a missed check can never read a deny as
an allow. An unreachable server, a timeout or any non-decision response rejects
with `StopbarUnavailable`: treat it as a deny.

Outside gatekeeper mode, report what happened to an allowed action so its limiter
reservation is committed or released: `sb.commit(requestId, txRef)` /
`sb.release(requestId)` (`POST /v1/actions/{id}/commit|release`, LLD §4.1).

### Provenance labels (taint)

A `Session` accumulates labels as the agent encounters untrusted input; they ride
on every request and only ever grow (taint is monotonic in v1):

```ts
const s = sb.session(["trusted_user"]);
s.add(pageText, "untrusted_web", { ref: url });   // after the agent reads web content
await s.evaluate(action);                          // both labels (and the source) attached
```

`add` scans every input not labelled `trusted_*` for encoded content — base64,
hex, Morse, ROT-n and zero-width characters — and adds `decoded` when it finds
any (the Grok/Bankr pattern: an instruction hidden in Morse in on-chain content).
Base64 and hex count only when they decode to readable text, so addresses, hashes
and calldata don't trip it. `detectEncodings(text)` exposes the detector.

> Labels are *claims* from the requester. In v1 they hold against an injected
> model with an honest harness (T1); against a compromised requester (T3) only
> the controls inside Stopbar — caps, allowlists, the circuit breaker and
> gatekeeper mode — hold.

## Develop

```bash
npm ci && npm test          # tsc + node:test against a mock server
```

`examples/protect-agent.ts` runs end to end against a real stopbard;
`scripts/e2e_sdk.sh` (part of `make e2e` and CI) starts one and runs it.

## License

Apache-2.0.
