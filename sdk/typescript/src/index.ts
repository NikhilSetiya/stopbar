// Stopbar TypeScript SDK — an intent firewall for an agent's actions.
//
//   import { Client, StopbarDenied, StopbarEscalated } from "stopbar";
//
//   const sb = new Client("http://127.0.0.1:7777", { apiKey: "stopbar_sk_...", tenant: "demo", agentId: "wallet-agent" });
//   try {
//     const d = await sb.evaluate(Client.evmTx({ ... }), { labels: ["untrusted_web"] });
//     broadcast(d.signedTx);                  // gatekeeper mode: Stopbar signed it
//   } catch (e) {
//     if (e instanceof StopbarEscalated) await sb.approve(e.requestId);  // once a human approves
//     else throw e;                           // StopbarDenied, StopbarUnavailable: never broadcast
//   }

export { Client, Decision, EscalationStatus, Session } from "./client.js";
export type { ClientOptions, EvaluateOptions, EvmTxParams } from "./client.js";
export { detectEncodings, KINDS } from "./encoding.js";
export type { Encoding } from "./encoding.js";
export {
  StopbarAuthError,
  StopbarDecisionError,
  StopbarDenied,
  StopbarError,
  StopbarEscalated,
  StopbarRequestError,
  StopbarUnavailable,
} from "./errors.js";
export type * from "./types.js";

export const VERSION = "0.1.0";
