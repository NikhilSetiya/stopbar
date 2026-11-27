// Stopbar client: an in-process firewall for an agent's actions.
//
// The agent builds an action as usual; the SDK sends it to Stopbar's
// /v1/evaluate and resolves with the signed decision only on an allow,
// rejecting with a typed error on a deny or escalate. Provenance labels (the
// agent's taint for the current context) ride on every request. Zero runtime
// dependencies: global fetch (Node >= 20), or node:https for mTLS.

import { randomBytes, randomUUID } from "node:crypto";
import { request as httpsRequest } from "node:https";
import { APPROVE, REJECT, loadKeyFile, signEscalation } from "./approval.js";
import { detectEncodings } from "./encoding.js";
import { StopbarAuthError, StopbarDenied, StopbarEscalated, StopbarRequestError, StopbarUnavailable, reasonIds } from "./errors.js";
import type { Action, ActionRequest, DecisionBody, ErrorBody, Label, Source, TypedData } from "./types.js";

/** An approver key: a raw 32-byte Ed25519 seed, or a path to a key file
 * written by `stopbar approver keygen` / approval.writeKeyFile. */
export type ApproverKey = Buffer | string;

/** Typed data as Stopbar takes it: integers (number, bigint) as decimal
 * strings, never JSON numbers beyond 2^53; bytes as 0x hex. */
function typedJson(v: unknown): unknown {
  if (typeof v === "bigint" || (typeof v === "number" && Number.isInteger(v))) return v.toString();
  if (v instanceof Uint8Array) return "0x" + Buffer.from(v).toString("hex");
  if (Array.isArray(v)) return v.map(typedJson);
  if (v !== null && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, typedJson(x)]));
  return v;
}

function approverSeed(key: ApproverKey): Buffer {
  return Buffer.isBuffer(key) ? key : loadKeyFile(key);
}

/** A Stopbar decision. `outcome` is "allow", "escalate" or "deny"; in
 * gatekeeper mode an allow carries `signedTx` and `txHash`. */
export class Decision {
  constructor(readonly status: number, readonly body: DecisionBody) {}
  get outcome(): string { return this.body.outcome ?? ""; }
  get requestId(): string { return this.body.request_id ?? ""; }
  get signedTx(): string | undefined { return this.body.signed_tx; }
  get txHash(): string | undefined { return this.body.tx_hash; }
  /** Gatekeeper mode, off-chain requests (CS-514): the signature and the digest it signs. */
  get signature(): string | undefined { return this.body.signature; }
  get signingHash(): string | undefined { return this.body.signing_hash; }
  get token(): string | undefined { return this.body.token; }
  get reasons(): string[] { return reasonIds(this.body); }
}

/** GET /v1/decisions/{id}: where an escalation is. `state` is "pending",
 * "allowed", "denied" or "expired"; `decision` is the escalate decision while
 * pending and the final one after (with the token, and in gatekeeper mode the
 * signed tx, once allowed). Only `allowed` is safe to act on. */
export class EscalationStatus {
  constructor(readonly status: number, readonly body: Record<string, unknown>) {}
  get state(): string { return typeof this.body.state === "string" ? this.body.state : ""; }
  get allowed(): boolean { return this.status === 200 && this.state === "allowed"; }
  get decision(): Decision | undefined {
    const d = this.body.decision;
    return d !== null && typeof d === "object" ? new Decision(this.status, d as DecisionBody) : undefined;
  }
}

export interface ClientOptions {
  /** Bearer secret from `stopbar keygen api-key` (omit only for loopback dev with auth off). */
  apiKey?: string;
  /** Must match the key's identity: Stopbar derives identity from the key and rejects a mismatched body. */
  tenant?: string;
  agentId?: string;
  sessionId?: string;
  timeoutMs?: number;
  /** mTLS (CS-103): a stopbard serving https with client-certificate auth. The
   * certificate's SPIFFE ID is the identity, so omit apiKey. PEM contents;
   * `ca` is the CA that issued stopbard's server certificate (default: system roots). */
  tls?: { cert: string | Buffer; key: string | Buffer; ca?: string | Buffer };
}

export interface EvaluateOptions {
  labels?: Label[];
  sources?: Source[];
  requestId?: string;
  nonce?: string;
  ttlSeconds?: number;
}

export interface EvmTxParams {
  chainId: number;
  from: string;
  to: string;
  valueWei?: string;
  data?: string;
  txNonce: string;
  gasLimit: string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
}

/** A client for one Stopbar deployment and one agent identity. */
export class Client {
  readonly baseUrl: string;
  readonly apiKey?: string;
  readonly tenant: string;
  readonly agentId: string;
  readonly sessionId: string;
  readonly timeoutMs: number;
  readonly #tls?: ClientOptions["tls"];

  constructor(baseUrl: string, opts: ClientOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    this.tenant = opts.tenant ?? "default";
    this.agentId = opts.agentId ?? "agent";
    this.sessionId = opts.sessionId ?? randomUUID();
    this.timeoutMs = opts.timeoutMs ?? 15_000;
    if (opts.tls && !(opts.tls.cert && opts.tls.key)) throw new Error("tls needs both cert and key");
    this.#tls = opts.tls;
  }

  /** A Session accumulates provenance labels (monotonic taint) that ride on
   * every request it evaluates — e.g. `add(page, "untrusted_web")` after the
   * agent reads web content, and it stays attached for the rest of the session. */
  session(labels: Label[] = []): Session {
    return new Session(this, labels);
  }

  /** Build an EIP-1559 action. Amounts are decimal strings (wei exceeds 2^53,
   * so never JSON numbers). The requester sends the complete unsigned
   * transaction; Stopbar binds every field. */
  static evmTx(p: EvmTxParams): Action {
    return {
      kind: "evm_tx", chain_id: p.chainId, from: p.from.toLowerCase(), to: p.to.toLowerCase(),
      value_wei: String(p.valueWei ?? "0"), data: (p.data ?? "0x").toLowerCase(), tx_type: 2, tx_nonce: String(p.txNonce),
      gas_limit: String(p.gasLimit), max_fee_per_gas: String(p.maxFeePerGas),
      max_priority_fee_per_gas: String(p.maxPriorityFeePerGas),
    };
  }

  evmTx(p: EvmTxParams): Action {
    return Client.evmTx(p);
  }

  /** Build an off-chain EIP-712 signature request (eth_signTypedData_v4,
   * CS-514). Stopbar decodes it like the approval or transfer it authorises
   * (Permit, Permit2, Seaport) and binds the exact payload. Integers (number
   * or bigint) become decimal strings, since uint256 values exceed 2^53. */
  static evmTypedData(p: { chainId: number; from: string; typedData: TypedData }): Action {
    return { kind: "evm_typed_data", chain_id: p.chainId, from: p.from.toLowerCase(), typed_data: typedJson(p.typedData) as TypedData };
  }

  /** Build an EIP-191 personal_sign request. `message` is text (UTF-8), raw
   * bytes, or a 0x-hex string taken as bytes, as wallets do. */
  static evmPersonalSign(p: { chainId: number; from: string; message: string | Uint8Array }): Action {
    const m = p.message;
    const hex = typeof m !== "string" ? Buffer.from(m).toString("hex")
      : /^0x([0-9a-fA-F]{2})+$/.test(m) ? m.slice(2).toLowerCase() : Buffer.from(m, "utf8").toString("hex");
    return { kind: "evm_personal_sign", chain_id: p.chainId, from: p.from.toLowerCase(), message: "0x" + hex };
  }

  /** Send an action to Stopbar. Resolves with the Decision on an allow; rejects
   * with StopbarDenied (403), StopbarEscalated (202), StopbarAuthError (401/403
   * auth) or StopbarUnavailable (unreachable / non-decision error). */
  async evaluate(action: Action, opts: EvaluateOptions = {}): Promise<Decision> {
    const body: ActionRequest = {
      id: opts.requestId ?? "req_" + randomUUID().replace(/-/g, ""),
      tenant: this.tenant,
      nonce: opts.nonce ?? randomBytes(18).toString("base64url"),
      issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      ttl_seconds: opts.ttlSeconds ?? 60,
      actor: { agent_id: this.agentId, session_id: this.sessionId },
      action,
      provenance: { labels: [...new Set(opts.labels ?? [])] },
    };
    if (opts.sources?.length) body.provenance.sources = [...opts.sources];
    return this.decision(...(await this.request("POST", "/v1/evaluate", body)));
  }

  /** Approve a pending escalation (CS-151): fetches what to sign from Stopbar
   * (GET /v1/approvals/{id}), signs it locally with approverKey — a raw
   * 32-byte Ed25519 seed, or a path to a key file written by
   * `stopbar approver keygen` / approval.writeKeyFile — and submits the
   * signature. The private key never leaves this process. On quorum,
   * Stopbar re-evaluates against current state; on an allow the Decision
   * carries the signed transaction. */
  async approve(requestId: string, approverKey: ApproverKey): Promise<Decision> {
    const sig = await this.signEscalation(requestId, approverKey, APPROVE);
    return this.decision(...(await this.request("POST", `/v1/approvals/${seg(requestId)}`, sig)));
  }

  /** Signs and submits a reject (CS-151): one valid reject denies the
   * escalation outright, audited with the rejecting owner. approverKey is
   * as for approve(). Resolves with the deny (reason APPROVAL_REJECTED);
   * rejects with StopbarDenied if Stopbar refused the signature itself,
   * StopbarRequestError for an unknown or already-resolved escalation. */
  async reject(requestId: string, approverKey: ApproverKey): Promise<Decision> {
    const sig = await this.signEscalation(requestId, approverKey, REJECT);
    const [status, body] = await this.request("POST", `/v1/approvals/${seg(requestId)}/reject`, sig);
    const d = body as unknown as DecisionBody;
    if (status === 403 && d.outcome === "deny" && d.reasons?.at(-1)?.code === "APPROVAL_REJECTED") return new Decision(status, d);
    refusal(status, body);
    if (status !== 200) this.decision(status, body); // throws: escalate / deny / unavailable
    throw new StopbarUnavailable(`Stopbar answered a reject with HTTP ${status}: not a rejection`);
  }

  private async signEscalation(requestId: string, approverKey: ApproverKey, decision: string) {
    const seed = approverSeed(approverKey);
    const [status, body] = await this.request("GET", `/v1/approvals/${seg(requestId)}`);
    if (status !== 200) {
      refusal(status, body);
      throw new StopbarUnavailable(`could not fetch what to sign (HTTP ${status}): ${(body as ErrorBody).code ?? JSON.stringify(body)}`);
    }
    return signEscalation(seed, {
      escalationId: String(body.escalation_id), payloadHash: String(body.payload_hash),
      policyBundleHash: String(body.policy_bundle_hash), decision,
      expiry: Math.floor(Date.now() / 1000) + 50 * 60, // comfortably under the 1h bound
    });
  }

  /** The escalation's current state (GET /v1/decisions/{id}). Visible to the
   * requesting agent and its tenant's approvers. A pending escalation past its
   * approval window comes back expired (a deny). */
  async poll(requestId: string): Promise<EscalationStatus> {
    const [status, body] = await this.request("GET", `/v1/decisions/${seg(requestId)}`);
    if ((status === 200 || status === 202 || status === 403) && body.state) return new EscalationStatus(status, body);
    refusal(status, body);
    throw new StopbarUnavailable(`Stopbar returned HTTP ${status}: ${(body as ErrorBody).code ?? JSON.stringify(body)}`);
  }

  /** Report that an allowed action was broadcast (txRef: its tx hash), turning
   * its reservation into committed spend (LLD §4.1). Retrying with the same
   * txRef is safe. Resolves with the body (`{state: "committed", late: true}`
   * if the reservation had lapsed: the spend is still recorded). */
  commit(requestId: string, txRef: string): Promise<Record<string, unknown>> {
    return this.settle(requestId, "commit", { tx_ref: txRef });
  }

  /** Abandon an allowed action and free its reservation. Retrying is safe. */
  release(requestId: string, reason?: string): Promise<Record<string, unknown>> {
    return this.settle(requestId, "release", reason ? { reason } : {});
  }

  private async settle(requestId: string, verb: string, body: object): Promise<Record<string, unknown>> {
    const [status, out] = await this.request("POST", `/v1/actions/${seg(requestId)}/${verb}`, body);
    if (status === 200) return out;
    refusal(status, out);
    throw new StopbarUnavailable(`Stopbar returned HTTP ${status}: ${(out as ErrorBody).code ?? JSON.stringify(out)}`);
  }

  private decision(status: number, body: Record<string, unknown>): Decision {
    const d = body as unknown as DecisionBody;
    if (status === 200) return new Decision(status, d);
    if (status === 202) throw new StopbarEscalated(status, d);
    if (status === 403 && d.outcome === "deny") throw new StopbarDenied(status, d);
    const e = body as ErrorBody;
    if (status === 401 || status === 403) throw new StopbarAuthError(`Stopbar auth failed (HTTP ${status}): ${e.code ?? e.message}`);
    throw new StopbarUnavailable(`Stopbar returned HTTP ${status}: ${e.code ?? e.message ?? JSON.stringify(body)}`);
  }

  private async request(method: string, path: string, body?: unknown): Promise<[number, Record<string, unknown>]> {
    const headers: Record<string, string> = body === undefined ? {} : { "Content-Type": "application/json" };
    if (this.apiKey) headers.Authorization = "Bearer " + this.apiKey;
    const payload = body === undefined ? undefined : JSON.stringify(body);
    let status: number;
    let text: string;
    try {
      if (this.#tls) {
        [status, text] = await this.mtlsRequest(method, path, headers, payload);
      } else {
        const res = await fetch(this.baseUrl + path, { method, headers, body: payload, signal: AbortSignal.timeout(this.timeoutMs) });
        [status, text] = [res.status, await res.text()];
      }
    } catch (err) {
      // unreachable, reset, refused handshake or timed out: fail closed
      throw new StopbarUnavailable(`Stopbar unreachable at ${this.baseUrl}: ${(err as Error).message}`, { cause: err });
    }
    return [status, parse(text)];
  }

  // Global fetch cannot present a client certificate, so mTLS uses node:https.
  private mtlsRequest(method: string, path: string, headers: Record<string, string>, payload?: string): Promise<[number, string]> {
    const { cert, key, ca } = this.#tls!;
    return new Promise((resolve, reject) => {
      const req = httpsRequest(this.baseUrl + path, { method, headers, cert, key, ca, minVersion: "TLSv1.3", timeout: this.timeoutMs }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve([res.statusCode ?? 0, Buffer.concat(chunks).toString("utf8")]));
        res.on("error", reject);
      });
      req.on("timeout", () => req.destroy(new Error("timed out")));
      req.on("error", reject);
      req.end(payload);
    });
  }
}

// Throw the typed error for a non-decision refusal, if it is one.
function refusal(status: number, body: Record<string, unknown>): void {
  const e = body as ErrorBody;
  if (status === 401 || (status === 403 && e.code)) throw new StopbarAuthError(`Stopbar auth failed (HTTP ${status}): ${e.code ?? e.message}`);
  if ([400, 404, 409, 410, 413, 415].includes(status)) throw new StopbarRequestError(status, e);
}

// A request id as one URL path segment.
const seg = (id: string) => encodeURIComponent(id);

function parse(text: string): Record<string, unknown> {
  try {
    const v: unknown = JSON.parse(text);
    return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : { value: v };
  } catch {
    return {};
  }
}

/** A client bound to a growing set of provenance labels. Labels only ever
 * accumulate (taint is monotonic), matching Stopbar's v1 trust model. */
export class Session {
  #labels: Label[] = [];
  #sources: Source[] = [];

  constructor(readonly client: Client, labels: Label[] = []) {
    labels.forEach((l) => this.addLabel(l));
  }

  get labels(): Label[] { return [...this.#labels]; }
  get sources(): Source[] { return [...this.#sources]; }

  addLabel(label: Label): this {
    if (!this.#labels.includes(label)) this.#labels.push(label);
    return this;
  }

  /** Record content entering the agent's context under `label` (LLD §8.2).
   * Any input not labelled `trusted_*` is scanned for encoded content (base64,
   * hex, Morse, ROT-n, zero-width); if any is found the session also gains
   * `decoded` (CS-183). `ref` (a URL, tx hash…) is recorded as a source. */
  add(content: string, label: Label, opts: { ref?: string } = {}): this {
    this.addLabel(label);
    const decoded = !label.startsWith("trusted_") && detectEncodings(content).length > 0;
    if (decoded) this.addLabel("decoded");
    if (opts.ref !== undefined) {
      this.#sources.push({ label, ref: opts.ref });
      if (decoded) this.#sources.push({ label: "decoded", ref: opts.ref });
    }
    return this;
  }

  evaluate(action: Action, opts: EvaluateOptions = {}): Promise<Decision> {
    return this.client.evaluate(action, {
      ...opts,
      labels: [...this.#labels, ...(opts.labels ?? [])],
      sources: [...this.#sources, ...(opts.sources ?? [])],
    });
  }

  approve(requestId: string, approverKey: ApproverKey): Promise<Decision> {
    return this.client.approve(requestId, approverKey);
  }

  reject(requestId: string, approverKey: ApproverKey): Promise<Decision> {
    return this.client.reject(requestId, approverKey);
  }

  poll(requestId: string): Promise<EscalationStatus> {
    return this.client.poll(requestId);
  }

  commit(requestId: string, txRef: string): Promise<Record<string, unknown>> {
    return this.client.commit(requestId, txRef);
  }

  release(requestId: string, reason?: string): Promise<Record<string, unknown>> {
    return this.client.release(requestId, reason);
  }
}
