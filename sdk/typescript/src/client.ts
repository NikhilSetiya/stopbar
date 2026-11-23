// Stopbar client: an in-process firewall for an agent's actions.
//
// The agent builds an action as usual; the SDK sends it to Stopbar's
// /v1/evaluate and resolves with the signed decision only on an allow,
// rejecting with a typed error on a deny or escalate. Provenance labels (the
// agent's taint for the current context) ride on every request. Zero runtime
// dependencies: global fetch (Node >= 20).

import { randomBytes, randomUUID } from "node:crypto";
import { detectEncodings } from "./encoding.js";
import { StopbarAuthError, StopbarDenied, StopbarEscalated, StopbarUnavailable, reasonIds } from "./errors.js";
import type { Action, ActionRequest, DecisionBody, ErrorBody, Label, Source } from "./types.js";

/** A Stopbar decision. `outcome` is "allow", "escalate" or "deny"; in
 * gatekeeper mode an allow carries `signedTx` and `txHash`. */
export class Decision {
  constructor(readonly status: number, readonly body: DecisionBody) {}
  get outcome(): string { return this.body.outcome ?? ""; }
  get requestId(): string { return this.body.request_id ?? ""; }
  get signedTx(): string | undefined { return this.body.signed_tx; }
  get txHash(): string | undefined { return this.body.tx_hash; }
  get token(): string | undefined { return this.body.token; }
  get reasons(): string[] { return reasonIds(this.body); }
}

export interface ClientOptions {
  /** Bearer secret from `stopbar keygen api-key` (omit only for loopback dev with auth off). */
  apiKey?: string;
  /** Must match the key's identity: Stopbar derives identity from the key and rejects a mismatched body. */
  tenant?: string;
  agentId?: string;
  sessionId?: string;
  timeoutMs?: number;
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

  constructor(baseUrl: string, opts: ClientOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
    this.tenant = opts.tenant ?? "default";
    this.agentId = opts.agentId ?? "agent";
    this.sessionId = opts.sessionId ?? randomUUID();
    this.timeoutMs = opts.timeoutMs ?? 15_000;
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
    return this.decision(...(await this.post("/v1/evaluate", body)));
  }

  /** Approve a pending escalation. Stopbar re-evaluates it against current
   * state; on an allow the Decision carries the signed transaction. Needs a
   * key with the 'approve' scope. */
  async approve(requestId: string): Promise<Decision> {
    return this.decision(...(await this.post(`/v1/approvals/${encodeURIComponent(requestId)}`)));
  }

  /** Report that an allowed action was broadcast, committing its limiter
   * reservation (LLD §4.1 `POST /v1/actions/{id}/commit`, body `{tx_ref}`).
   * Idempotent for the same txRef. Rejects with StopbarAuthError, or
   * StopbarUnavailable on anything else but a 2xx (e.g. 409 for a different
   * txRef, 404 for a released/unknown id). */
  async commit(requestId: string, txRef: string): Promise<Record<string, unknown>> {
    return this.ack(...(await this.post(`/v1/actions/${encodeURIComponent(requestId)}/commit`, { tx_ref: txRef })));
  }

  /** Abandon an allowed action, releasing its limiter reservation (LLD §4.1
   * `POST /v1/actions/{id}/release`, optional body `{reason}`). */
  async release(requestId: string, reason?: string): Promise<Record<string, unknown>> {
    return this.ack(...(await this.post(`/v1/actions/${encodeURIComponent(requestId)}/release`, reason === undefined ? {} : { reason })));
  }

  private decision(status: number, body: Record<string, unknown>): Decision {
    const d = body as unknown as DecisionBody;
    if (status === 200) return new Decision(status, d);
    if (status === 202) throw new StopbarEscalated(status, d);
    if (status === 403 && d.outcome === "deny") throw new StopbarDenied(status, d);
    return fail(status, body);
  }

  private ack(status: number, body: Record<string, unknown>): Record<string, unknown> {
    return status >= 200 && status < 300 ? body : fail(status, body);
  }

  private async post(path: string, body?: unknown): Promise<[number, Record<string, unknown>]> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) headers.Authorization = "Bearer " + this.apiKey;
    let res: Response;
    let text: string;
    try {
      res = await fetch(this.baseUrl + path, {
        method: "POST", headers, body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      text = await res.text();
    } catch (err) {
      // unreachable, reset or timed out: fail closed
      throw new StopbarUnavailable(`Stopbar unreachable at ${this.baseUrl}: ${(err as Error).message}`, { cause: err });
    }
    return [res.status, parse(text)];
  }
}

// Anything that is not a decision or a 2xx ack: an auth failure, or (fail
// closed) unavailable.
function fail(status: number, body: Record<string, unknown>): never {
  const e = body as ErrorBody;
  if (status === 401 || status === 403) throw new StopbarAuthError(`Stopbar auth failed (HTTP ${status}): ${e.code ?? e.message}`);
  throw new StopbarUnavailable(`Stopbar returned HTTP ${status}: ${e.code ?? e.message ?? JSON.stringify(body)}`);
}

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

  approve(requestId: string): Promise<Decision> {
    return this.client.approve(requestId);
  }
}
