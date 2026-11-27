// Wire types, hand-mirrored from spec/schemas/action_request.v1.schema.json and
// decision.v1.schema.json (which mirror internal/model, the contract). Change
// them together. Amounts are decimal strings: wei exceeds 2^53.

/** Provenance labels (LLD §8.1). Other strings are accepted; labels only restrict. */
export type Label =
  | "trusted_user"
  | "trusted_system"
  | "tool_output"
  | "untrusted_web"
  | "untrusted_onchain"
  | "untrusted_email"
  | "untrusted_file"
  | "decoded"
  | "sensitive_internal"
  | (string & {});

export interface Action {
  kind: "evm_tx" | "tool_call" | "withdrawal" | "evm_typed_data" | "evm_personal_sign";
  chain_id?: number;
  from?: string;
  to?: string;
  value_wei?: string;
  data?: string;
  tool?: string | null;
  args?: Record<string, unknown> | null;
  tx_type?: 2;
  tx_nonce?: string;
  gas_limit?: string;
  max_fee_per_gas?: string;
  max_priority_fee_per_gas?: string;
  /** evm_typed_data: the EIP-712 payload as eth_signTypedData_v4 takes it (CS-514). */
  typed_data?: TypedData;
  /** evm_personal_sign: the bytes to sign, 0x hex. */
  message?: string;
}

/** An EIP-712 payload (CS-514). Integers travel as decimal strings. */
export interface TypedData {
  types: Record<string, { name: string; type: string }[]>;
  primaryType: string;
  domain: Record<string, unknown>;
  message: Record<string, unknown>;
}

export interface Source {
  label: Label;
  ref: string;
  hash?: string;
}

export interface Provenance {
  labels: Label[];
  sources?: Source[];
  sdk?: { name: string; version: string };
}

export interface Actor {
  agent_id: string;
  workload_identity?: string;
  session_id?: string;
  on_behalf_of?: string;
}

export interface ActionRequest {
  id: string;
  tenant: string;
  nonce: string;
  issued_at: string;
  ttl_seconds: number;
  actor: Actor;
  action: Action;
  provenance: Provenance;
  parent_request_id?: string | null;
}

export interface Reason {
  code?: string;
  policy_id: string;
  message: string;
}

export interface Approval {
  approver: string;
  at: string;
  signature: string;
  [k: string]: unknown;
}

export type Outcome = "allow" | "deny" | "escalate";

/** The Decision body Stopbar returns for every outcome (LLD §3.4). */
export interface DecisionBody {
  request_id: string;
  outcome: Outcome;
  reasons: Reason[];
  policy_bundle_hash: string;
  payload_hash: string;
  approvals: Approval[];
  reservation_id: string | null;
  issued_at: string;
  expires_at: string;
  token?: string;
  signed_tx?: string;
  tx_hash?: string;
  /** Gatekeeper mode, off-chain requests: 65-byte signature (0x hex, v = 27/28) and the digest it signs. */
  signature?: string;
  signing_hash?: string;
}

/** A gateway error body (LLD §4.1). */
export interface ErrorBody {
  code?: string;
  message?: string;
  request_id?: string;
  problems?: string[];
}
