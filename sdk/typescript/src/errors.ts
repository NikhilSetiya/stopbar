// Typed errors so a caller can act on the HTTP status alone: 200 is allow and
// only allow, 202 is escalate, 403 is deny. Client.evaluate and approve resolve
// with the decision on allow and reject with one of these otherwise, so "the
// firewall said no" is never a value a caller can forget to check.

import type { DecisionBody } from "./types.js";

/** Base class for every Stopbar SDK error. */
export class StopbarError extends Error {
  override name = "StopbarError";
}

/** A decision that is not an allow (deny or escalate), with the decision body
 * and the policy/reason codes so the agent can read why. */
export class StopbarDecisionError extends StopbarError {
  override name = "StopbarDecisionError";
  readonly reasons: string[];
  constructor(readonly status: number, readonly decision: Partial<DecisionBody> & { code?: string }) {
    const reasons = reasonIds(decision);
    if (reasons.length === 0 && decision.code) reasons.push(decision.code);
    const verb = status === 202 ? "escalated for human approval" : status === 403 ? "denied" : "rejected";
    super(`Stopbar ${verb} (HTTP ${status}): ${reasons.join(", ") || "—"}`);
    this.reasons = reasons;
  }
}

/** The action is forbidden (HTTP 403). It will not be signed, for any caller. */
export class StopbarDenied extends StopbarDecisionError {
  override name = "StopbarDenied";
}

/** The action needs human approval (HTTP 202). Hold requestId and call
 * Client.approve once a human has approved; approval re-evaluates against
 * current state. */
export class StopbarEscalated extends StopbarDecisionError {
  override name = "StopbarEscalated";
  get requestId(): string {
    return this.decision.request_id ?? "";
  }
}

/** Stopbar could not be reached or returned a non-decision error. Fail closed:
 * treat it as a deny, never as an allow. */
export class StopbarUnavailable extends StopbarError {
  override name = "StopbarUnavailable";
}

/** The credential is missing, invalid, or lacks the required scope. */
export class StopbarAuthError extends StopbarError {
  override name = "StopbarAuthError";
}

export function reasonIds(d: Partial<DecisionBody>): string[] {
  return (d.reasons ?? []).map((r) => r.policy_id || r.code || "").filter((r) => r !== "");
}
