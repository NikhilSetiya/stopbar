"""Typed errors the SDK raises so a caller can act on the HTTP status alone.

The contract mirrors Stopbar's: 200 is allow and only allow, 202 is escalate,
403 is deny. ``Client.evaluate`` and ``Client.approve`` return the decision on
allow and raise one of these otherwise, so "the firewall said no" is never a
value a caller can forget to check.
"""
from __future__ import annotations

from typing import Any


class StopbarError(Exception):
    """Base class for every Stopbar SDK error."""


class StopbarDecisionError(StopbarError):
    """A decision that is not an allow (deny or escalate). Carries the decision
    body and the policy/reason codes so an agent — or an adaptive attacker in a
    research setting — can read why."""

    def __init__(self, status: int, decision: dict[str, Any]):
        self.status = status
        self.decision = decision
        self.reasons = _reasons(decision)
        verb = {202: "escalated for human approval", 403: "denied"}.get(status, "rejected")
        super().__init__(f"Stopbar {verb} (HTTP {status}): {', '.join(self.reasons) or '—'}")


class StopbarDenied(StopbarDecisionError):
    """The action is forbidden (HTTP 403). It will not be signed, for any caller."""


class StopbarEscalated(StopbarDecisionError):
    """The action needs human approval (HTTP 202). Hold the request id and call
    ``Client.approve`` once a human has approved; the approval re-evaluates
    against current state."""

    @property
    def request_id(self) -> str:
        return self.decision.get("request_id", "")


class StopbarUnavailable(StopbarError):
    """Stopbar could not be reached or returned a non-decision error. Fail
    closed: treat it as a deny, never as an allow."""


class StopbarAuthError(StopbarError):
    """The credential is missing, invalid, or lacks the required scope."""


def _reasons(decision: dict[str, Any]) -> list[str]:
    rs = [r.get("policy_id") or r.get("code") for r in decision.get("reasons", [])]
    rs = [str(r) for r in rs if r]
    if not rs and decision.get("code"):
        rs = [str(decision["code"])]
    return rs
