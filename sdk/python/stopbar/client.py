"""Stopbar client: an in-process firewall for an agent's actions.

The agent builds an action as usual; the SDK sends it to Stopbar's /v1/evaluate
and returns the signed decision only on an allow, raising a typed error on a
deny or escalate. Provenance labels (the agent's taint for the current context)
ride on every request. Stdlib-only: no third-party dependency for the HTTP path.
"""
from __future__ import annotations

import base64
import datetime
import json
import os
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any

from .errors import (
    StopbarAuthError,
    StopbarDenied,
    StopbarEscalated,
    StopbarUnavailable,
)


@dataclass
class Decision:
    """A Stopbar decision. ``outcome`` is "allow", "escalate" or "deny"; in
    gatekeeper mode an allow carries ``signed_tx`` and ``tx_hash``."""

    status: int
    body: dict[str, Any]

    @property
    def outcome(self) -> str:
        return self.body.get("outcome", "")

    @property
    def request_id(self) -> str:
        return self.body.get("request_id", "")

    @property
    def signed_tx(self) -> str | None:
        return self.body.get("signed_tx")

    @property
    def tx_hash(self) -> str | None:
        return self.body.get("tx_hash")

    @property
    def token(self) -> str | None:
        return self.body.get("token")

    @property
    def reasons(self) -> list[str]:
        rs = [r.get("policy_id") or r.get("code") for r in self.body.get("reasons", [])]
        return [str(r) for r in rs if r]


@dataclass
class Client:
    """A client for one Stopbar deployment and one agent identity.

    base_url: the stopbard URL. api_key: the bearer secret from
    ``stopbar keygen api-key`` (None only for loopback dev with auth off).
    tenant/agent_id must match the key's identity — Stopbar derives identity
    from the key, and a mismatched body is rejected.
    """

    base_url: str
    api_key: str | None = None
    tenant: str = "default"
    agent_id: str = "agent"
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timeout: float = 15.0

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")

    # ---- context ----

    def session(self, labels: list[str] | None = None) -> "Session":
        """A Session accumulates provenance labels (monotonic taint) that ride
        on every request it evaluates — e.g. add ``untrusted_web`` after the
        agent reads web content, and it stays attached for the rest of the
        session."""
        return Session(self, list(labels or []))

    # ---- actions ----

    @staticmethod
    def evm_tx(
        *,
        chain_id: int,
        from_addr: str,
        to: str,
        value_wei: str = "0",
        data: str = "0x",
        tx_nonce: str,
        gas_limit: str,
        max_fee_per_gas: str,
        max_priority_fee_per_gas: str,
    ) -> dict[str, Any]:
        """Build an EIP-1559 action. Amounts are decimal strings (wei exceeds
        2^53, so never JSON numbers). The requester sends the complete unsigned
        transaction; Stopbar binds every field."""
        return {
            "kind": "evm_tx", "chain_id": chain_id, "from": from_addr.lower(), "to": to.lower(),
            "value_wei": str(value_wei), "data": data.lower(), "tx_type": 2, "tx_nonce": str(tx_nonce),
            "gas_limit": str(gas_limit), "max_fee_per_gas": str(max_fee_per_gas),
            "max_priority_fee_per_gas": str(max_priority_fee_per_gas),
        }

    # ---- evaluate / approve ----

    def evaluate(
        self,
        action: dict[str, Any],
        *,
        labels: list[str] | None = None,
        request_id: str | None = None,
        nonce: str | None = None,
        ttl_seconds: int = 60,
    ) -> Decision:
        """Send an action to Stopbar. Returns the Decision on an allow; raises
        StopbarDenied (403), StopbarEscalated (202), StopbarAuthError (401/403
        auth), or StopbarUnavailable (unreachable / non-decision error)."""
        body = {
            "id": request_id or ("req_" + uuid.uuid4().hex),
            "tenant": self.tenant,
            "nonce": nonce or base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("="),
            "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ttl_seconds": ttl_seconds,
            "actor": {"agent_id": self.agent_id, "session_id": self.session_id},
            "action": action,
            "provenance": {"labels": list(labels or [])},
        }
        status, decoded = self._post("/v1/evaluate", body)
        return self._decision(status, decoded)

    def approve(self, request_id: str) -> Decision:
        """Approve a pending escalation. Stopbar re-evaluates it against current
        state; on an allow the returned Decision carries the signed transaction.
        Needs a key with the 'approve' scope."""
        status, decoded = self._post(f"/v1/approvals/{request_id}", None)
        return self._decision(status, decoded)

    # ---- internals ----

    def _decision(self, status: int, decoded: dict[str, Any]) -> Decision:
        if status == 200:
            return Decision(status, decoded)
        if status == 202:
            raise StopbarEscalated(status, decoded)
        if status == 403 and decoded.get("outcome") == "deny":
            raise StopbarDenied(status, decoded)
        if status in (401, 403):
            raise StopbarAuthError(f"Stopbar auth failed (HTTP {status}): {decoded.get('code') or decoded.get('message')}")
        raise StopbarUnavailable(f"Stopbar returned HTTP {status}: {decoded.get('code') or decoded.get('message') or decoded}")

    def _post(self, path: str, body: dict[str, Any] | None) -> tuple[int, dict[str, Any]]:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        req = urllib.request.Request(self.base_url + path, data=data, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, _json(r.read())
        except urllib.error.HTTPError as e:
            return e.code, _json(e.read())
        except OSError as e:  # unreachable: fail closed
            raise StopbarUnavailable(f"Stopbar unreachable at {self.base_url}: {e}") from e


@dataclass
class Session:
    """A client bound to a growing set of provenance labels. Labels only ever
    accumulate (taint is monotonic), matching Stopbar's v1 trust model."""

    client: Client
    labels: list[str]

    def add_label(self, label: str) -> "Session":
        if label not in self.labels:
            self.labels.append(label)
        return self

    def evaluate(self, action: dict[str, Any], **kw: Any) -> Decision:
        extra = kw.pop("labels", None) or []
        merged = list(dict.fromkeys([*self.labels, *extra]))
        return self.client.evaluate(action, labels=merged, **kw)

    def approve(self, request_id: str) -> Decision:
        return self.client.approve(request_id)


def _json(raw: bytes) -> dict[str, Any]:
    try:
        out = json.loads(raw)
        return out if isinstance(out, dict) else {"value": out}
    except (ValueError, TypeError):
        return {}
