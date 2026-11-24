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
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any

from .encoding import detect
from .errors import (
    StopbarAuthError,
    StopbarDenied,
    StopbarEscalated,
    StopbarRequestError,
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
class EscalationStatus:
    """GET /v1/decisions/{id}: where an escalation is. ``state`` is "pending",
    "allowed", "denied" or "expired"; ``decision`` is the escalate decision while
    pending and the final one after (with the token, and in gatekeeper mode the
    signed tx, once allowed). Only ``allowed`` is safe to act on."""

    status: int
    body: dict[str, Any]

    @property
    def state(self) -> str:
        return self.body.get("state", "")

    @property
    def allowed(self) -> bool:
        return self.status == 200 and self.state == "allowed"

    @property
    def decision(self) -> Decision | None:
        d = self.body.get("decision")
        return Decision(self.status, d) if isinstance(d, dict) else None


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
        on every request it evaluates — e.g. ``add(page, "untrusted_web")``
        after the agent reads web content, and it stays attached for the rest
        of the session."""
        return Session(self, list(dict.fromkeys(labels or [])))

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
        sources: list[dict[str, str]] | None = None,
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
            "provenance": {"labels": list(dict.fromkeys(labels or []))},
        }
        if sources:
            body["provenance"]["sources"] = list(sources)
        status, decoded = self._post("/v1/evaluate", body)
        return self._decision(status, decoded)

    def approve(self, request_id: str) -> Decision:
        """Approve a pending escalation. Stopbar re-evaluates it against current
        state; on an allow the returned Decision carries the signed transaction.
        Needs a key with the 'approve' scope."""
        status, decoded = self._post(f"/v1/approvals/{_seg(request_id)}", None)
        return self._decision(status, decoded)

    def reject(self, request_id: str) -> Decision:
        """Reject a pending escalation: it is denied and nothing is signed. Needs
        a key with the 'approve' scope that did not request it. Returns the deny
        (reason APPROVAL_REJECTED); raises StopbarDenied if Stopbar refused the
        rejection itself (e.g. self-rejection), StopbarRequestError for an unknown
        or already-resolved escalation."""
        status, decoded = self._post(f"/v1/approvals/{_seg(request_id)}/reject", None)
        if status == 403 and decoded.get("outcome") == "deny" and \
                (decoded.get("reasons") or [{}])[-1].get("code") == "APPROVAL_REJECTED":
            return Decision(status, decoded)
        self._refusal(status, decoded)
        if status != 200:
            self._decision(status, decoded)  # raises: escalate / deny / unavailable
        raise StopbarUnavailable(f"Stopbar answered a reject with HTTP {status}: not a rejection")

    def poll(self, request_id: str) -> EscalationStatus:
        """The escalation's current state (GET /v1/decisions/{id}). Visible to the
        requesting agent and to its tenant's approvers. A pending escalation past
        its approval window comes back expired (a deny)."""
        status, decoded = self._request("GET", f"/v1/decisions/{_seg(request_id)}", None)
        if status in (200, 202, 403) and decoded.get("state"):
            return EscalationStatus(status, decoded)
        self._refusal(status, decoded)
        raise StopbarUnavailable(f"Stopbar returned HTTP {status}: {decoded.get('code') or decoded}")

    def commit(self, request_id: str, tx_ref: str) -> dict[str, Any]:
        """Report that an allowed action was broadcast (tx_ref: its tx hash), turning
        its reservation into committed spend. Retrying with the same tx_ref is safe.
        Returns the body ({"state": "committed", "late": true} if the reservation
        had lapsed: the spend is still recorded)."""
        return self._settle(request_id, "commit", {"tx_ref": tx_ref})

    def release(self, request_id: str, reason: str | None = None) -> dict[str, Any]:
        """Abandon an allowed action and free its reservation. Retrying is safe."""
        return self._settle(request_id, "release", {"reason": reason} if reason else {})

    # ---- internals ----

    def _settle(self, request_id: str, verb: str, body: dict[str, Any]) -> dict[str, Any]:
        status, decoded = self._post(f"/v1/actions/{_seg(request_id)}/{verb}", body)
        if status == 200:
            return decoded
        self._refusal(status, decoded)
        raise StopbarUnavailable(f"Stopbar returned HTTP {status}: {decoded.get('code') or decoded}")

    @staticmethod
    def _refusal(status: int, decoded: dict[str, Any]) -> None:
        """Raise the typed error for a non-decision refusal, if it is one."""
        if status == 401 or (status == 403 and decoded.get("code")):
            raise StopbarAuthError(f"Stopbar auth failed (HTTP {status}): {decoded.get('code') or decoded.get('message')}")
        if status in (400, 404, 409, 410, 413, 415):
            raise StopbarRequestError(status, decoded)

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
        return self._request("POST", path, body)

    def _request(self, method: str, path: str, body: dict[str, Any] | None) -> tuple[int, dict[str, Any]]:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        req = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers)
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
    sources: list[dict[str, str]] = field(default_factory=list)

    def add_label(self, label: str) -> "Session":
        if label not in self.labels:
            self.labels.append(label)
        return self

    def add(self, content: str, label: str, ref: str | None = None) -> "Session":
        """Record content entering the agent's context under ``label`` (LLD
        §8.2). Any input not labelled ``trusted_*`` is scanned for encoded
        content (base64, hex, Morse, ROT-n, zero-width); if any is found the
        session also gains ``decoded`` (CS-183). ``ref`` (a URL, tx hash…) is
        recorded as a provenance source."""
        self.add_label(label)
        decoded = not label.startswith("trusted_") and bool(detect(content))
        if decoded:
            self.add_label("decoded")
        if ref is not None:
            self.sources.append({"label": label, "ref": ref})
            if decoded:
                self.sources.append({"label": "decoded", "ref": ref})
        return self

    def evaluate(self, action: dict[str, Any], **kw: Any) -> Decision:
        extra = kw.pop("labels", None) or []
        merged = list(dict.fromkeys([*self.labels, *extra]))
        sources = [*self.sources, *(kw.pop("sources", None) or [])]
        return self.client.evaluate(action, labels=merged, sources=sources, **kw)

    def approve(self, request_id: str) -> Decision:
        return self.client.approve(request_id)

    def poll(self, request_id: str) -> EscalationStatus:
        return self.client.poll(request_id)

    def commit(self, request_id: str, tx_ref: str) -> dict[str, Any]:
        return self.client.commit(request_id, tx_ref)

    def release(self, request_id: str, reason: str | None = None) -> dict[str, Any]:
        return self.client.release(request_id, reason)


def _seg(request_id: str) -> str:
    """A request id as one URL path segment."""
    return urllib.parse.quote(request_id, safe="")


def _json(raw: bytes) -> dict[str, Any]:
    try:
        out = json.loads(raw)
        return out if isinstance(out, dict) else {"value": out}
    except (ValueError, TypeError):
        return {}
