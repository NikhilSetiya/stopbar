"""Signed approvals (CS-151, spec/approval-signature-v1.md): Ed25519 approver
keys, separate from API keys, that countersign an escalation approve/reject
or a breaker reset. Optional — requires ``pip install stopbar[approver]``
(the ``cryptography`` package); the core client (``stopbar.client``) stays
stdlib-only and never imports this module.

Key files use exactly Stopbar's tagged format
(``stopbar-approver-key-ed25519-v1\\n`` + base64url seed), so a key this
module writes loads with the Go CLI's ``stopbar approver keygen`` /
``approval.LoadKeyFile``, and vice versa.

The two objects a signature covers are small, flat and fixed-shape (spec
§2/§3): this module's canonicalisation is written for exactly those two
shapes, not as a general RFC 8785 (JCS) implementation. It sorts keys
lexicographically and emits compact JSON with no extra whitespace, which is
byte-identical to the Go core's ``canon.Marshal`` for the plain ASCII
identifiers and decimal integers these objects carry. The server
independently re-canonicalises and verifies every signature; a client-side
canonicalisation bug can only make a signature fail to verify (fail closed),
never a forged one succeed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "stopbar.approval needs the 'approver' extra: pip install stopbar[approver]"
    ) from e

APPROVE = "approve"
REJECT = "reject"
RESET = "reset"

_KEY_FILE_TAG = b"stopbar-approver-key-ed25519-v1\n"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def generate_key() -> tuple[bytes, bytes]:
    """Returns (private_seed, public_key), 32 bytes each. The private seed
    never leaves the caller's process except via write_key_file, to a local
    file."""
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    return seed, pub


def write_key_file(path: str, seed: bytes) -> None:
    """Writes seed as a tagged approver key file, mode 0600. Refuses to
    overwrite an existing file."""
    if os.path.exists(path):
        raise FileExistsError(f"{path} already exists; refusing to overwrite a key")
    data = _KEY_FILE_TAG + _b64(seed).encode("ascii") + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def load_key_file(path: str) -> bytes:
    """Reads an approver key written by write_key_file (or the Go CLI's
    ``stopbar approver keygen``). Refuses a file readable by anyone but its
    owner, and any file that is not a tagged approver key — a decision key
    or wallet key file can never be loaded as one."""
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise PermissionError(f"key file {path} has mode {oct(mode)}; must be 0600 or stricter")
    with open(path, "rb") as f:
        raw = f.read()
    if not raw.startswith(_KEY_FILE_TAG):
        raise ValueError(f"{path} is not a Stopbar approver key file")
    seed = _b64d(raw[len(_KEY_FILE_TAG):].strip().decode("ascii"))
    if len(seed) != 32:
        raise ValueError(f"{path}: malformed key")
    return seed


def kid(public_key: bytes) -> str:
    """RFC 7638 JWK thumbprint, matching internal/decision.Kid and
    internal/approval.Kid exactly (same construction, same key space as
    decision keys — the key *files* stay separately tagged)."""
    jwk = '{"crv":"Ed25519","kty":"OKP","x":"' + _b64(public_key) + '"}'
    return _b64(hashlib.sha256(jwk.encode("ascii")).digest())


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign(seed: bytes, domain: bytes, obj: dict[str, Any]) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    sig = priv.sign(domain + _canonical(obj))
    return _b64(sig)


@dataclass
class SignedEscalation:
    """The wire envelope POSTed to /v1/approvals/{id}[/reject]
    (spec/approval-signature-v1.md §2, §4.1)."""

    escalation_id: str
    payload_hash: str
    decision: str
    expiry: int
    kid: str
    sig: str

    def to_json(self) -> dict[str, Any]:
        return {
            "escalation_id": self.escalation_id, "payload_hash": self.payload_hash,
            "decision": self.decision, "expiry": self.expiry, "kid": self.kid, "sig": self.sig,
        }


@dataclass
class SignedBreakerReset:
    """The wire envelope POSTed to /v1/breakers/{tenant}/reset (spec §3, §4.1)."""

    tenant: str
    trip_request_id: str
    expiry: int
    kid: str
    sig: str

    def to_json(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant, "trip_request_id": self.trip_request_id, "decision": RESET,
            "expiry": self.expiry, "kid": self.kid, "sig": self.sig,
        }


def sign_escalation(seed: bytes, *, escalation_id: str, payload_hash: str, decision: str, expiry: int) -> SignedEscalation:
    """Signs an escalation approve/reject envelope (spec §2). decision is
    APPROVE or REJECT; expiry is a Unix-seconds int, which the server will
    refuse if it is not within (now, now + 1h] of its own clock."""
    if decision not in (APPROVE, REJECT):
        raise ValueError(f"decision must be {APPROVE!r} or {REJECT!r}, got {decision!r}")
    obj = {"escalation_id": escalation_id, "payload_hash": payload_hash, "decision": decision, "expiry": expiry}
    sig = _sign(seed, b"stopbar-approval-escalation-v1\n", obj)
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return SignedEscalation(escalation_id, payload_hash, decision, expiry, kid(pub), sig)


def sign_breaker_reset(seed: bytes, *, tenant: str, trip_request_id: str, expiry: int) -> SignedBreakerReset:
    """Signs a breaker-reset envelope (spec §3)."""
    obj = {"tenant": tenant, "trip_request_id": trip_request_id, "decision": RESET, "expiry": expiry}
    sig = _sign(seed, b"stopbar-approval-breaker-reset-v1\n", obj)
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return SignedBreakerReset(tenant, trip_request_id, expiry, kid(pub), sig)


__all__ = [
    "APPROVE", "REJECT", "RESET",
    "generate_key", "write_key_file", "load_key_file", "kid",
    "sign_escalation", "sign_breaker_reset",
    "SignedEscalation", "SignedBreakerReset",
]
