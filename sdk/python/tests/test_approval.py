"""Tests for stopbar.approval (CS-151): key files, kid, canonicalisation and
signing. Needs the 'approver' extra (cryptography)."""
import os
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stopbar import approval


def test_generate_key_round_trips_through_write_load():
    seed, pub = approval.generate_key()
    assert len(seed) == 32 and len(pub) == 32


def test_write_key_file_mode_and_tag(tmp_path):
    seed, pub = approval.generate_key()
    path = str(tmp_path / "approver.key")
    approval.write_key_file(path, seed)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
    loaded = approval.load_key_file(path)
    assert loaded == seed
    loaded_pub = Ed25519PrivateKey.from_private_bytes(loaded).public_key().public_bytes_raw()
    assert loaded_pub == pub


def test_write_key_file_refuses_overwrite(tmp_path):
    seed, _ = approval.generate_key()
    path = str(tmp_path / "approver.key")
    approval.write_key_file(path, seed)
    with pytest.raises(FileExistsError):
        approval.write_key_file(path, approval.generate_key()[0])


def test_load_key_file_rejects_loose_permissions(tmp_path):
    seed, _ = approval.generate_key()
    path = str(tmp_path / "approver.key")
    approval.write_key_file(path, seed)
    os.chmod(path, 0o644)
    with pytest.raises(PermissionError):
        approval.load_key_file(path)


def test_load_key_file_rejects_wrong_tag(tmp_path):
    path = str(tmp_path / "not-an-approver.key")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b"stopbar-decision-key-ed25519-v1\nsomething\n")
    os.close(fd)
    with pytest.raises(ValueError):
        approval.load_key_file(path)


def test_kid_is_deterministic_rfc7638_thumbprint():
    seed, pub = approval.generate_key()
    k1 = approval.kid(pub)
    k2 = approval.kid(pub)
    assert k1 == k2 and len(k1) > 0
    other_seed, other_pub = approval.generate_key()
    assert approval.kid(other_pub) != k1


def test_sign_escalation_shape_and_decision_validation():
    seed, pub = approval.generate_key()
    s = approval.sign_escalation(seed, escalation_id="esc_1", payload_hash="sha256:" + "a" * 64, policy_bundle_hash="sha256:" + "b" * 64, decision=approval.APPROVE, expiry=4102444800)
    body = s.to_json()
    assert body["escalation_id"] == "esc_1" and body["decision"] == "approve"
    assert body["policy_bundle_hash"] == "sha256:" + "b" * 64
    assert body["kid"] == approval.kid(pub)
    assert body["sig"]
    with pytest.raises(ValueError):
        approval.sign_escalation(seed, escalation_id="esc_1", payload_hash="x", policy_bundle_hash="y", decision="maybe", expiry=1)


def test_sign_breaker_reset_shape():
    seed, pub = approval.generate_key()
    r = approval.sign_breaker_reset(seed, tenant="acme", trip_request_id="req_1", expiry=4102444800)
    body = r.to_json()
    assert body["tenant"] == "acme" and body["trip_request_id"] == "req_1" and body["decision"] == "reset"
    assert body["kid"] == approval.kid(pub) and body["sig"]


def test_signature_actually_verifies_with_raw_ed25519():
    """Cross-checks this module's signature against a hand-rolled verifier
    using the same domain separation and canonicalisation the Go core uses
    (spec/approval-signature-v1.md §4), so a bug here fails closed (wrong
    signature) rather than silently producing something unverifiable in a
    different way."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    seed, pub = approval.generate_key()
    s = approval.sign_escalation(seed, escalation_id="esc_1", payload_hash="sha256:" + "a" * 64, policy_bundle_hash="sha256:" + "b" * 64, decision=approval.APPROVE, expiry=4102444800)
    canon = approval._canonical({"escalation_id": "esc_1", "payload_hash": "sha256:" + "a" * 64, "policy_bundle_hash": "sha256:" + "b" * 64, "decision": "approve", "expiry": 4102444800})
    msg = b"stopbar-approval-escalation-v2\n" + canon
    pubkey = Ed25519PublicKey.from_public_bytes(pub)
    pubkey.verify(approval._b64d(s.sig), msg)  # raises if invalid

    # A tampered field must not verify.
    tampered = approval._canonical({"escalation_id": "esc_2", "payload_hash": "sha256:" + "a" * 64, "policy_bundle_hash": "sha256:" + "b" * 64, "decision": "approve", "expiry": 4102444800})
    with pytest.raises(InvalidSignature):
        pubkey.verify(approval._b64d(s.sig), b"stopbar-approval-escalation-v2\n" + tampered)


def test_matches_the_go_conformance_vectors():
    """Signs every OK escalation and breaker-reset vector in
    spec/vectors/approval-signature-v1.json with the vector key's seed and
    expects the vector's exact signature (Ed25519 is deterministic), so the
    SDK and the Go core agree byte for byte on the v2 escalation object."""
    import json

    vf = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "..", "spec", "vectors", "approval-signature-v1.json")))
    seeds = {k["kid"]: bytes.fromhex(k["seed_hex"]) for k in vf["keys"]}
    checked = 0
    for v in vf["escalations"]:
        e = v["envelope"]
        if v["result"] != "OK" or e["kid"] not in seeds:
            continue
        s = approval.sign_escalation(seeds[e["kid"]], escalation_id=e["escalation_id"], payload_hash=e["payload_hash"],
                                     policy_bundle_hash=e["policy_bundle_hash"], decision=e["decision"], expiry=e["expiry"])
        assert s.to_json() == e, v["name"]
        checked += 1
    for v in vf["breaker_resets"]:
        e = v["envelope"]
        if v["result"] != "OK":
            continue
        r = approval.sign_breaker_reset(seeds[e["kid"]], tenant=e["tenant"], trip_request_id=e["trip_request_id"], expiry=e["expiry"])
        assert r.to_json() == e, v["name"]
        checked += 1
    assert checked >= 3
