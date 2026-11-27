"""Client tests against a mock stopbard (an in-process HTTP server), so they
need no running service. They exercise the real request shape, the label
plumbing, and the typed-error mapping for each outcome."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from stopbar import (
    Client,
    StopbarAuthError,
    StopbarDenied,
    StopbarEscalated,
    StopbarRequestError,
    StopbarUnavailable,
)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        getr = getattr(self.server, "get_responder", None)
        if getr is None:
            self.do_POST()
            return
        self.server.last_method, self.server.last_path = self.command, self.path
        self.server.last_auth = self.headers.get("Authorization")
        status, body = getr(self.path)
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b""
        self.server.last_body = json.loads(raw) if raw else None
        self.server.last_auth = self.headers.get("Authorization")
        self.server.last_method, self.server.last_path = self.command, self.path
        status, body = self.server.responder(self.path, self.server.last_body)
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def serve(responder, get_responder=None):
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    srv.responder = responder
    srv.get_responder = get_responder
    srv.last_body = srv.last_auth = srv.last_method = srv.last_path = None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def client(srv, **kw):
    kw.setdefault("tenant", "demo")
    kw.setdefault("agent_id", "wallet-agent")
    return Client(f"http://127.0.0.1:{srv.server_address[1]}", **kw)


def evm(sb):
    return sb.evm_tx(chain_id=8453, from_addr="0x" + "1" * 40, to="0x" + "2" * 40,
                     value_wei="1000", tx_nonce="0", gas_limit="21000",
                     max_fee_per_gas="200000000", max_priority_fee_per_gas="100000000")


def test_allow_returns_decision_with_signed_tx():
    srv = serve(lambda path, body: (200, {"request_id": body["id"], "outcome": "allow", "signed_tx": "0xdeadbeef"}))
    sb = client(srv, api_key="stopbar_sk_test")
    d = sb.evaluate(evm(sb), labels=["untrusted_web"])
    assert d.outcome == "allow" and d.signed_tx == "0xdeadbeef"
    # the request carried identity, a nonce, and the labels
    assert srv.last_auth == "Bearer stopbar_sk_test"
    assert srv.last_body["tenant"] == "demo"
    assert srv.last_body["actor"]["agent_id"] == "wallet-agent"
    assert srv.last_body["provenance"]["labels"] == ["untrusted_web"]
    assert srv.last_body["action"]["kind"] == "evm_tx"
    assert isinstance(srv.last_body["action"]["value_wei"], str)  # never a JSON number


def test_deny_raises_stopbar_denied():
    srv = serve(lambda path, body: (403, {"request_id": body["id"], "outcome": "deny",
                                          "reasons": [{"policy_id": "unlimited-approval"}]}))
    sb = client(srv)
    with pytest.raises(StopbarDenied) as ei:
        sb.evaluate(evm(sb))
    assert ei.value.reasons == ["unlimited-approval"]
    assert ei.value.status == 403


def test_escalate_raises_with_request_id_then_approve():
    from stopbar import approval

    seed, _ = approval.generate_key()

    def responder(path, body):
        assert path == "/v1/approvals/req_1"
        assert body["decision"] == approval.APPROVE and body["escalation_id"] == "req_1"
        assert body["kid"] and body["sig"]  # genuinely signed
        assert body["policy_bundle_hash"] == "sha256:" + "b" * 64  # signs the bundle the server named
        return (200, {"request_id": "req_1", "outcome": "allow", "signed_tx": "0xabc"})

    def get_responder(path):
        assert path == "/v1/approvals/req_1"
        return (200, {"escalation_id": "req_1", "payload_hash": "sha256:" + "a" * 64,
                      "policy_bundle_hash": "sha256:" + "b" * 64, "tenant": "demo"})

    srv = serve(lambda path, body: (202, {"request_id": body["id"], "outcome": "escalate",
                                          "reasons": [{"policy_id": "large-share-of-balance"}]}), get_responder)
    sb = client(srv, api_key="k")
    with pytest.raises(StopbarEscalated) as ei:
        sb.evaluate(evm(sb), request_id="req_1")
    rid = ei.value.request_id
    assert rid == "req_1" and ei.value.reasons == ["large-share-of-balance"]

    # Swap in the POST responder (the mock serves one path differently per phase).
    srv.responder = responder
    approved = sb.approve(rid, seed)
    assert approved.outcome == "allow" and approved.signed_tx == "0xabc"


def test_session_labels_are_monotonic():
    srv = serve(lambda path, body: (200, {"request_id": body["id"], "outcome": "allow"}))
    sb = client(srv)
    s = sb.session(["trusted_user"])
    s.add_label("untrusted_web").add_label("untrusted_web")  # dedup
    s.evaluate(evm(sb), labels=["untrusted_onchain"])
    assert srv.last_body["provenance"]["labels"] == ["trusted_user", "untrusted_web", "untrusted_onchain"]


def test_auth_error_maps():
    srv = serve(lambda path, body: (401, {"code": "UNAUTHENTICATED"}))
    sb = client(srv)
    with pytest.raises(StopbarAuthError):
        sb.evaluate(evm(sb))


def test_unreachable_fails_closed():
    sb = Client("http://127.0.0.1:1", timeout=1)  # nothing listening
    with pytest.raises(StopbarUnavailable):
        sb.evaluate(evm(sb))


def test_commit_and_release_settle_the_reservation():
    srv = serve(lambda path, body: (200, {"request_id": "req_1", "state": path.rsplit("/", 1)[1] + "ted"}))
    sb = client(srv, api_key="k")
    assert sb.commit("req_1", "0xabc")["state"] == "committed"
    assert (srv.last_method, srv.last_path, srv.last_body) == ("POST", "/v1/actions/req_1/commit", {"tx_ref": "0xabc"})
    sb.release("req_1", "user cancelled")
    assert (srv.last_path, srv.last_body) == ("/v1/actions/req_1/release", {"reason": "user cancelled"})
    sb.release("req/../x")  # an id is one path segment, never a path
    assert srv.last_path == "/v1/actions/req%2F..%2Fx/release" and srv.last_body == {}


@pytest.mark.parametrize("status,code", [(404, "NOT_FOUND"), (409, "CONFLICT"), (410, "RESERVATION_EXPIRED"),
                                         (400, "INVALID_REQUEST")])
def test_settle_refusals_are_typed(status, code):
    srv = serve(lambda path, body: (status, {"code": code}))
    sb = client(srv)
    with pytest.raises(StopbarRequestError) as ei:
        sb.commit("req_1", "0xabc")
    assert ei.value.status == status and ei.value.code == code


def test_settle_auth_and_server_errors():
    srv = serve(lambda path, body: (403, {"code": "FORBIDDEN_SCOPE"}))
    with pytest.raises(StopbarAuthError):
        client(srv).release("req_1")
    srv = serve(lambda path, body: (500, {"code": "INTERNAL"}))
    with pytest.raises(StopbarUnavailable):
        client(srv).commit("req_1", "0x1")


@pytest.mark.parametrize("status,state,allowed", [(202, "pending", False), (200, "allowed", True),
                                                  (403, "denied", False), (403, "expired", False)])
def test_poll_reports_state(status, state, allowed):
    srv = serve(lambda path, body: (status, {"request_id": "req_1", "state": state,
                                             "decision": {"request_id": "req_1", "outcome": "allow" if allowed else "deny", "token": "t"}}))
    st = client(srv, api_key="k").poll("req_1")
    assert (srv.last_method, srv.last_path) == ("GET", "/v1/decisions/req_1")
    assert st.state == state and st.allowed is allowed
    assert st.decision.outcome == ("allow" if allowed else "deny")


def test_poll_unknown_raises():
    srv = serve(lambda path, body: (404, {"code": "NOT_FOUND"}))
    with pytest.raises(StopbarRequestError):
        client(srv).poll("nope")


def _approval_get_responder(escalation_id="req_1"):
    def get_responder(path):
        assert path == f"/v1/approvals/{escalation_id}"
        return (200, {"escalation_id": escalation_id, "payload_hash": "sha256:" + "a" * 64, "policy_bundle_hash": "sha256:" + "b" * 64, "tenant": "demo"})

    return get_responder


def test_reject_returns_the_deny():
    from stopbar import approval

    seed, _ = approval.generate_key()
    srv = serve(lambda path, body: (403, {"request_id": "req_1", "outcome": "deny",
                                          "reasons": [{"code": "APPROVAL_REJECTED", "policy_id": ""}]}),
                _approval_get_responder())
    d = client(srv, api_key="ops").reject("req_1", seed)
    assert (srv.last_method, srv.last_path) == ("POST", "/v1/approvals/req_1/reject")
    assert srv.last_body["decision"] == approval.REJECT and srv.last_body["kid"] and srv.last_body["sig"]
    assert d.outcome == "deny" and d.reasons == ["APPROVAL_REJECTED"]


def test_reject_refusals_raise():
    from stopbar import approval

    seed, _ = approval.generate_key()
    srv = serve(lambda path, body: (403, {"request_id": "req_1", "outcome": "deny",
                                          "reasons": [{"code": "APPROVAL_SELF_APPROVAL"}]}),
                _approval_get_responder())
    with pytest.raises(StopbarDenied):
        client(srv).reject("req_1", seed)
    srv = serve(lambda path, body: (409, {"code": "ALREADY_RESOLVED"}), _approval_get_responder())
    with pytest.raises(StopbarRequestError) as ei:
        client(srv).reject("req_1", seed)
    assert ei.value.code == "ALREADY_RESOLVED"
    srv = serve(lambda path, body: (200, {"request_id": "req_1", "outcome": "allow"}), _approval_get_responder())
    with pytest.raises(StopbarUnavailable):  # an allow is never a rejection: fail closed
        client(srv).reject("req_1", seed)


def test_approve_reject_accept_a_key_file(tmp_path):
    from stopbar import approval

    path = str(tmp_path / "approver.key")
    approval.write_key_file(path, approval.generate_key()[0])
    srv = serve(lambda path_, body: (200, {"request_id": "req_1", "outcome": "allow"}), _approval_get_responder())
    d = client(srv).approve("req_1", path)  # a file path, not raw seed bytes
    assert d.outcome == "allow"
