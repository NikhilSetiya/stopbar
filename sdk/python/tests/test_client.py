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
        self.do_POST()

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


def serve(responder):
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    srv.responder = responder
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
    def responder(path, body):
        if path.startswith("/v1/approvals/"):
            return (200, {"request_id": path.rsplit("/", 1)[1], "outcome": "allow", "signed_tx": "0xabc"})
        return (202, {"request_id": body["id"], "outcome": "escalate",
                      "reasons": [{"policy_id": "large-share-of-balance"}]})

    srv = serve(responder)
    sb = client(srv, api_key="k")
    with pytest.raises(StopbarEscalated) as ei:
        sb.evaluate(evm(sb))
    rid = ei.value.request_id
    assert rid and ei.value.reasons == ["large-share-of-balance"]
    approved = sb.approve(rid)
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


def test_reject_returns_the_deny():
    srv = serve(lambda path, body: (403, {"request_id": "req_1", "outcome": "deny",
                                          "reasons": [{"code": "APPROVAL_REJECTED", "policy_id": ""}]}))
    d = client(srv, api_key="ops").reject("req_1")
    assert (srv.last_method, srv.last_path) == ("POST", "/v1/approvals/req_1/reject")
    assert d.outcome == "deny" and d.reasons == ["APPROVAL_REJECTED"]


def test_reject_refusals_raise():
    srv = serve(lambda path, body: (403, {"request_id": "req_1", "outcome": "deny",
                                          "reasons": [{"code": "APPROVAL_SELF_APPROVAL"}]}))
    with pytest.raises(StopbarDenied):
        client(srv).reject("req_1")
    srv = serve(lambda path, body: (409, {"code": "ALREADY_RESOLVED"}))
    with pytest.raises(StopbarRequestError) as ei:
        client(srv).reject("req_1")
    assert ei.value.code == "ALREADY_RESOLVED"
    srv = serve(lambda path, body: (200, {"request_id": "req_1", "outcome": "allow"}))
    with pytest.raises(StopbarUnavailable):  # an allow is never a rejection: fail closed
        client(srv).reject("req_1")
