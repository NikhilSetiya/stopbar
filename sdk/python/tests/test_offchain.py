"""Off-chain signature requests (CS-514): action builders and the decision's
signature fields, against the mock stopbard."""
from test_client import client, serve

from stopbar import Client

PERMIT = {
    "types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"}],
              "Mail": [{"name": "n", "type": "uint256"}, {"name": "ok", "type": "bool"}, {"name": "raw", "type": "bytes"}]},
    "primaryType": "Mail",
    "domain": {"name": "x", "chainId": 8453},
    "message": {"n": 2**200, "ok": True, "raw": b"\x01\x02"},
}


def test_typed_data_builder_stringifies_integers():
    a = Client.evm_typed_data(chain_id=8453, from_addr="0x" + "A" * 40, typed_data=PERMIT)
    assert a["kind"] == "evm_typed_data" and a["from"] == "0x" + "a" * 40
    m = a["typed_data"]["message"]
    assert m["n"] == str(2**200) and m["ok"] is True and m["raw"] == "0x0102"  # bool stays a bool
    assert a["typed_data"]["domain"]["chainId"] == "8453"
    assert PERMIT["message"]["n"] == 2**200  # caller's dict untouched


def test_personal_sign_builder():
    text = Client.evm_personal_sign(chain_id=8453, from_addr="0x" + "1" * 40, message="hi")
    assert text["kind"] == "evm_personal_sign" and text["message"] == "0x6869"
    assert Client.evm_personal_sign(chain_id=1, from_addr="0x" + "1" * 40, message="0xABCD")["message"] == "0xabcd"
    assert Client.evm_personal_sign(chain_id=1, from_addr="0x" + "1" * 40, message=b"\x00\xff")["message"] == "0x00ff"
    assert Client.evm_personal_sign(chain_id=1, from_addr="0x" + "1" * 40, message="0xnot hex")["message"] == "0x" + b"0xnot hex".hex()


def test_allow_carries_signature():
    srv = serve(lambda path, body: (200, {"request_id": body["id"], "outcome": "allow",
                                          "signature": "0x" + "ab" * 65, "signing_hash": "0x" + "cd" * 32}))
    sb = client(srv)
    d = sb.evaluate(Client.evm_typed_data(chain_id=8453, from_addr="0x" + "1" * 40, typed_data=PERMIT))
    assert d.signature == "0x" + "ab" * 65 and d.signing_hash == "0x" + "cd" * 32 and d.signed_tx is None
    assert srv.last_body["action"]["typed_data"]["message"]["n"] == str(2**200)
