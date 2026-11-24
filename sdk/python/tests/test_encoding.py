"""CS-183: the encoding detector, on the fixtures shared with the TypeScript
SDK (sdk/testdata/encodings.json), and the Session wiring that turns a hit in
untrusted input into the 'decoded' label."""
import json
import pathlib

import pytest

from stopbar import StopbarDenied, detect_encodings
from test_client import client, evm, serve

FIXTURES = json.loads((pathlib.Path(__file__).parents[2] / "testdata" / "encodings.json").read_text())


@pytest.mark.parametrize("case", FIXTURES["encoded"], ids=lambda c: c["name"])
def test_encoded_inputs_are_detected(case):
    assert detect_encodings(case["text"]) == case["kinds"]


@pytest.mark.parametrize("case", FIXTURES["plain"], ids=lambda c: c["name"])
def test_ordinary_text_is_not_flagged(case):
    assert detect_encodings(case["text"]) == []


def test_grok_pattern_fixture_is_labelled_decoded():
    g = FIXTURES["grok"]  # corpus CS-2026-0001
    srv = serve(lambda path, body: (403, {"request_id": body["id"], "outcome": "deny",
                                          "reasons": [{"policy_id": "taint-unknown-destination"}]}))
    sb = client(srv)
    s = sb.session().add(g["text"], g["label"], ref=g["ref"])
    assert s.labels == g["labels"]
    with pytest.raises(StopbarDenied):
        s.evaluate(evm(sb))
    prov = srv.last_body["provenance"]
    assert prov["labels"] == g["labels"]
    assert prov["sources"] == [{"label": g["label"], "ref": g["ref"]}, {"label": "decoded", "ref": g["ref"]}]


def test_only_untrusted_input_is_scanned():
    g = FIXTURES["grok"]
    sb = client(serve(lambda path, body: (200, {})))
    assert sb.session().add(g["text"], "trusted_user").labels == ["trusted_user"]
    assert sb.session().add(FIXTURES["plain"][0]["text"], "untrusted_web").labels == ["untrusted_web"]
    assert sb.session().add(g["text"], "tool_output").labels == ["tool_output", "decoded"]
