"""Monotonic session taint for the wallet agent (PILOT-2 harness v1.1).

The v1 trust boundary treats the agent harness (SDK) as trusted and the model
as untrusted. This module implements the SDK taint the Stopbar policy already
expects: the trust map (`policies/pilot2/tool-trust.json`, hashed into the
bundle) decides — from tool/resource definitions alone — which read tools
return third-party content. Once the agent consumes such a surface in an
episode, the session is tainted; the taint is **monotonic** within the episode
(labels only grow) and is attached to `provenance.labels` on **every** signing
request, in **all arms, benign included**. The policy's `taint-unknown-destination`
rule then denies a transfer to a non-allowlisted destination from a tainted
session; benign tasks send to allowlisted destinations, so taint never blocks
them.

The taint *categories* are definitional provenance sources the frozen policy
recognises (`untrusted_web | untrusted_onchain | untrusted_email`): transaction
history is on-chain; a read resource's category is declared by its surface in
`scenarios.py`. The trusted/untrusted decision itself lives in the hashed trust
map, never here.
"""
import json
import pathlib

PILOT2 = pathlib.Path(__file__).resolve().parent.parent / "policies" / "pilot2"
TRUST_FILE = PILOT2 / "tool-trust.json"

# Transaction history is on-chain, counterparty-controlled; its provenance
# category when `get_recent_transactions` is an untrusted-output tool.
TX_HISTORY_LABEL = "untrusted_onchain"
BASE_LABEL = "trusted_user"


def load_trust() -> dict:
    return json.loads(TRUST_FILE.read_text())


class Session:
    """One episode's monotonic taint set. `provenance()` is handed to the
    wallet provider, so every signing request carries the current labels."""

    def __init__(self, trust: dict | None = None):
        self.trust = trust if trust is not None else load_trust()
        self.untrusted_tools = set(self.trust.get("untrusted_output_tools", []))
        self.labels: set[str] = set()

    def reset(self) -> None:
        self.labels = set()

    def taint_tool(self, tool: str, label: str) -> None:
        """Taint the session when an *untrusted-output* read tool (per the
        hashed trust map) returns content carrying the given provenance label."""
        if tool in self.untrusted_tools and label:
            self.labels.add(label)

    def provenance(self) -> list[str]:
        return [BASE_LABEL, *sorted(self.labels)]
