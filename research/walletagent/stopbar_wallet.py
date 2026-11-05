"""Coinbase AgentKit wallet provider that holds no key: Stopbar gatekeeper mode.

The agent's AgentKit actions (transfer, approve, wrap, supply, ...) build
transactions as usual. This provider:
  1. fills in the nonce, gas and fees from the chain (exactly what AgentKit's
     own EthAccountWalletProvider does),
  2. sends the complete unsigned EIP-1559 transaction to stopbard's
     /v1/evaluate,
  3. broadcasts the signed transaction stopbard returns, and only on HTTP 200
     (allow). 202 (escalate) and every other status raise; nothing is sent.

stopbard holds the wallet key (-dev-wallet). This process never sees it, so
an agent that is injected or compromised can't sign around the policy.

Off-chain signatures (sign_message, sign_typed_data: EIP-712 permits, Permit2
signatures) are not gated by Stopbar yet, so they are refused here: a signed
Permit2 message is as good as an approval.
"""
import base64, datetime, json, os, urllib.error, urllib.request, uuid
from decimal import Decimal
from typing import Any, Callable

from coinbase_agentkit.network import Network
from coinbase_agentkit.wallet_providers.evm_wallet_provider import EvmWalletProvider
from web3 import Web3


class StopbarBlocked(Exception):
    """stopbard did not allow the transaction. Carries the HTTP status and the
    decision's reasons, so the agent (and an adaptive attacker) can read why."""

    def __init__(self, status: int, decision: dict):
        self.status, self.decision = status, decision
        reasons = [r.get("policy_id") or r.get("code") for r in decision.get("reasons", [])] or [decision.get("code")]
        verb = {202: "needs human approval (escalated)", 403: "denied"}.get(status, "rejected")
        super().__init__(f"Stopbar {verb} (HTTP {status}): {', '.join(str(r) for r in reasons)}")


class StopbarWalletProvider(EvmWalletProvider):
    def __init__(self, *, stopbard_url: str, rpc_url: str, address: str, chain_id: int, tenant: str = "test",
                 agent_id: str = "wallet-agent", session_id: str | None = None,
                 provenance: Callable[[], list[str]] = lambda: ["trusted_user"],
                 gas_limit_multiplier: float = 1.2, fee_per_gas_multiplier: float = 1.0, timeout: float = 15.0):
        self.url, self.timeout = stopbard_url.rstrip("/"), timeout
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        self.address = Web3.to_checksum_address(address)
        self.chain_id = chain_id
        self.tenant, self.agent_id = tenant, agent_id
        self.session_id = session_id or str(uuid.uuid4())
        self.provenance = provenance  # the harness's taint labels for the agent's current context (v1: SDK taint)
        self.gas_mult, self.fee_mult = gas_limit_multiplier, fee_per_gas_multiplier
        self.decisions: list[dict] = []  # every decision, for the run log

    # ---- identity and reads ----
    def get_address(self) -> str:
        return self.address

    def get_network(self) -> Network:
        return Network(protocol_family="evm", network_id=f"chain-{self.chain_id}", chain_id=str(self.chain_id))

    def get_name(self) -> str:
        return "stopbar_gatekeeper_wallet_provider"

    def get_balance(self) -> Decimal:
        return Decimal(self.web3.eth.get_balance(self.address))

    def read_contract(self, contract_address, abi, function_name, args=None, block_identifier="latest") -> Any:
        c = self.web3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=abi)
        return getattr(c.functions, function_name)(*(args or [])).call(block_identifier=block_identifier)

    def wait_for_transaction_receipt(self, tx_hash, timeout: float = 120, poll_latency: float = 0.1) -> dict[str, Any]:
        return self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout, poll_latency=poll_latency)

    # ---- signing: only through Stopbar ----
    def sign_message(self, message) -> str:
        raise StopbarBlocked(0, {"code": "OFFCHAIN_SIGNING_NOT_GATED"})

    def sign_typed_data(self, typed_data: dict[str, Any]) -> str:
        raise StopbarBlocked(0, {"code": "OFFCHAIN_SIGNING_NOT_GATED"})

    def sign_transaction(self, transaction) -> Any:
        raise StopbarBlocked(0, {"code": "SIGN_WITHOUT_BROADCAST_NOT_SUPPORTED"})

    def native_transfer(self, to: str, value: Decimal) -> str:
        """value is in whole ETH, as AgentKit's own providers take it."""
        return self.send_transaction({"to": Web3.to_checksum_address(to), "value": Web3.to_wei(value, "ether")})

    def send_transaction(self, transaction) -> str:
        tx = dict(transaction)
        tx["from"] = self.address
        tx["chainId"] = self.chain_id
        tx.setdefault("value", 0)
        tx.setdefault("data", "0x")
        tx["nonce"] = self.web3.eth.get_transaction_count(self.address, "pending")
        base = self.web3.eth.get_block("latest")["baseFeePerGas"]
        tip = self.web3.eth.max_priority_fee
        tx["maxPriorityFeePerGas"] = int(tip * self.fee_mult)
        tx["maxFeePerGas"] = int((2 * base + tip) * self.fee_mult)
        tx["gas"] = int(self.web3.eth.estimate_gas({k: v for k, v in tx.items() if k in ("from", "to", "value", "data")}) * self.gas_mult)
        status, d = self.evaluate(tx)
        self.decisions.append({"status": status, "decision": d, "tx": {k: str(v) for k, v in tx.items()}})
        if status != 200 or not d.get("signed_tx"):
            raise StopbarBlocked(status, d)
        return Web3.to_hex(self.web3.eth.send_raw_transaction(d["signed_tx"]))

    def evaluate(self, tx: dict) -> tuple[int, dict]:
        data = tx["data"] if isinstance(tx["data"], str) else Web3.to_hex(tx["data"])
        body = {
            "id": "req_" + uuid.uuid4().hex, "tenant": self.tenant,
            "nonce": base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("="),
            "issued_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ttl_seconds": 60, "actor": {"agent_id": self.agent_id, "session_id": self.session_id},
            "action": {
                "kind": "evm_tx", "chain_id": self.chain_id, "from": self.address.lower(), "to": tx["to"].lower(),
                "value_wei": str(int(tx["value"])), "data": data.lower(), "tx_type": 2, "tx_nonce": str(tx["nonce"]),
                "gas_limit": str(tx["gas"]), "max_fee_per_gas": str(tx["maxFeePerGas"]),
                "max_priority_fee_per_gas": str(tx["maxPriorityFeePerGas"]),
            },
            "provenance": {"labels": list(self.provenance())},
        }
        req = urllib.request.Request(self.url + "/v1/evaluate", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except ValueError:
                return e.code, {}
        except OSError as e:  # stopbard unreachable: fail closed
            return 0, {"code": "GATE_UNREACHABLE", "message": str(e)}
