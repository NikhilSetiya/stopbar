"""Coinbase AgentKit wallet provider that holds no key: Stopbar gatekeeper mode.

Optional — requires ``pip install stopbar[wallet]`` (coinbase-agentkit, web3).
The agent's AgentKit actions build transactions as usual; this provider fills in
nonce, gas and fees from the chain, sends the complete unsigned transaction to
Stopbar through the SDK Client, and broadcasts the signed transaction Stopbar
returns only on an allow. stopbard holds the wallet key, so an injected or
compromised agent cannot sign around the policy.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Callable

try:
    from coinbase_agentkit.network import Network
    from coinbase_agentkit.wallet_providers.evm_wallet_provider import EvmWalletProvider
    from web3 import Web3
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "stopbar.wallet needs the 'wallet' extra: pip install stopbar[wallet]"
    ) from e

from .client import Client
from .errors import StopbarError


class StopbarWalletProvider(EvmWalletProvider):
    """An AgentKit EvmWalletProvider whose signing goes only through Stopbar.

    Off-chain signatures (sign_message, sign_typed_data) are refused: a signed
    Permit2 message is as good as an approval and is not gated yet.
    """

    def __init__(
        self,
        *,
        client: Client,
        rpc_url: str,
        address: str,
        chain_id: int,
        provenance: Callable[[], list[str]] = lambda: [],
        gas_limit_multiplier: float = 1.2,
        fee_per_gas_multiplier: float = 1.0,
    ) -> None:
        self.client = client
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        self.address = Web3.to_checksum_address(address)
        self.chain_id = chain_id
        self.provenance = provenance
        self.gas_mult, self.fee_mult = gas_limit_multiplier, fee_per_gas_multiplier
        self.decisions: list[dict[str, Any]] = []

    # ---- identity and reads ----
    def get_address(self) -> str:
        return self.address

    def get_network(self) -> "Network":
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
        raise StopbarError("off-chain signing is not gated by Stopbar yet; refused")

    def sign_typed_data(self, typed_data: dict[str, Any]) -> str:
        raise StopbarError("off-chain signing is not gated by Stopbar yet; refused")

    def sign_transaction(self, transaction) -> Any:
        raise StopbarError("sign-without-broadcast is not supported; use send_transaction")

    def native_transfer(self, to: str, value: Decimal) -> str:
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

        data = tx["data"] if isinstance(tx["data"], str) else Web3.to_hex(tx["data"])
        action = Client.evm_tx(
            chain_id=self.chain_id, from_addr=self.address, to=tx["to"], value_wei=str(int(tx["value"])),
            data=data, tx_nonce=str(tx["nonce"]), gas_limit=str(tx["gas"]),
            max_fee_per_gas=str(tx["maxFeePerGas"]), max_priority_fee_per_gas=str(tx["maxPriorityFeePerGas"]),
        )
        # evaluate raises StopbarDenied / StopbarEscalated on a non-allow, which
        # propagate to the agent as a tool error — nothing is broadcast.
        decision = self.client.evaluate(action, labels=list(self.provenance()))
        self.decisions.append({"status": decision.status, "decision": decision.body})
        if not decision.signed_tx:
            raise StopbarError("allow without a signed transaction (is stopbard in gatekeeper mode?)")
        return Web3.to_hex(self.web3.eth.send_raw_transaction(decision.signed_tx))
