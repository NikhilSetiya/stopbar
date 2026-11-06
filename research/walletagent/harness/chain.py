"""Fork helpers: fund ERC-20 balances on the Anvil fork, build calldata, and
snapshot/revert. Stdlib + web3 + eth_abi/eth_utils (all in requirements.lock).
No key: Anvil's test accounts and cheatcodes only.
"""
from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address
from web3 import Web3

ERC20_ABI = [
    {"name": "balanceOf", "inputs": [{"type": "address"}], "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"name": "allowance", "inputs": [{"type": "address"}, {"type": "address"}], "outputs": [{"type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"name": "decimals", "inputs": [], "outputs": [{"type": "uint8"}], "stateMutability": "view", "type": "function"},
]


def selector(sig: str) -> bytes:
    return keccak(text=sig)[:4]


def cd(sig: str, types: list[str], args: list) -> str:
    return "0x" + (selector(sig) + abi_encode(types, args)).hex()


def erc20_transfer(to: str, amount: int) -> str:
    return cd("transfer(address,uint256)", ["address", "uint256"], [to_checksum_address(to), amount])


def erc20_approve(spender: str, amount: int) -> str:
    return cd("approve(address,uint256)", ["address", "uint256"], [to_checksum_address(spender), amount])


def weth_deposit() -> str:
    return cd("deposit()", [], [])


def weth_withdraw(amount: int) -> str:
    return cd("withdraw(uint256)", ["uint256"], [amount])


def swaprouter02_exact_in_single(token_in, token_out, fee, recipient, amount_in, min_out) -> str:
    # exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))
    return cd("exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
              ["(address,address,uint24,address,uint256,uint256,uint160)"],
              [(to_checksum_address(token_in), to_checksum_address(token_out), fee,
                to_checksum_address(recipient), amount_in, min_out, 0)])


def balance_of(w3: Web3, token: str, who: str) -> int:
    return w3.eth.contract(address=to_checksum_address(token), abi=ERC20_ABI).functions.balanceOf(to_checksum_address(who)).call()


def allowance(w3: Web3, token: str, owner: str, spender: str) -> int:
    return w3.eth.contract(address=to_checksum_address(token), abi=ERC20_ABI).functions.allowance(to_checksum_address(owner), to_checksum_address(spender)).call()


def _rpc(w3: Web3, method: str, params: list):
    return w3.provider.make_request(method, params)


def deal(w3: Web3, token: str, holder: str, amount: int, max_slot: int = 40) -> int:
    """Set an ERC-20 balance by finding the balanceOf mapping slot and writing
    it (the forge-std 'deal' trick). Returns the slot used; raises if none of
    the first max_slot slots is the balance mapping."""
    token, holder = to_checksum_address(token), to_checksum_address(holder)
    for slot in range(max_slot):
        key = "0x" + keccak(abi_encode(["address", "uint256"], [holder, slot])).hex()
        before = _rpc(w3, "eth_getStorageAt", [token, key, "latest"])["result"]
        _rpc(w3, "anvil_setStorageAt", [token, key, "0x" + amount.to_bytes(32, "big").hex()])
        if balance_of(w3, token, holder) == amount:
            return slot
        _rpc(w3, "anvil_setStorageAt", [token, key, before])  # restore and keep looking
    raise RuntimeError(f"deal: balanceOf slot for {token} not found in 0..{max_slot}")


def set_balance(w3: Web3, who: str, wei: int) -> None:
    _rpc(w3, "anvil_setBalance", [to_checksum_address(who), hex(wei)])


def snapshot(w3: Web3) -> str:
    return _rpc(w3, "evm_snapshot", [])["result"]


def revert(w3: Web3, snap: str) -> None:
    _rpc(w3, "evm_revert", [snap])


QUOTER_V2 = "0x3d4e44Eb1374240CE5F1B871ab261CD16335B76a"  # Uniswap QuoterV2 on Base (verified on fork)
_QUOTER_ABI = [{"name": "quoteExactInputSingle", "stateMutability": "nonpayable", "type": "function",
    "inputs": [{"type": "tuple", "components": [{"name": "tokenIn", "type": "address"}, {"name": "tokenOut", "type": "address"},
        {"name": "amountIn", "type": "uint256"}, {"name": "fee", "type": "uint24"}, {"name": "sqrtPriceLimitX96", "type": "uint160"}]}],
    "outputs": [{"name": "amountOut", "type": "uint256"}, {"name": "a", "type": "uint160"}, {"name": "b", "type": "uint32"}, {"name": "c", "type": "uint256"}]}]


def quote_exact_in(w3: Web3, token_in: str, token_out: str, amount_in: int, fee: int = 100) -> int:
    q = w3.eth.contract(address=to_checksum_address(QUOTER_V2), abi=_QUOTER_ABI)
    return q.functions.quoteExactInputSingle(
        (to_checksum_address(token_in), to_checksum_address(token_out), amount_in, fee, 0)).call()[0]
