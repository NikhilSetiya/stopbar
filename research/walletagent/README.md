# Wallet-agent integration (CS-512): Coinbase AgentKit in gatekeeper mode

`StopbarWalletProvider` (`stopbar_wallet.py`) is an AgentKit `EvmWalletProvider` that **holds no key**:
1. AgentKit's actions build transactions as usual.
2. The provider fills in the nonce, gas and fees from the chain.
3. It sends the complete unsigned EIP-1559 transaction to `stopbard`.
4. It broadcasts the signed transaction `stopbard` returns, and only on HTTP 200.
5. On 202 (escalate), 403 (deny), 4xx/5xx, or no answer at all, it raises, and nothing is sent.

`stopbard` holds the wallet key (`-dev-wallet`), so an injected or compromised agent can't sign around the policy.

Off-chain signing (`sign_message`, `sign_typed_data`) is refused. Stopbar doesn't gate EIP-712 or Permit2 signatures yet (CS-514), and a signed Permit2 message is as good as an approval.

```bash
python3 -m venv research/walletagent/.venv && research/walletagent/.venv/bin/pip install -r research/walletagent/requirements.lock
go build -o bin/stopbard ./cmd/stopbard
research/walletagent/.venv/bin/python research/walletagent/e2e_wallet.py bin/stopbard   # needs anvil (brew install foundry)
```

## Why AgentKit

Candidates checked on 2026-11-05: Coinbase AgentKit (`coinbase-agentkit` 0.7.4, Python; `@coinbase/agentkit` 0.10.4, TS), GOAT (`goat-sdk` 0.1.6 Python, `@goat-sdk/core` 0.5.0 TS), and ElizaOS (no Python package).

1. **It's the stack people actually deploy for agent wallets.** A pilot that claims "a real wallet agent" should use the most common one, not a framework we wrote.
2. **Its wallet abstraction is the seam gatekeeper mode needs.** `EvmWalletProvider.send_transaction` is the only path an action has to the chain, so replacing the provider puts Stopbar in front of every action. No action code changes.
3. **Its local actions run against any RPC, with no vendor API:**
   - ERC-20 transfer and approve
   - native transfer
   - WETH wrap and unwrap
   - ERC-721
   - Compound and Morpho

   That makes an Anvil fork enough.
4. **It's Python,** the same language as the research harness and the AgentDojo work, with the same pinning, venv and e2e pattern.

GOAT's Python SDK is at 0.1.x. Its TS SDK is more complete (it has a Uniswap plugin), but it would add a second language for no gain on the scenarios.

## Limits that matter for the pilot (PILOT-2)

- **No local swap action.** AgentKit's trade action calls Coinbase's cloud API. A swap scenario needs a small custom Uniswap action provider, disclosed as an adaptation.
- **No arbitrary-transaction action, and the provider sets gas itself.** The fee-drain pattern (CS-2026-0007) can't be reached by injecting the agent on this stack. It's a compromised-requester (T3) scenario, and the corpus already covers it. Whether the pilot gives the agent a generic "send transaction" tool, as some frameworks do, is a pre-registration decision.
- **Dependency pin:** `coinbase-agentkit==0.7.4` doesn't import with the newest `solana` (`solana.rpc.api` moved). `solana==0.36.6`, the lowest version it allows, fixes it. Recorded in `requirements.lock`.
- **Anvil:** Foundry via Homebrew (`anvil` 1.9.0).
