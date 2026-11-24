"""AgentKit posts the wallet address, network and every action name to
Coinbase analytics and has no opt-out. Stub both call sites process-wide; every
demo, e2e and pilot provider imports this first (mirrors stopbar.wallet)."""


def disable_agentkit_telemetry() -> None:
    from coinbase_agentkit.action_providers import action_decorator
    from coinbase_agentkit.wallet_providers.wallet_provider import WalletProvider

    WalletProvider.track_initialization = lambda self: None
    action_decorator.send_analytics_event = lambda event: None
