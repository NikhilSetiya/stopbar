// Stopbar starter policy: AI agent with an EVM hot wallet.
// Outcomes: @outcome("deny") > @outcome("escalate") > permit. No permit match = deny.

@id("base-permit")
permit (principal, action in [Stopbar::Action::"transfer", Stopbar::Action::"contract_call"], resource);

// Approvals are permitted only when bounded, to a known spender (the tenant's
// allowlist), and worth at most $1,000. Anything else is default-denied, and
// unlimited approvals are also forbidden below.
@id("bounded-approval")
permit (principal, action == Stopbar::Action::"approve", resource)
when {
  context.dest_known && context has approval_usd &&
  context.approval_usd.lessThanOrEqual(decimal("1000.0")) &&
  !context.flags.contains("unlimited_approval")
};

@id("taint-unknown-destination") @message("Untrusted content is in the agent's context and the destination is not allowlisted") @outcome("deny")
forbid (principal, action, resource)
when { context.taint.containsAny(["untrusted_web","untrusted_onchain","untrusted_email"]) && !context.dest_known };

// Flags are the union over every nested call, so these rules match whatever
// the top-level action is: an approval inside a multicall is still caught.
@id("unlimited-approval") @message("Unlimited token approval") @outcome("deny")
forbid (principal, action, resource)
when { context.flags.contains("unlimited_approval") };

@id("min-out-zero") @message("Swap accepts any output at all (no slippage protection)") @outcome("deny")
forbid (principal, action, resource) when { context.flags.contains("min_out_zero") };

@id("wallet-admin") @message("Changes who controls the wallet (owners, threshold, modules or guard)") @outcome("escalate")
forbid (principal, action, resource) when { context.flags.contains("wallet_admin") };

@id("delegatecall") @message("delegatecall hands control of the wallet to another contract") @outcome("deny")
forbid (principal, action, resource) when { context.flags.contains("delegatecall") };

@id("excessive-fee") @message("Fee terms (gas limit × max fee) could burn far more than a normal transaction") @outcome("deny")
forbid (principal, action, resource) when { context.flags.contains("excessive_fee") };

@id("proxy-upgrade") @message("Proxy upgrade changes the code behind the contract") @outcome("deny")
forbid (principal, action, resource) when { context.flags.contains("proxy_upgrade") };

@id("large-share-of-balance") @message("Transfer exceeds 20% of the wallet balance") @outcome("escalate")
forbid (principal, action, resource) when { context has pct_of_balance && context.pct_of_balance.greaterThan(decimal("0.20")) };

@id("address-poisoning") @message("Destination looks like a known address but is not one (address poisoning)") @outcome("escalate")
forbid (principal, action, resource) when { context.dest_similar_to_known && !context.dest_known };

@id("stale-price") @message("Price data is stale; USD value cannot be trusted") @outcome("escalate")
forbid (principal, action, resource) when { context.price_stale };

@id("unknown-call") @message("Contract call could not be decoded") @outcome("escalate")
forbid (principal, action, resource) when { context.flags.containsAny(["unknown_call","opaque"]) };
