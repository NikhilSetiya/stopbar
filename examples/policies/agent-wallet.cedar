// Stopbar starter policy: AI agent with an EVM hot wallet.
// Outcomes: @outcome("deny") > @outcome("escalate") > permit. No permit match = deny.

@id("base-permit")
permit (principal, action in [Stopbar::Action::"transfer", Stopbar::Action::"contract_call"], resource);

@id("taint-unknown-destination") @message("Untrusted content is in the agent's context and the destination is not allowlisted") @outcome("deny")
forbid (principal, action, resource)
when { context.taint.containsAny(["untrusted_web","untrusted_onchain","untrusted_email"]) && !context.dest_known };

@id("unlimited-approval") @message("Unlimited token approval") @outcome("deny")
forbid (principal, action == Stopbar::Action::"approve", resource)
when { context.flags.contains("unlimited_approval") };

@id("delegatecall") @message("delegatecall hands control of the wallet to another contract") @outcome("deny")
forbid (principal, action, resource) when { context.flags.contains("delegatecall") };

@id("excessive-fee") @message("Fee terms (gas limit × max fee) could burn far more than a normal transaction") @outcome("deny")
forbid (principal, action, resource) when { context.flags.contains("excessive_fee") };

@id("proxy-upgrade") @message("Proxy upgrade changes the code behind the contract") @outcome("deny")
forbid (principal, action, resource) when { context.flags.contains("proxy_upgrade") };

@id("large-share-of-balance") @message("Transfer exceeds 20% of the wallet balance") @outcome("escalate")
forbid (principal, action, resource) when { context.pct_of_balance.greaterThan(decimal("0.20")) };

@id("address-poisoning") @message("Destination looks like a known address but is not one (address poisoning)") @outcome("escalate")
forbid (principal, action, resource) when { context.dest_similar_to_known && !context.dest_known };

@id("stale-price") @message("Price data is stale; USD value cannot be trusted") @outcome("escalate")
forbid (principal, action, resource) when { context.price_stale };

@id("unknown-call") @message("Contract call could not be decoded") @outcome("escalate")
forbid (principal, action, resource) when { context.flags.containsAny(["unknown_call","opaque"]) };
