// Stopbar starter policy: AI agent with an EVM hot wallet.
// Outcomes: @outcome("deny") > @outcome("escalate") > permit. No permit match = deny.

@id("base-permit")
permit (principal, action in [Stopbar::Action::"transfer", Stopbar::Action::"contract_call"], resource);

@id("taint-unknown-destination") @outcome("deny")
forbid (principal, action, resource)
when { context.taint.containsAny(["untrusted_web","untrusted_onchain","untrusted_email"]) && !context.dest_known };

@id("unlimited-approval") @outcome("deny")
forbid (principal, action == Stopbar::Action::"approve", resource)
when { context.flags.contains("unlimited_approval") };

@id("delegatecall") @outcome("deny")
forbid (principal, action, resource) when { context.flags.contains("delegatecall") };

@id("proxy-upgrade") @outcome("deny")
forbid (principal, action, resource) when { context.flags.contains("proxy_upgrade") };

@id("large-share-of-balance") @outcome("escalate")
forbid (principal, action, resource) when { context.pct_of_balance > decimal("0.20") };

@id("address-poisoning") @outcome("escalate")
forbid (principal, action, resource) when { context.dest_similar_to_known && !context.dest_known };

@id("stale-price") @outcome("escalate")
forbid (principal, action, resource) when { context.price_stale };

@id("unknown-call") @outcome("escalate")
forbid (principal, action, resource) when { context.flags.containsAny(["unknown_call","opaque"]) };
