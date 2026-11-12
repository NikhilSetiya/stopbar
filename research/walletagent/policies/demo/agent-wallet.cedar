// Stopbar demo policy (make demo-live): an agent wallet that may pay or approve
// only destinations on the owner's allowlist, never grant an unlimited approval,
// and escalates a transfer worth more than 20% of the balance for a human.
// Outcomes combine deny > escalate > permit, with default deny (LLD §5).

@id("permit-allowlisted")
permit (
  principal,
  action in [Stopbar::Action::"transfer", Stopbar::Action::"approve", Stopbar::Action::"contract_call"],
  resource
) when { context.dest_known };

@id("unknown-destination") @message("Destination is not on the wallet's allowlist") @outcome("deny")
forbid (principal, action, resource) when { !context.dest_known };

@id("unlimited-approval") @message("Unlimited token approval") @outcome("deny")
forbid (principal, action, resource) when { context.flags.contains("unlimited_approval") };

@id("large-share-of-balance") @message("Transfer exceeds 20% of the wallet balance") @outcome("escalate")
forbid (principal, action, resource) when { context has pct_of_balance && context.pct_of_balance.greaterThan(decimal("0.20")) };

// When the price feed is unavailable, an unpriced transfer is never allowed
// unchecked: a large amount (raw token units, which need no price) is denied,
// and anything under that cap escalates for a human instead of passing.
@id("stale-price-amount-cap") @message("Price unavailable and the transfer exceeds the hard token-unit backstop cap") @outcome("deny")
forbid (principal, action in [Stopbar::Action::"transfer", Stopbar::Action::"contract_call"], resource)
when { context.price_stale && context has amount_tokens && context.amount_tokens.greaterThan(decimal("1000.0")) };

@id("stale-price") @message("Price unavailable; USD value cannot be trusted") @outcome("escalate")
forbid (principal, action, resource) when { context.price_stale };
