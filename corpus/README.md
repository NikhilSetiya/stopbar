# Attack corpus

Every real-world attack on agents, wallets, or signers becomes a regression test here.
Schema: [`schema.json`](schema.json). Entries live in [`attacks/`](attacks/) as `CS-YYYY-NNNN-slug.yaml`.

To contribute: copy an existing entry, describe the attack, reference public sources,
and set `expected` to the outcome a correct policy must produce. CI validates the schema and
replays it against the starter policy pack.

Seed backlog (CS-193): encoded injection, unauthorised agent signing, agent over-transfer,
unlimited approval, delegatecall (Bybit), proxy upgrade, address poisoning, velocity drain,
stale-price under-valuation, multicall-hidden transfer.
