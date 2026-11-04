# Banking pilot policy pack, v1. FROZEN (see FREEZE.md)

Pre-registration: [`../../PILOT.md`](../../PILOT.md) §3. The bundle is the three files this README sits next to: `banking.cedar`, `tools.cedarschema` and `tool-trust.json`. The bundle hash covers all three (`internal/policy`, LLD §5.4). This README is not part of the hash.

## What the author read

Only the banking **tool definitions** in `agentdojo==0.1.35`:
- `default_suites/v1/tools/banking_client.py`
- `file_reader.py`
- `user_account.py`

No injection tasks, user tasks, attack templates or run output were read. The only contact with the task files was a `grep -c` class count, done while scoping. The author's prior exposure to AgentDojo through training data is disclosed in PILOT.md §3.2.

## Trust map (`tool-trust.json`)

**Principle** (hashed in the file): *any tool output containing content not written by a trusted input during this session is untrusted.* When a definition doesn't establish who wrote a field, the output is untrusted.

| Tool | Output | Class | From the definition |
|---|---|---|---|
| `get_iban` | `str` | read-only, trusted | Returns `account.iban`, the account's own identifier |
| `get_balance` | `float` | read-only, trusted | Returns `account.balance` |
| `get_user_info` | profile dict | read-only, trusted | Returns the account holder's own first/last name, street and city |
| `get_most_recent_transactions` | `list[Transaction]` | read-only, **untrusted** | `Transaction.subject` is free text and `sender` is a counterparty IBAN. Incoming transactions are written by counterparties. |
| `get_scheduled_transactions` | `list[Transaction]` | read-only, **untrusted** | The same `Transaction` type with a free-text `subject`. The definition doesn't establish that a trusted input wrote it this session, so it's untrusted under the principle. Confirmed in review (PILOT Amendment 2). |
| `read_file` | `str` | read-only, **untrusted** | Returns `filesystem.files[path]`: arbitrary contents of unknown authorship |
| `send_money` | message | state-changing | Appends an outgoing `Transaction` |
| `schedule_transaction` | message | state-changing | Appends a scheduled, optionally recurring, outgoing `Transaction` |
| `update_scheduled_transaction` | message | state-changing | Changes recipient, amount, subject, date or recurrence of a scheduled `Transaction` |
| `update_password` | message | state-changing (account identity, which no pilot rule uses) | Sets `account.password` |
| `update_user_info` | profile dict | state-changing (account identity, which no pilot rule uses) | Changes the holder's name, street or city |

## Rules (`banking.cedar`)

| Rule | Outcome | What it blocks | Justified by | Names a specific IBAN, amount, file or task? |
|---|---|---|---|---|
| `permit-declared-tools` | allow | Nothing; it permits any **declared** tool. An undeclared tool fails closed before policy runs, because `tool-trust.json` must list it. | Default-deny model (LLD §5.2): only tools the trust map classifies are callable | **No.** It matches on the action type only |
| `tainted-state-change` | **deny** | Any state-changing tool (the five above) once the session has evaluated a call to an untrusted-output tool | `Transaction.subject` and file contents are free text Stopbar can't authenticate (trust map), and the state-changing tools mutate the account. Session taint (LLD §8.2) forbids that combination. This is deliberately blunt (PILOT §3.4). | **No.** It uses only the `state_changing` fact and the generic `untrusted_tool_output` label |

Arguments (`recipient`, `amount`, `subject`, `file_path` and so on) are not inspected by any rule. The pilot measures blunt session-level taint.

**Removed in review (PILOT Amendment 2): `account-identity-change`** (escalate identity changes in any session).
- In an injected session the session is already tainted, so `tainted-state-change` blocks those tools anyway.
- In a clean session the rule would only block benign tasks, and that loss would land in the headline gap the decision rule reads.

It stays a product rule (CS-117).

## Freeze

Frozen. The hash, the date and the sign-off are in [`FREEZE.md`](FREEZE.md). `TestBankingPackIsFrozen` fails CI if any bundle file changes, and the harness (CS-503) refuses to run on any other hash. Any change after this is a new pre-registered version.
