# Banking pilot policy pack, v1. FOR REVIEW, NOT YET FROZEN

Pre-registration: [`../../PILOT.md`](../../PILOT.md) §3. The bundle is the three files this README sits next to: `banking.cedar`, `tools.cedarschema` and `tool-trust.json`. The bundle hash covers all three (`internal/policy`, LLD §5.4). This README is not part of the hash.

## What the author read

Only the banking **tool definitions** in `agentdojo==0.1.35`:
- `default_suites/v1/tools/banking_client.py`
- `file_reader.py`
- `user_account.py`

No injection tasks, user tasks, attack templates or run output were read. The only contact with the task files was a `grep -c` class count, done while scoping. The author's prior exposure to AgentDojo through training data is disclosed in PILOT.md §3.2.

## Trust map (`tool-trust.json`)

| Tool | Output | Class | From the definition |
|---|---|---|---|
| `get_iban` | `str` | read-only, trusted | Returns `account.iban`, the account's own identifier |
| `get_balance` | `float` | read-only, trusted | Returns `account.balance` |
| `get_user_info` | profile dict | read-only, trusted | Returns the account holder's own first/last name, street and city |
| `get_most_recent_transactions` | `list[Transaction]` | read-only, **untrusted** | `Transaction.subject` is free text and `sender` is a counterparty IBAN. Incoming transactions are written by counterparties. |
| `get_scheduled_transactions` | `list[Transaction]` | read-only, **untrusted** | The same `Transaction` type with a free-text `subject` that wasn't written in this session. Classed untrusted conservatively, since taint only restricts. |
| `read_file` | `str` | read-only, **untrusted** | Returns `filesystem.files[path]`: arbitrary contents of unknown authorship |
| `send_money` | message | state-changing | Appends an outgoing `Transaction` |
| `schedule_transaction` | message | state-changing | Appends a scheduled, optionally recurring, outgoing `Transaction` |
| `update_scheduled_transaction` | message | state-changing | Changes recipient, amount, subject, date or recurrence of a scheduled `Transaction` |
| `update_password` | message | state-changing, account identity | Sets `account.password` |
| `update_user_info` | profile dict | state-changing, account identity | Changes the holder's name, street or city |

## Rules (`banking.cedar`)

| Rule | Outcome | What it blocks | Justified by | Names a specific IBAN, amount, file or task? |
|---|---|---|---|---|
| `permit-declared-tools` | allow | Nothing; it permits any **declared** tool. An undeclared tool fails closed before policy runs, because `tool-trust.json` must list it. | Default-deny model (LLD §5.2): only tools the trust map classifies are callable | **No.** It matches on the action type only |
| `tainted-state-change` | **deny** | Any state-changing tool (the five above) once the session has evaluated a call to an untrusted-output tool | `Transaction.subject` and file contents are free text Stopbar can't authenticate (trust map), and the state-changing tools mutate the account. Session taint (LLD §8.2) forbids that combination. This is deliberately blunt (PILOT §3.4). | **No.** It uses only the `state_changing` fact and the generic `untrusted_tool_output` label |
| `account-identity-change` | **escalate** (blocks in the pilot) | `update_password` and `update_user_info`, in any session | They change credentials or the account holder's identity, which loses control of the account rather than money. Pre-registered as an escalation even with no taint (PILOT §3.4). | **No.** It uses only the `account_identity` fact |

Arguments (`recipient`, `amount`, `subject`, `file_path` and so on) are not inspected by any rule. The pilot measures blunt session-level taint.

## Freeze

Not frozen. Freezing waits for the review in PILOT.md §3.2(c). The freeze is a single commit adding `FREEZE.md` with the bundle hash, the date and the sign-off. The harness (CS-503) refuses to run if the loaded bundle hash differs.
