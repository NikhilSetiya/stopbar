# Contributing

The highest-leverage contribution is an **attack**: see [corpus/README.md](corpus/README.md).

For code:
1. Pick an issue (start with the `thin-slice` label). Task IDs (`CS-xxx`) map to [docs/TASKS.md](docs/TASKS.md).
2. Reference the ID in commits and PRs: `CS-122: atomic reserve/commit`.
3. Every PR must keep CI green, including the corpus replay suite.
4. Design changes: add or update an ADR in `docs/adr/`.

Backlog edits: change `scripts/tasks.py`, run `python3 scripts/tasks.py`, commit both outputs.
