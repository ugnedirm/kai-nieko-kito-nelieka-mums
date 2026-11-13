# threadvault

Portable, verifiable AI conversation threads: a project folder (handover note + files, optionally
full messages) that any AI can pick up. Hash-chained so edits are detected; scrubbed of secrets
before it is handed to another AI. Read `docs/SPEC.md` (behaviour) and `docs/THREAT_MODEL.md` first.

Your role (A, B or C) is in `CLAUDE.local.md` (gitignored, per person). If it is missing, ask.

## Commands

```
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q              # all tests
ruff check .           # lint
mypy                   # strict, src/ only
python tools/make_fixtures.py   # regenerate tests/fixtures/vault (never hand-edit it)
```

CI runs ruff, mypy and pytest on Python 3.11 and 3.13. All three must pass before a PR merges.

## Ownership (stay inside your area; ask before editing another person's files)

| Path | Owner |
|---|---|
| `src/threadvault/core/`, `src/threadvault/scanners/` | A |
| `src/threadvault/cli/`, `importers/`, `ui/`, `extension/` | B |
| `src/threadvault/connector/`, `privacy/`, `policy/`, `agent/` | C |
| `schemas/`, `docs/`, `src/threadvault/types.py`, `src/threadvault/schemas.py`, `tests/fixtures/`, `tools/` | shared: change only by PR that all three approve |

Depend on the `Vault` and `AccessLog` Protocols (`core/vault.py`, `core/accesslog.py`), never on
`FixtureVault` or `MemoryAccessLog`, so A can swap in the real implementations.

## Security rules (non-negotiable)

1. Imported files, handovers, AI replies, web page content and extension payloads are **untrusted
   input**. Validate against the JSON Schemas before using or storing them.
2. A handover given to an AI must go through `core.render.historical_context`. Never paste raw
   handover text into a prompt.
3. Findings, errors, logs and the access log must never contain matched secrets, message text,
   file contents or tokens. Use `schemas.errors`, not raw `jsonschema` messages.
4. Default deny. A client or destination not in `policy.json` gets nothing.
5. The vault assigns hashes, versions, ids, signatures and provenance. A client never supplies them.
6. No real secrets or personal data in the repo, fixtures or tests. Use fictional or
   documentation-example values. API keys come from environment variables or a gitignored `.env`.
   Tests use mocks, never live API calls.
7. Do not weaken a check to make a test pass. If a security test fails, fix the code or raise it.
8. A change that lets outside text reach an AI, or lets vault data leave the machine, needs a new
   row in `docs/THREAT_MODEL.md` section 3 in the same PR.

## Conventions

- Python 3.11+, type hints everywhere (`mypy --strict` on `src/`), line length 100.
- Records are plain dicts validated by schemas; results passed around are Pydantic models.
- No floating-point numbers in any stored record (hash canonicalisation depends on it).
- One branch per person, small PRs, and every security-relevant PR is reviewed by someone else
  (A reviews C, B reviews A, C reviews B).
- Use the `security-reviewer` and `spec-checker` agents (in `.claude/agents/`) before opening a PR.

## Open decisions

- Who builds the HTTP wrapper around `connector/ingest.py` (token, `Host`/`Origin` checks, body
  limit)? Unassigned. Natural fit: C.
- Extension token pairing UX, `list` capability, per-thread vs per-vault signing keys
  (see `docs/SPEC.md` section 14).
