# threadvault

Your AI conversations as something you own and carry between AIs: a project folder holding the
handover note and files, verifiable (hash chain, signatures), scrubbed of secrets before sharing.

Status: Phase 0 (contracts). See `docs/` once added.

## Layout and ownership

| Path | Owner | Contents |
|---|---|---|
| `src/threadvault/core/` | A | thread store, file store, hash chain, verify, pack, access log, expiry |
| `src/threadvault/scanners/` | A | secret scanning, file sanitization |
| `src/threadvault/cli/`, `importers/`, `ui/` | B | Typer CLI, importers, Streamlit compare page |
| `extension/` | B | browser extension (Manifest V3) |
| `src/threadvault/connector/`, `privacy/`, `policy/`, `agent/` | C | MCP connector, redaction, trust policy, handover agent |
| `schemas/`, `docs/`, `tests/fixtures/` | everyone | shared contracts (change by PR with all three approving) |

## Dev setup

```
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```
