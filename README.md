# threadvault

Your AI conversations as something you own and carry between AIs: a project folder holding the
handover note and files, verifiable (hash chain, signatures), scrubbed of secrets before sharing.

Status: the CLI, importers, on-disk vault, comparison page and the local ingest service for the
browser extension work. See `docs/SPEC.md` and `docs/THREAT_MODEL.md`.

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

## Quick start (CLI)

Use fake data while trying it out. The vault is `--vault <dir>`, else `$THREADVAULT_DIR`, else
`~/.threadvault`.

```
export THREADVAULT_DIR=/tmp/tv-demo
thread init                                # vault + extension token + starter policy.json
thread import chatgpt conversations.json   # also: claude, gemini, markdown
thread list
thread verify                              # exit code 1 if any thread was edited
thread show <thread-id>
thread fork <thread-id> --label alt        # new branch sharing history; becomes current
thread pack <thread-id>                    # handover wrapped as historical context
thread handover add <thread-id> reply.txt  # save an AI-written handover after review
thread export <thread-id> <destination> out.txt   # only destinations listed in policy.json
```

Imports are stored as `imported-unverified` and scanned for secrets and prompt injection.
`export` is default-deny: put a `policy.json` in the vault directory first.
Set `THREADVAULT_KEYCHAIN=1` (with `pip install -e ".[keychain]"`) to sign records with a key in
the OS keychain; otherwise records are hash-chained but unsigned, and `verify` says so.

## Comparison page

```
pip install -e ".[ui]"
streamlit run src/threadvault/ui/app.py -- --vault "$THREADVAULT_DIR"
```

## Browser extension (Chrome / Firefox)

```
cd extension && npm run build        # writes dist/chrome and dist/firefox; npm test runs its tests
```

Chrome: `chrome://extensions` > Developer mode > Load unpacked > `extension/dist/chrome`.
Firefox: `about:debugging` > This Firefox > Load Temporary Add-on > `extension/dist/firefox/manifest.json`.
Connect it to the vault:

1. `thread init` (once), then `thread token show`; paste the token into the extension options.
2. Find the extension id on `chrome://extensions` (Firefox: `about:debugging`, "Internal UUID").
3. `thread serve --origin chrome-extension://<id>` (Firefox: `--origin moz-extension://<uuid>`).
   It listens on 127.0.0.1:8765 only; the extension options hold the port.
4. Open ChatGPT or Claude, capture a handover, review it, save. Then `thread list` and
   `thread verify`.

The service checks the token, `Host` and `Origin`, accepts JSON only (70 MiB cap, rate limited),
and applies `policy.json`: only `browser-extension` may append and save handovers, secrets are
blocked and personal data needs your confirmation. Sign records with `THREADVAULT_KEYCHAIN=1`.
