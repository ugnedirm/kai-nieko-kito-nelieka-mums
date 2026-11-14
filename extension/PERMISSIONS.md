# Extension permissions (reviewed manifest)

Enforced by `tests/test_extension.py`: a change to either manifest that adds anything below fails CI.
Needs review by someone other than the author (C reviews B).

| Permission | Why | Not requested, on purpose |
|---|---|---|
| `storage` | Keep the vault token, port and options in this browser profile | `tabs`, `activeTab`, `scripting`, `cookies`, `webRequest`, `history`, `downloads`, `clipboard*`, `<all_urls>` |
| host `https://chatgpt.com/*`, `https://chat.openai.com/*`, `https://claude.ai/*` | Content script reads the chat page and fills the handover request | any other site |
| host `http://127.0.0.1/*` | Background worker talks to the local vault service (any port) | `localhost`, any remote host |

- No `web_accessible_resources`, no `externally_connectable`: web pages cannot load or message the extension.
- CSP: `script-src 'self'`, no inline script, no `eval`, no remote code. All code ships in the package.
- Only `background.js` makes network requests, only to `http://127.0.0.1:<port>`, with the token, `credentials: omit`, `redirect: error`.
- Content scripts never hold the token and never use the network. They ask the background worker for the (non-secret) options; where the browser supports `storage.local.setAccessLevel` (Chrome), `storage.local` is closed to content scripts entirely. The worker accepts messages only from this extension (chat tabs on the allowed hosts, or its own pages).
- No telemetry, no analytics.

## Known gaps (to close before a store release)

- The vault HTTP service does not exist yet (open decision in CLAUDE.md). Until it does, the extension cannot save anything end to end.
- Adapter selectors have not been checked against the live sites; use the popup self-test, then bump the adapter `version`.
- The Firefox build asks the user to grant host permissions after install (MV3 behaviour).
- Terms of service of the chat sites may restrict automated capture (THREAT_MODEL residual risk 4).
