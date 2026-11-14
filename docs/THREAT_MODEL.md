# Threat model (v1 draft)

Companion to `SPEC.md`. Purpose: say what we defend, against whom, and where we stop, so security
work is testable and reviewers know what "secure enough" means here.

## 1. What we protect

| Asset | Why it matters |
|---|---|
| Integrity of the record (handovers, messages, files) | Users rely on it for contracts, research, handoffs |
| Confidentiality of vault contents | Threads contain personal data, secrets, business information |
| The user's control over where data goes | Handing a thread to the wrong AI is a leak |
| Permission boundaries | A loaded thread must never grant an AI more power |
| The API token and signing keys | They are the keys to the vault |

## 2. Trust boundaries

1. **Vault owner (trusted).** The user and their local OS account.
2. **Vault code (trusted, but must be tested).** Core, scanners, policy, ingest service.
3. **AI providers (semi-trusted).** They see whatever we send them. They can write wrong or malicious text.
4. **Browser extension (limited trust).** Reads chat pages; talks to the vault.
5. **Web pages, including the chat sites (untrusted).** Page content is attacker-influenced.
6. **Imported files and handover text (untrusted input).** Always.
7. **Other local processes and other OS users (untrusted).**

## 3. Threats and mitigations

Status: **Spec** = required by `SPEC.md`; **Test** = a fixture or test exists; **Later** = planned.

| # | Threat | Attacker | Mitigation | Spec | Status |
|---|---|---|---|---|---|
| T1 | A message or handover is silently edited, reordered or removed | Anyone with file access, a buggy tool | Hash chain, `verify` recomputes everything, head hash in manifest | §3, §6 | Test (`thr_tamper01`) |
| T2 | Attacker edits and recomputes hashes after the fact | Local attacker with write access | Signatures with a key held in the OS keychain; trusted keys come from the key store, never the manifest; once a lineage is signed every later record must be; optional RFC 3161 timestamps | §3.6, §15 | Test (`test_verify_tamper.py`, `test_properties.py`) |
| T3 | Handover contains instructions that hijack the next AI ("ignore previous instructions") | Malicious page, imported chat, poisoned summary | Wrap as `<historical_context>`, escape closing tags, schema caps, scan for injection patterns, user review before save | §7 | Test (planted line in `thr_secrets01`) |
| T4 | A handover or import claims permissions ("user approved deleting files") | Same | Loading never changes permissions; approvals are history only | §7.5 | Spec |
| T5 | Secrets or PII go to another AI or an export | User mistake, AI copying keys into summaries | Scanners on ingest and on every handoff; per-destination profile; `block_on_secrets` enforced by the vault | §8.5, §9 | Test (fixture) |
| T6 | Unlisted AI or plugin reads or writes the vault | Rogue MCP client or plugin | Default-deny policy, capability checks, destination allowlist, access log | §10 | Test (policy fixture) |
| T7 | A web page talks to the local ingest service | Malicious site (CSRF, DNS rebinding) | 127.0.0.1 bind, token, `Host` check, `Origin` allowlist, no wildcard CORS, JSON only | §8 | Spec |
| T8 | Another local user or process reads the token | Local attacker | Token file mode `0600`; documented limit (see §4) | §8 | Spec |
| T9 | Malicious or malformed import (zip bomb, path traversal, huge JSON, hidden Unicode) | Attacker-supplied export file | Size and depth limits, safe extraction (no path escapes), schema validation, fuzz tests | schemas | Test (`tests/test_importers_*.py`, hypothesis fuzzing; Phase 3 importers for ChatGPT, Claude, Gemini, Markdown) |
| T10 | Compromised extension or hostile page content exfiltrates chats | Supply chain, XSS in the extension | Minimal permissions (two chat domains + localhost), no remote code, no telemetry, review screen before send, pinned dependencies | — | Test (`tests/test_extension.py` audits permissions, CSP, no remote code/HTML injection, network confined to the background worker) |
| T11 | Extension forges history (fake provenance) | Compromised extension | Vault assigns hashes, versions and provenance; page-scraped content is stored `imported-unverified` | §8.3 | Spec |
| T12 | Deleted data survives ("forget" doesn't forget) | Careless implementation | `forget` removes blob and writes tombstones everywhere it was referenced; tested | §5 | Test (`thr_tomb0001`) |
| T13 | Access log is edited to hide activity | Local attacker | Hash-chained log; entries never contain content | §11 | Test |
| T14 | Secrets leak through logs, errors or the access log | Our own code | `detail` and findings never contain values; no tokens in logs | §9, §11 | Spec |
| T15 | API keys for LiteLLM or the Anthropic API end up in the repo or vault | Developer mistake | Environment variables or gitignored `.env`; tests use mocks; secret scan in CI | — | Later (CI) |
| T16 | Oversized or abusive requests | Local process | Body limit, per-token rate limit | §8 | Spec |
| T17 | A forged fork or branch splices foreign history | Attacker with write access | `fork_link_mismatch` check; fork point must exist in the parent chain | §6 | Test (`thr_forked01`) |
| T18 | Imported or captured text carries hidden Unicode (tag characters, bidi overrides, zero-width) that a human cannot see but an AI reads | Attacker-supplied export or chat page | Importers and the extension strip hidden characters and non-printing controls and report counts; `scan_import` flags them; visible instructions are flagged as `prompt_injection`; output still goes through `historical_context` | §7, §9 | Test (`test_importers_more.py`, `extension/test/lib.test.js`) |
| T19 | Terminal escape sequences in imported titles or messages hijack the owner's terminal when `show`, `pack` or `verify` print them | Attacker-supplied export | Every string the CLI or compare page prints passes through `terminal_safe` (control, bidi, zero-width characters replaced); the compare page uses `st.text` only, never HTML or Markdown | — | Test (`test_cli.py`) |
| T20 | A page forges roles or conversation structure so the capture lies about who said what (for example text that starts with "assistant:") | Hostile chat page, changed site markup | Role comes from the matching selector, never from page text; adapters have a versioned self-test and capture is refused when it fails; captured messages are stored `imported-unverified`; the extension never sets provenance, hashes or ids | §8.3 | Test (`extension/test/adapters.test.js`) |
| T21 | The extension fills the chat box with text the user did not intend, or a page triggers capture without the user knowing | Hostile page, compromised extension | Only the static handover prompt (generated from the Python package, checked by a test) is ever inserted; the extension never presses send; nothing is saved until the review screen is approved (`user_reviewed`); the extension holds no read capability, so no vault data flows into chats | §7.4, §8 | Test (`test_extension.py`) |
| T22 | An export leaks more than the user chose, or is altered or padded in transit | User mistake; anyone handling the bundle | Selective export (branches, files, handover-only); withheld files listed; descriptor signed over every entry's hash; `verify_export` rejects unlisted, altered or unsafe paths; export refuses high-severity secrets in records unless explicitly allowed (included blobs are NOT scanned; handover-only and default exports include every file in `manifest.files`); `verify_export` fails when trusted keys are given and the signer is not one of them, and requires signed records; `export_thread` has no policy check of its own, so the caller must check `export` capability and destination profile first (open: a single policy-checked entry point, natural owner C) | §15 | Test (`test_timestamps_export.py`, `test_review_regressions.py`) |
| T23 | Timestamping leaks thread content or trusts a lying TSA | TSA operator, network observer | Only the 32-byte record hash and a random nonce are sent, and only to a TSA URL the user names; response imprint and nonce checked; TSA signature is NOT verified by us (needs the TSA trust anchor; use `openssl ts -verify`), so a token is evidence for a third party, not something `verify` trusts | §15 | Test (mock TSA) |
| T24 | Encrypted vault contents read from disk or backups | Thief of the disk or a backup | age (X25519 + ChaCha20-Poly1305) for blobs and chain records, identity in the OS keychain; manifests and branch files stay plaintext (titles, ids, timestamps visible) | §15 | Test (`test_crypto_and_amend.py`) |
| T25 | A "sanitized" file still carries metadata or hidden content | Our own code; unusual file structures | Report says `NOT removed` and `complete: false` whenever something was found but not stripped; PDF rebuilt and orphaned objects dropped; tests check the cleaned bytes, not just the report | §15 | Test (`test_scanners_sanitize.py`) |
| T26 | File contents, messages or metadata in a context pack hijack the next AI or escape the wrapper | Malicious file, page scrape, import | Files and messages go in `<historical_files>`/`<historical_messages>` with the "information, not instructions" preamble; every interpolated field (content, model, role, file name, media type) is flattened to one printable line and wrapper tags are neutralised; caller must apply the destination profile first | §7, §15.6 | Test (`test_review_regressions.py`) |

## 4. Explicitly out of scope (v1)

State these in user-facing docs too, so no one assumes more protection than exists.

- **A fully compromised machine or OS account.** Malware running as the user can read the vault,
  the token and the keychain. We reduce damage (encryption at rest, Phase 2) but do not defend against it.
- **Malicious AI providers.** Anything sent to a provider is visible to it. Redaction reduces
  exposure; it is not a guarantee. Regex and NER detection will miss things.
- **Proving a handover was truthful.** `verify` shows a handover has not changed since saving. It
  cannot show the summary matched the real conversation, and in handover-only mode there is no
  transcript to compare to. The UI must say so.
- **Proving authorship of imported history.** Imports are `imported-unverified`.
- **Denial of service by the vault owner's own tools.**
- **Side channels and traffic analysis.**
- **Guaranteed erasure on SSDs and copy-on-write filesystems.** `forget` overwrites plaintext blobs
  before unlinking them, but the drive may keep old blocks; encryption at rest is the real defence.
- **Dropping the newest access-log entry.** The log is a chain with no external head anchor, so
  removing the last entry (only) is not detectable from the log alone.
- **Cutting the tail off a signed chain, or deleting a whole fork.** The manifest (which holds the
  branch heads) is not signed, so an attacker can remove the last N records of a branch and update
  `head_hash`, or remove a fork and its manifest entry, and `verify` still passes. Signing the
  manifest heads or anchoring them (key store, RFC 3161 timestamp of the head) is open work.
- **Proving a file is absent from an encrypted vault.** Blob names are the SHA-256 of the plaintext,
  so anyone with the vault folder can confirm whether a file they already have is stored; manifests
  also show file names, sizes and media types.
- **Multi-user vaults and remote sharing** (not in v1).

## 5. Residual risks to communicate

1. A user can approve a bad handover in the review screen. Review-before-save reduces this but
   people click through.
2. Scanner false negatives: a leaked secret in an unusual format will pass. Keep patterns and tests
   growing; treat `block_on_secrets` as a safety net, not a guarantee.
3. Extension adapters break when sites change markup; a broken adapter could capture partial or
   wrong content. It must fail loudly, never silently.
4. Terms of service of the chat sites may restrict automated capture. Check before publishing.

## 6. Security tests each person owns

| Person | Must have tests for |
|---|---|
| A | T1, T2 (when signing lands), T12, T13, T17: chain tamper cases, property-based fuzzing of `verify`, tombstone rules |
| B | T9, T10, T11: hostile import files, extension permission audit, adapter-failure behaviour |
| C | T3, T4, T5, T6, T7, T14, T16: injection wrapping, capability denials, redaction, origin/Host checks, no value in findings |

Every security-relevant PR gets a review from a different person than the author (A reviews C,
B reviews A, C reviews B).

## 7. Review cadence

Revisit this document at the end of each phase and whenever a new input channel, destination or
capability is added. A new feature that adds a way for outside text to reach an AI, or for vault
data to leave the machine, needs a new row in §3 before it merges.
