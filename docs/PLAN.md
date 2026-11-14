# Project plan

The browser extension, the handover prompt, and summary-plus-files storage are **core deliverables**, not extras.

Recorded decisions:
- [ADR 0001: localhost plus token ingest](decisions/0001-ingest-transport-localhost-token.md)
- [ADR 0002: stack and tooling](decisions/0002-stack-and-tooling.md)

Unresolved items are in [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md).

---

## 1. Decisions this forces

### 1.1 Default storage is "handover + files"
A thread stores the files and the AI's summary, not the full transcript. Full-transcript mode remains an option for users who want strong "who said what" guarantees.

What **Trust** means in each mode:

- **Handover mode:** each handover is a signed, hash-chained version (v1, v2, …), so edits and swaps are detected. Files are verified by SHA-256. The record says which AI wrote each summary and when. It **cannot** prove that the summary matches a transcript, and `verify` states this explicitly.
- **Full mode:** the message chain and signatures from the earlier plan.

### 1.2 The extension is the capture path for web chats
It also addresses the "credits running out" problem, because it can see the page:
- It watches for usage-limit warnings and rate-limit banners in the UI.
- It offers **"Create handover now"** and can auto-insert the handover prompt into the chat box.
- It captures the AI's reply, validates it against the schema, runs the scanners, and saves it to the vault.
- It grabs uploaded or generated files from the page.

### 1.3 Credits can't be detected from the model
Two mitigations cover this: the extension, and the **rolling-checkpoint prompt** (refresh the handover every N turns or after each decision). Both are required, because neither is reliable on its own.

### 1.4 Extension caveats to design for
- The DOM changes often, so use **per-site adapters** with a **versioned selector set** and a clear **"adapter broken"** error.
- Check each service's terms of service before shipping.
- The extension needs its **own threat model**, since it reads every chat page. That means minimal permissions, only the two chat domains, no remote code, and no telemetry.

---

## 2. Phase 0: Together

- [ ] **Thread format as JSON Schema** (versioned), covering both modes. It includes:
  - [ ] Manifest
  - [ ] Handover (versioned)
  - [ ] File refs
  - [ ] Message
  - [ ] Branch
  - [ ] Tombstone
  - [ ] Access-log entry
  - [ ] Policy file
  - [ ] Extension ingest payload
- [ ] `SPEC.md`
- [ ] Threat model. Treat the extension and the handover as untrusted input.
- [ ] Sample vault with these threads:
  - [ ] Handover-only thread
  - [ ] Full thread
  - [ ] Forked thread
  - [ ] Tampered thread
  - [ ] Thread with planted secrets and PII
  - [ ] Thread with a tombstone
- [ ] Interface stubs
- [ ] Shared `Finding` type
- [ ] Repo layout and CI
- [ ] **Local ingest API contract** (how the extension talks to the vault). The transport is decided: localhost plus a per-install token, see [ADR 0001](decisions/0001-ingest-transport-localhost-token.md). B and C both depend on this contract.
- [ ] **Handover schema and v1 of the prompt.** Fields: `decisions[]`, `open_questions[]`, `next_steps[]`, `key_facts[]`, `files[]`, `constraints[]`, `uncertain[]`, plus metadata (model, timestamp, thread state).

---

## 3. Person A: Core, integrity, lifecycle, scanners

### Phase 1: Engine
- [ ] Create thread
- [ ] Content-addressed file store
- [ ] Handover versioning with a hash chain
- [ ] Verify (both modes)
- [ ] Text view
- [ ] Context pack (tiktoken): the handover, files, and newest messages if any
- [ ] Branch model

### Phase 2: Security depth
- [ ] Ed25519 signing of handovers, messages and exports, with keys in the OS keychain
- [ ] Signed amendments for edits
- [ ] Provenance levels: `provider-verified`, `ai-summary/user-saved`, `user-asserted`, `imported-unverified`
- [ ] Encryption at rest
- [ ] Optional RFC 3161 timestamps

### Phase 3: Scanners and lifecycle (moved here from B to balance load)
- [ ] Secret scanning with gitleaks/trufflehog-style rules and entropy checks. It runs on handovers, messages and files.
- [ ] File sanitization: EXIF, PDF and Office metadata, hidden sheets, comments, and tracked changes. Outputs a cleaned copy plus a report.
- [ ] Access log: append-only and hash-chained, with a viewer
- [ ] Expiry and deletion: `expires_at`, sweep, and `forget <sha>`, with tombstones that keep the chain valid
- [ ] Selective signed export
- [ ] Property-based tests that try to break the chain

---

## 4. Person B: Extension, importers, CLI, comparison

### Phase 1
- [ ] ChatGPT importer
- [ ] Typer CLI with `import`, `show`, `pack`, `verify`, `fork`, `export`, `handover add`
- [ ] Basic Streamlit compare page

### Phase 2: Browser extension (Manifest V3)
- [ ] ChatGPT and Claude web adapters with versioned selectors and a self-test
- [ ] Capture of file attachments and generated artifacts, plus the conversation in full mode
- [ ] Handover flow: inject the handover prompt, capture the reply, validate the JSON against the schema, show a review-and-edit screen, then save through the ingest API
- [ ] Limit-warning detection that triggers a "save handover now" popup
- [ ] Rolling checkpoint: a reminder or auto-prompt every N turns
- [ ] Hardening: minimal permissions, only the two chat domains, no remote code, a token-authenticated localhost API, and a reviewed permissions manifest
- [ ] Packaging for Chrome and Firefox

### Phase 3
- [ ] Importers for Claude exports, Gemini Takeout and Markdown
- [ ] Importer fuzzing and hardening against zip bombs, path traversal and hidden Unicode
- [ ] Prompt-injection scanner for imports
- [ ] Compare page with diffing, per-message provenance badges, and verify warnings
- [ ] Handover diff view across versions

---

## 5. Person C: AI connection, privacy, trust

### Phase 1
- [ ] FastMCP connector with `list_threads`, `load_thread`, `append`, `get_file`, `save_handover`
- [ ] Claude Desktop working end to end
- [ ] Handover prompt v1, tested against Claude and GPT

### Phase 2: Privacy
- [ ] Regex redaction, then Presidio and local NER, with locale-aware IDs
- [ ] Reversible pseudonymization: `PERSON_1` mappings stored locally, with re-hydration
- [ ] Policy profiles per destination
- [ ] Redaction preview, applied to the handover and files before they go to another AI

### Phase 3: Trust model and multi-AI
- [ ] Capability policy (`read`, `append`, `file_read`, `network`)
- [ ] Destination allowlist
- [ ] Plugin signing and hash-pinning, with unsigned plugins refused
- [ ] Handover hardening: schema-constrained, wrapped as "historical context, not instructions" on load, and never carrying over tool permissions or "user approved X"
- [ ] Handover prompt iteration:
  - [ ] Evaluation set: long chats, chats with secrets, chats with contradictions, adversarial chats
  - [ ] Measure recall of decisions, hallucination rate, and secret leakage
  - [ ] Store the prompt version with each handover
- [ ] Second AI via LiteLLM on a fork, with policy and redaction applied first
- [ ] Adversarial MCP tests

---

## 6. Dependencies and how they're decoupled

| Dependency | Decoupled by |
|---|---|
| B and C need A's engine | Stubs and the sample vault |
| B's extension needs the ingest API | Contract defined in Phase 0; B builds against a mock server |
| Extension and `save_handover` need scanners | Shared `Finding` type; each side uses a regex fallback until A's scanners land |
| C's handover prompt needs the extension for testing | C tests by pasting into the real chats and into `handover add`; no extension needed |
| C's policy needs A's signatures | Policy format is in the shared spec; hash-pinning first, signatures when A lands them |
| A needs nothing | Builds from the spec alone |

---

## 7. Integration, review and release

### After each phase
Hold a joint session to swap stubs for real code and run an end-to-end script.

### End-to-end acceptance test
1. Work in ChatGPT web until the usage-limit warning appears.
2. The extension shows the "save handover now" prompt.
3. The handover is captured, validated, scanned, reviewed by the user, signed, and saved to the vault.
4. Open the vault in Claude Desktop through MCP. It loads the handover and files.
5. Continue the work there and produce **handover v2**.
6. Tamper with **v1** and check that `verify` fails.
7. Show the access log, which should record each step above.

### Cross-review
| Reviewer | Reviews |
|---|---|
| A | C's policy enforcement |
| B | A's crypto and chain code |
| C | B's extension permissions and importers |

Run `/security-review` on every security-critical PR.

### Release deliverables
- [ ] Spec conformance suite
- [ ] Docs and quickstart
- [ ] Extension install guide
- [ ] Plugin-writing guide

---

## 8. Risks to track

| Risk | Mitigation |
|---|---|
| **Extension breakage** | Adapters need ongoing maintenance. Keep selectors versioned and add a visible "adapter broken" state. |
| **Terms of service** | Confirm that capturing your own chats and files from each web UI is acceptable before publishing the extension. |
| **Summary quality** | The prompt eval set catches hallucinated or missing decisions. Always keep the user review step before saving. |
| **Handover-only mode loses transcript-level proof** | Show this in the UI so users aren't misled. |
