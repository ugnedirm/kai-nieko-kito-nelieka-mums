// Content script (isolated world). Runs only on the chat domains listed in manifest.json.
// The page is hostile: read text only, never eval, never insert page text as HTML, and send
// nothing anywhere except to this extension's background worker.
(function () {
  const TV = globalThis.TV;
  const ext = globalThis.browser || globalThis.chrome;
  const adapter = TV.adapterIndex.adapterFor(location.hostname);
  if (!adapter || window.top !== window) return;

  const DEBOUNCE_MS = 1000;
  const AWAIT_TIMEOUT_MS = 10 * 60 * 1000;
  let settings = { checkpointEvery: TV.constants.DEFAULT_CHECKPOINT_EVERY, checkpointMode: "remind", fullMode: false };
  let awaiting = null; // { baselineTurns, baselineText, startedAt }
  let lastBucket = 0;
  let limitShown = false;

  // Options come from the background worker: content scripts cannot read storage.local (it also
  // holds the vault token), see background.js setAccessLevel.
  ext.runtime.sendMessage({ type: "get_content_settings" }).then((s) => {
    if (!s) return;
    if (Number.isInteger(s.checkpointEvery) && s.checkpointEvery > 0) settings.checkpointEvery = s.checkpointEvery;
    if (["off", "remind", "fill"].includes(s.checkpointMode)) settings.checkpointMode = s.checkpointMode;
    settings.fullMode = s.fullMode === true;
  });

  // ---- in-page notice (closed shadow root; CSSOM styles only; text via textContent) ----------
  let host = null;
  function h(tag, css, text) {
    const el = document.createElement(tag);
    el.style.cssText = css;
    if (text) el.textContent = text;
    return el;
  }
  function notify(message, buttons) {
    if (host) host.remove();
    host = document.createElement("div");
    const shadow = host.attachShadow({ mode: "closed" });
    const box = h("div", "position:fixed;z-index:2147483647;right:16px;bottom:16px;max-width:340px;" +
      "background:#1f2937;color:#fff;font:14px system-ui,sans-serif;padding:12px 14px;border-radius:8px;" +
      "box-shadow:0 4px 16px rgba(0,0,0,.4)");
    box.append(h("div", "font-weight:600;margin-bottom:6px", "threadvault"), h("div", "margin-bottom:10px", message));
    const row = h("div", "display:flex;gap:8px;justify-content:flex-end");
    for (const b of buttons.concat([{ label: "Dismiss" }])) {
      const btn = h("button", "cursor:pointer;border:0;border-radius:6px;padding:5px 10px;" +
        "background:" + (b.primary ? "#2563eb" : "#4b5563") + ";color:#fff", b.label);
      btn.addEventListener("click", () => { host.remove(); host = null; if (b.run) b.run(); });
      row.append(btn);
    }
    box.append(row);
    shadow.append(box);
    document.documentElement.append(host);
  }

  // ---- handover flow -------------------------------------------------------------------------
  function startHandover() {
    const t = adapter.selfTest(document);
    if (!t.ok) {
      notify("This page no longer matches what the extension expects (" + adapter.site + " adapter v" +
        adapter.version + "). Nothing was captured. Please update the extension.", []);
      return { ok: false, error: "adapter self-test failed" };
    }
    const filled = adapter.fillInput(document, TV.prompt.text);
    if (filled === "busy") {
      notify("The chat box already has text. Send or clear it first, then try again.", []);
      return { ok: false, error: "chat box not empty" };
    }
    if (filled !== "ok") return { ok: false, error: "could not fill the chat box" };
    awaiting = { baselineTurns: adapter.assistantTurns(document),
      baselineText: adapter.lastAssistantText(document), startedAt: Date.now() };
    notify("The handover request is in the chat box. Press send, then wait for the reply: I will " +
      "show it to you for review before anything is saved.", []);
    return { ok: true };
  }

  function checkReply() {
    if (!awaiting) return;
    if (Date.now() - awaiting.startedAt > AWAIT_TIMEOUT_MS) { awaiting = null; return; }
    if (adapter.isGenerating(document)) return;
    const turns = adapter.assistantTurns(document);
    const text = adapter.lastAssistantText(document);
    if (turns <= awaiting.baselineTurns && text === awaiting.baselineText) return;
    const parsed = TV.handover.parseReply(text);
    if (!parsed.ok) {
      awaiting.baselineTurns = turns;
      awaiting.baselineText = text;
      notify("The reply could not be used: " + parsed.problems.slice(0, 3).join("; ") +
        ". Ask the AI to fix it and reply again; I am still watching.", []);
      return;
    }
    awaiting = null;
    const message = { type: "captured", site: adapter.site, adapterVersion: adapter.version,
      title: adapter.pageTitle(document), content: parsed.content, warnings: parsed.warnings };
    if (settings.fullMode) {
      message.messages = adapter.conversation(document);
      message.artifacts = adapter.artifacts(document);
    }
    ext.runtime.sendMessage(message).catch(() => notify("Could not reach the extension background.", []));
  }

  // ---- limit warning and rolling checkpoint --------------------------------------------------
  function checkLimits() {
    if (!limitShown && TV.limits.detectLimitWarning(adapter.noticeTexts(document))) {
      limitShown = true;
      notify("This chat may be close to its limit. Save a handover now so another AI can continue?",
        [{ label: "Save handover now", primary: true, run: startHandover }]);
      return;
    }
    if (settings.checkpointMode === "off" || awaiting) return;
    const bucket = TV.limits.checkpointDue(adapter.assistantTurns(document), settings.checkpointEvery, lastBucket);
    if (bucket === null) return;
    lastBucket = bucket;
    if (settings.checkpointMode === "fill") startHandover();
    else notify("Checkpoint: " + bucket * settings.checkpointEvery + " replies so far. Save a handover?",
      [{ label: "Save handover", primary: true, run: startHandover }]);
  }

  let timer = null;
  new MutationObserver(() => {
    clearTimeout(timer);
    timer = setTimeout(() => { checkReply(); checkLimits(); }, DEBOUNCE_MS);
  }).observe(document.body, { childList: true, subtree: true, characterData: true });

  // ---- commands from the popup (extension pages only) ----------------------------------------
  ext.runtime.onMessage.addListener((msg, sender, respond) => {
    if (sender.id !== ext.runtime.id || !msg) return false;
    if (msg.type === "start_handover") respond(startHandover());
    else if (msg.type === "selftest") respond(adapter.selfTest(document));
    else return false;
    return false;
  });
})();
