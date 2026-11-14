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
  let settings = { checkpointEvery: TV.constants.DEFAULT_CHECKPOINT_EVERY, checkpointMode: "remind", fullMode: false,
    captureFiles: true, attachMode: "ask" };
  let awaiting = null; // { baselineTurns, baselineText, startedAt }
  let lastBucket = 0;
  let limitShown = false;

  // Options come from the background worker: content scripts cannot read storage.local (it also
  // holds the vault token), see background.js setAccessLevel.
  function loadSettings() {
    return ext.runtime.sendMessage({ type: "get_content_settings" }).then((s) => {
      if (!s) return;
      if (Number.isInteger(s.checkpointEvery) && s.checkpointEvery > 0) settings.checkpointEvery = s.checkpointEvery;
      if (["off", "remind", "fill"].includes(s.checkpointMode)) settings.checkpointMode = s.checkpointMode;
      settings.fullMode = s.fullMode === true;
      settings.captureFiles = s.captureFiles !== false;
      if (["ask", "auto", "off"].includes(s.attachMode)) settings.attachMode = s.attachMode;
    });
  }
  // Start counting from the replies already on the page, so opening an old chat (or changing the
  // interval) does not trigger a reminder at once: the next one comes after N MORE replies.
  let checkpointsReady = false; // chat pages fill in after load: wait for them before counting
  const syncCheckpoints = () => {
    lastBucket = Math.floor(adapter.assistantTurns(document) / settings.checkpointEvery);
    checkpointsReady = true;
  };
  loadSettings().then(() => setTimeout(syncCheckpoints, 4000));

  // ---- pictures and files shown in the chat ----------------------------------------------------
  // The ONLY network use in a content script. It runs on the person's own, already-open chat and
  // fetches nothing the guard below does not allow: this site's own https/blob URLs, a size cap,
  // no redirects, and the bytes must be a type the vault can clean (checked by magic bytes).
  // Nothing leaves the page here: the result goes to the background, then to the review screen.
  async function fetchAttachment(url, budget) {
    if (!TV.files.urlAllowed(url, location.origin)) return null;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 15000);
    try {
      const res = await fetch(url, { credentials: "same-origin", redirect: "error", cache: "no-store", signal: ctl.signal });
      if (!res.ok) return null;
      const declared = Number(res.headers.get("content-length"));
      if (Number.isFinite(declared) && declared > Math.min(TV.files.LIMITS.MAX_FILE_BYTES, budget.left)) return null;
      const bytes = new Uint8Array(await res.arrayBuffer());
      if (bytes.length === 0 || bytes.length > TV.files.LIMITS.MAX_FILE_BYTES || bytes.length > budget.left) return null;
      budget.left -= bytes.length;
      return bytes;
    } catch (_) {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  async function collectFiles() {
    const budget = { left: TV.files.LIMITS.MAX_TOTAL_BYTES };
    const files = [];
    for (const c of adapter.attachments(document)) {
      if (files.length >= TV.files.LIMITS.MAX_FILES) break;
      if (c.kind === "link" && !TV.files.looksCapturable(c.name)) continue;
      const bytes = await fetchAttachment(c.url, budget);
      if (!bytes) continue;
      const type = TV.files.sniff(bytes, c.name || "image.png");
      if (!type) { budget.left += bytes.length; continue; }
      files.push({ name: TV.files.cleanName(c.name || "image", type), data_base64: TV.files.toBase64(bytes) });
    }
    return files;
  }

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
    const dark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    const c = dark ? { bg: "#1b1920", ink: "#ebe8f0", line: "#2c2933", title: "#c3a2e8" }
      : { bg: "#ffffff", ink: "#1d1a22", line: "#e7e4ec", title: "#6A31A6" };
    const box = h("div", "position:fixed;z-index:2147483647;right:16px;bottom:16px;max-width:340px;" +
      "background:" + c.bg + ";color:" + c.ink + ";border:1px solid " + c.line + ";" +
      "font:14px/1.5 system-ui,sans-serif;padding:14px 16px;border-radius:10px;" +
      "box-shadow:0 6px 24px rgba(0,0,0,.12)");
    box.append(h("div", "font-weight:600;margin-bottom:6px;color:" + c.title, "When nothing else is left"),
      h("div", "margin-bottom:12px", message));
    const row = h("div", "display:flex;gap:8px;justify-content:flex-end");
    for (const b of buttons.concat([{ label: "Dismiss" }])) {
      const btn = h("button", "cursor:pointer;border-radius:7px;padding:5px 12px;font:inherit;" +
        "font-weight:500;border:1px solid " + (b.primary ? "#6A31A6" : c.line) + ";background:" +
        (b.primary ? "#6A31A6" : "transparent") + ";color:" + (b.primary ? "#fff" : c.ink), b.label);
      btn.addEventListener("click", () => { host.remove(); host = null; if (b.run) b.run(); });
      row.append(btn);
    }
    box.append(row);
    shadow.append(box);
    document.documentElement.append(host);
  }

  // ---- files the person attaches to the chat ---------------------------------------------------
  // The person picks a file for the AI; at that moment we hold the real file, so no download link
  // is needed. Only genuine user actions count (`isTrusted`: page scripts cannot fake them). Reading
  // a File is local; the bytes go to the background worker, which re-checks and saves them to the
  // local vault (cleaned there). Nothing is saved without "ask" consent or the "auto" setting.
  const offered = new Set(); // so one pick (change + drop for the same file) is offered once
  const trusted = (fn) => (e) => { if (e.isTrusted) fn(e); };

  async function saveAttachment(file, ack) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (!TV.files.sniff(bytes, file.name)) {
      notify("This extension keeps pictures, PDFs, Word, PowerPoint, Excel and text files. \"" + file.name +
        "\" is another type, so no copy was saved. (The AI still received it.)", []);
      return;
    }
    const res = await ext.runtime.sendMessage({ type: "attach_file", site: adapter.site,
      adapterVersion: adapter.version, title: adapter.pageTitle(document), mode: settings.fullMode ? "full" : "handover",
      name: file.name, data_base64: TV.files.toBase64(bytes), ack: !!ack }).catch(() => null);
    if (!res) { notify("Could not reach the extension background.", []); return; }
    if (res.status === "accepted") notify("Saved a copy of \"" + file.name + "\" to your vault.", []);
    else if (res.status === "needs_confirmation") {
      const plain = { file_metadata: "hidden file details (such as author or location)",
        hidden_content: "hidden content", api_key: "a key", secret: "a secret", email: "an email address",
        phone: "a phone number", person: "a name", prompt_injection: "text that looks like instructions to an AI" };
      const what = Array.from(new Set((res.findings || []).map((f) => plain[f.kind] || f.kind))).join(", ");
      notify("\"" + file.name + "\" may still contain " + what + " that could not be removed. " +
        "Save a copy anyway? It stays on your computer and is never sent to another AI.",
        [{ label: "Save anyway", primary: true, run: () => saveAttachment(file, true) }]);
    } else {
      notify("No copy of \"" + file.name + "\" was saved: " + (res.error || "the vault did not accept it") +
        ". You can attach it by hand on your vault page.", []);
    }
  }

  function onUserFiles(list) {
    if (settings.attachMode === "off") return;
    for (const file of Array.from(list).slice(0, 5)) { // copied now: the page may clear the list
      const key = file.name + ":" + file.size + ":" + file.lastModified;
      if (offered.has(key)) continue;
      offered.add(key);
      if (file.size > TV.files.LIMITS.MAX_ATTACH_BYTES) {
        notify("\"" + file.name + "\" is too large for your vault (25 MB). Attach it by hand on your vault page.", []);
      } else if (settings.attachMode === "auto") {
        saveAttachment(file, false).catch(() => {});
      } else {
        notify("You attached \"" + file.name + "\" to this chat. Save a copy to your vault too?",
          [{ label: "Save a copy", primary: true, run: () => saveAttachment(file, false).catch(() => {}) }]);
      }
    }
  }

  document.addEventListener("change", trusted((e) => {
    const t = e.target;
    if (t && t.tagName === "INPUT" && t.type === "file" && t.files && t.files.length) onUserFiles(t.files);
  }), true);
  document.addEventListener("drop", trusted((e) => {
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) onUserFiles(e.dataTransfer.files);
  }), true);
  document.addEventListener("paste", trusted((e) => {
    if (e.clipboardData && e.clipboardData.files && e.clipboardData.files.length) onUserFiles(e.clipboardData.files);
  }), true);

  // ---- "Continue here": put a saved thread into this chat ---------------------------------------
  // The text goes into the chat box (never sent: the person presses send) and the files into the
  // page's own file picker, as if the person had chosen them. Both came from the local vault,
  // already cleaned for this destination. These events are synthetic (isTrusted is false), so the
  // attach listeners above ignore them: nothing is saved back.
  function fillContinue(msg) {
    const text = typeof msg.text === "string" ? msg.text.slice(0, 400000) : "";
    if (!text) return { ok: false, error: "nothing to fill in" };
    const filled = adapter.fillInput(document, text);
    if (filled === "busy") return { ok: false, error: "The chat box already has text. Send or clear it first." };
    if (filled !== "ok") return { ok: false, error: "could not find the chat box" };
    const limits = { maxFile: TV.files.LIMITS.MAX_ATTACH_BYTES, maxTotal: TV.files.LIMITS.MAX_ATTACH_BYTES };
    const files = TV.files.validateCaptured(msg.files, limits);
    let attached = 0;
    let note = "";
    if (files.length) {
      const input = document.querySelector("input[type='file']");
      if (!input) {
        note = "I could not find the page's file picker: attach the files yourself from your vault page.";
      } else {
        try {
          const dt = new DataTransfer();
          for (const f of files) {
            dt.items.add(new File([TV.files.fromBase64(f.data_base64)], f.name, { type: f.media_type }));
          }
          input.files = dt.files;
          input.dispatchEvent(new Event("change", { bubbles: true }));
          attached = files.length;
        } catch (_) {
          note = "The page did not accept the files: attach them yourself from your vault page.";
        }
      }
    }
    return { ok: true, attached, offered: files.length, note };
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

  async function checkReply() {
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
    if (settings.captureFiles) message.files = await collectFiles();
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
    if (settings.checkpointMode === "off" || awaiting || !checkpointsReady) return;
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
    else if (msg.type === "fill_continue") respond(fillContinue(msg));
    else if (msg.type === "reload_settings") {
      // The popup changed the checkpoint choice: apply it now, without reloading the chat.
      loadSettings().then(() => { syncCheckpoints(); respond({ ok: true }); }, () => respond({ ok: false }));
      return true;
    } else return false;
    return false;
  });
})();
