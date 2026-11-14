// Background worker. The only code that holds the vault token or talks to the vault.
if (typeof importScripts === "function") {
  importScripts("lib/constants.js", "lib/util.js", "lib/files.js", "lib/handover.js", "lib/ingest.js");
}
(function () {
  const TV = globalThis.TV;
  const ext = globalThis.browser || globalThis.chrome;
  const U = TV.util;
  // The token lives in storage.local. Where supported, hide that area from content scripts, which
  // run next to hostile pages. (Firefox has no such switch; there the content script simply never
  // asks for the token.)
  if (ext.storage.local.setAccessLevel) {
    ext.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => {});
  }
  const memory = new Map();
  const store = ext.storage.session || null; // survives worker restarts where available

  const pendingGet = async (id) => store ? (await store.get(id))[id] : memory.get(id);
  const pendingSet = (id, v) => store ? store.set({ [id]: v }) : memory.set(id, v);
  const pendingDel = (id) => store ? store.remove(id) : memory.delete(id);

  const fromExtensionPage = (s) => s.id === ext.runtime.id && typeof s.url === "string" &&
    s.url.startsWith(ext.runtime.getURL(""));
  const fromChatTab = (s) => s.id === ext.runtime.id && !!s.tab && U.hostAllowed(s.url || (s.tab && s.tab.url));

  async function settings() {
    const s = await ext.storage.local.get(["token", "port"]);
    return { token: typeof s.token === "string" ? s.token : "", port: Number.isInteger(s.port) ? s.port : TV.constants.DEFAULT_PORT };
  }

  async function onCaptured(m, sender) {
    if (m.site !== "chatgpt" && m.site !== "claude") return;
    const check = TV.handover.parseReply(JSON.stringify(m.content)); // never trust the sender's shape
    if (!check.ok) return;
    const id = U.randomId("pend");
    await pendingSet(id, {
      tabId: sender && sender.tab ? sender.tab.id : null,
      site: m.site, adapterVersion: U.clip(String(m.adapterVersion), 32), title: U.clip(String(m.title), 200),
      content: check.content, warnings: (m.warnings || []).slice(0, 20).map((w) => U.clip(String(w), 200)),
      messages: Array.isArray(m.messages) ? m.messages.slice(0, TV.constants.MAX_MESSAGES).map((x) => ({
        role: ["user", "assistant"].includes(x.role) ? x.role : "user", text: U.clip(U.cleanText(x.text), TV.constants.MAX_MESSAGE_CHARS) })) : null,
      files: TV.files.validateCaptured(m.files), // re-checked here: the content script is not trusted
      artifacts: Array.isArray(m.artifacts) ? m.artifacts.slice(0, 50).map((x) => ({ name: U.clip(String(x.name), 255), text: U.clip(U.cleanText(x.text), 1000000) })) : null,
      // Fixed at capture time: the vault hashes the whole request body, so a retry must be
      // byte-identical to the first attempt (SPEC 8.8).
      capturedAt: U.nowIso(),
      reqIds: { handover: U.randomId("req"), messages: U.randomId("req"), artifacts: U.randomId("req"), files: U.randomId("req") },
      done: {}, keys: {}, acked: {},
    });
    await ext.tabs.create({ url: ext.runtime.getURL("pages/review.html?id=" + encodeURIComponent(id)) });
  }

  async function digest(text) {
    const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(d), (x) => x.toString(16).padStart(2, "0")).join("");
  }

  // A file the person attached to the chat, saved to this tab's thread (created on first use) so the
  // handover captured later lands in the same thread.
  async function onAttach(m, sender) {
    if (m.site !== "chatgpt" && m.site !== "claude") return { status: "error", error: "unknown site" };
    const tabId = sender.tab ? sender.tab.id : null;
    const files = TV.files.validateCaptured([{ name: m.name, data_base64: m.data_base64 }],
      { maxFile: TV.files.LIMITS.MAX_ATTACH_BYTES, maxTotal: TV.files.LIMITS.MAX_ATTACH_BYTES });
    if (!files.length) return { status: "error", error: "this kind of file is not kept" };
    const { token, port } = await settings();
    const key = "tabThread:" + tabId;
    const known = store ? (await store.get(key))[key] : memory.get(key);
    const choice = known ? { threadId: known }
      : { title: U.clip(String(m.title || "Chat files"), 200), mode: m.mode === "full" ? "full" : "handover" };
    const req = TV.ingest.binaryFileRequest(m.site, U.clip(String(m.adapterVersion), 32), choice, files[0],
      { requestId: U.randomId("req"), userReviewed: false, capturedAt: U.nowIso(), acknowledged: m.ack === true });
    const res = await TV.ingest.post(fetch, port, token, req);
    if (res.status === "accepted" && res.thread_id) {
      if (!known) await (store ? store.set({ [key]: res.thread_id }) : memory.set(key, res.thread_id));
      // Fallback for the review screen when the tab cannot be matched (reload, another tab).
      const last = { site: m.site, threadId: res.thread_id, at: Date.now() };
      await (store ? store.set({ lastAttach: last }) : memory.set("lastAttach", last));
    }
    return res;
  }

  // Review screen result -> vault. Handover first, then (optionally) the conversation and files.
  // Acknowledgement is per step: it applies only to the step whose findings the user was shown,
  // and is dropped if that step's content changes afterwards.
  async function onSubmit(m) {
    const p = await pendingGet(m.id);
    if (!p) return { status: "error", error: "this capture expired; capture again" };
    const { token, port } = await settings();
    const checked = TV.handover.parseReply(JSON.stringify(m.content)); // re-validate the user's edits
    if (!checked.ok) return { status: "error", error: "edited handover is invalid: " + checked.problems.slice(0, 3).join("; ") };
    const wantMessages = !!(m.saveMessages && p.messages && p.messages.length);
    const wantFiles = !!(m.saveArtifacts && p.artifacts && p.artifacts.length);
    const chosen = Array.isArray(m.fileIndexes) ? m.fileIndexes.filter((i) => Number.isInteger(i) && p.files && p.files[i]) : [];
    const baseChoice = m.threadId && /^[A-Za-z0-9_-]{8,64}$/.test(m.threadId)
      ? { threadId: m.threadId } : { title: U.clip(String(m.title || p.title), 200), mode: wantMessages ? "full" : "handover" };
    const I = TV.ingest;
    const o = (rid) => ({ userReviewed: true, requestId: rid, capturedAt: p.capturedAt });

    const steps = [["handover", (c) => I.handoverRequest(p.site, p.adapterVersion, c, checked.content, o(p.reqIds.handover))]];
    if (wantMessages) steps.push(["messages", (c) => I.messagesRequest(p.site, p.adapterVersion, c,
      p.messages.map((x) => ({ role: x.role, text: x.text })), o(p.reqIds.messages))]);
    if (wantFiles) p.artifacts.forEach((f, i) => steps.push(["artifact" + i, (c) => I.fileRequest(
      p.site, p.adapterVersion, c, f, o(p.reqIds.artifacts + "_" + i))])); // stable id per file

    for (const i of chosen) steps.push(["file" + i, (c) => I.binaryFileRequest(
      p.site, p.adapterVersion, c, p.files[i], o(p.reqIds.files + "_" + i))]);

    let finished = false;
    try {
      for (const [name, build] of steps) {
        if (p.done[name]) continue;
        const req = build(p.threadId ? { threadId: p.threadId } : baseChoice);
        const key = await digest(JSON.stringify(req));
        if (p.keys[name] !== key) { p.keys[name] = key; delete p.acked[name]; } // content changed: re-confirm
        if (m.ackStep === name) p.acked[name] = true;
        const res = await I.post(fetch, port, token, p.acked[name] ? { ...req, acknowledged_findings: true } : req);
        if (res.status !== "accepted") return Object.assign(res, { step: name });
        p.done[name] = true;
        if (res.thread_id) p.threadId = res.thread_id;
      }
      finished = true;
      return { status: "accepted", thread_id: p.threadId };
    } finally {
      await (finished ? pendingDel(m.id) : pendingSet(m.id, p)); // keep progress so a retry resumes
    }
  }

  // First run: show the welcome page so nobody has to guess what to do.
  if (ext.runtime.onInstalled) {
    ext.runtime.onInstalled.addListener((d) => {
      if (d && d.reason === "install") ext.tabs.create({ url: ext.runtime.getURL("pages/welcome.html") });
    });
  }

  // Connection state for the popup and welcome page: is the vault running, and are we paired?
  async function vaultStatus() {
    const { token, port } = await settings();
    const running = await TV.ingest.health(fetch, port);
    const connected = running && await TV.ingest.tokenWorks(fetch, port, token);
    return { running, connected, port };
  }

  // "Connect to my vault": ask the vault, then wait for the person to click Allow on its page.
  async function pairStart() {
    const { port } = await settings();
    const r = await TV.ingest.pairRequest(fetch, port);
    if (!r.ok) return r;
    await (store ? store.set({ pairPoll: r.poll }) : memory.set("pairPoll", r.poll));
    await ext.tabs.create({ url: `http://${TV.constants.API_HOST}:${port}/pair` });
    return { ok: true };
  }

  async function pairCheck() {
    const { port } = await settings();
    const poll = store ? (await store.get("pairPoll")).pairPoll : memory.get("pairPoll");
    if (!poll) return { status: "none" };
    const r = await TV.ingest.pairStatus(fetch, port, poll);
    if (r.status === "approved") {
      await ext.storage.local.set({ token: r.token });
      await (store ? store.remove("pairPoll") : memory.delete("pairPoll"));
      return { status: "approved" };
    }
    if (r.status !== "pending") await (store ? store.remove("pairPoll") : memory.delete("pairPoll"));
    return { status: r.status };
  }

  const SITE_DESTINATION = { "chatgpt.com": "chatgpt", "chat.openai.com": "chatgpt", "claude.ai": "claude" };

  // "Continue here": fetch the prepared text and files from the vault and hand them to the chat tab.
  // The page code only fills the chat box and the file picker; the person presses send.
  async function continueStart(m) {
    const tabId = Number.isInteger(m.tabId) ? m.tabId : null;
    const threadId = typeof m.threadId === "string" && /^[A-Za-z0-9_-]{8,64}$/.test(m.threadId) ? m.threadId : null;
    if (tabId === null || !threadId) return { ok: false, error: "choose a thread first" };
    let host = "";
    try { host = new URL((await ext.tabs.get(tabId)).url || "").hostname; } catch (_) { /* below */ }
    const destination = SITE_DESTINATION[host];
    if (!destination) return { ok: false, error: "open a ChatGPT or Claude chat first" };
    const { token, port } = await settings();
    const got = await TV.ingest.continueRequest(fetch, port, token, threadId, destination);
    if (!got.ok) return got;
    const sent = await ext.tabs.sendMessage(tabId, { type: "fill_continue", text: got.text, files: got.files })
      .catch(() => null);
    if (!sent) return { ok: false, error: "could not reach the chat page: reload it and try again" };
    return { ...sent, hidden: got.hidden, skipped: got.skipped };
  }

  async function openVault() {
    const { token, port } = await settings();
    const url = await TV.ingest.openUrl(fetch, port, token);
    if (!url) return { ok: false };
    await ext.tabs.create({ url });
    return { ok: true };
  }

  ext.runtime.onMessage.addListener((msg, sender, respond) => {
    if (!msg || typeof msg.type !== "string") return false;
    let task = null;
    if (msg.type === "captured" && fromChatTab(sender)) task = onCaptured(msg, sender).then(() => ({}));
    else if (msg.type === "attach_file" && fromChatTab(sender)) task = onAttach(msg, sender);
    else if (msg.type === "get_content_settings" && fromChatTab(sender)) {
      // Options only. The token never goes to a content script.
      task = ext.storage.local.get(["checkpointEvery", "checkpointMode", "fullMode", "captureFiles", "attachMode"]);
    }
    else if (fromExtensionPage(sender)) {
      if (msg.type === "get_pending") {
        // The review page needs only names and sizes of files, not their bytes.
        task = pendingGet(String(msg.id)).then(async (p) => {
          if (!p) return null;
          const key = "tabThread:" + p.tabId;
          let suggested = store ? (await store.get(key))[key] : memory.get(key);
          if (!suggested) { // no match for this tab: the most recent attachment on this site, if fresh
            const last = store ? (await store.get("lastAttach")).lastAttach : memory.get("lastAttach");
            if (last && last.site === p.site && Date.now() - last.at < 2 * 3600 * 1000) suggested = last.threadId;
          }
          return { ...p, suggestedThreadId: suggested || null,
            files: (p.files || []).map((f) => ({ name: f.name, type: f.type, size: f.size })) };
        });
      }
      else if (msg.type === "submit") task = onSubmit(msg);
      else if (msg.type === "vault_status") task = vaultStatus();
      else if (msg.type === "pair_start") task = pairStart();
      else if (msg.type === "pair_check") task = pairCheck();
      else if (msg.type === "open_vault") task = openVault();
      else if (msg.type === "continue_start") task = continueStart(msg);
      else if (msg.type === "list_threads") task = settings().then((s) => TV.ingest.listThreads(fetch, s.port, s.token));
    }
    if (!task) return false; // unknown sender or type: ignored, no reply
    task.then(respond, () => respond({ status: "error", error: "internal error" })); // never leak details
    return true;
  });
})();
