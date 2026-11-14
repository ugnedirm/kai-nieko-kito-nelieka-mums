// Background worker. The only code that holds the vault token or talks to the vault.
if (typeof importScripts === "function") {
  importScripts("lib/constants.js", "lib/util.js", "lib/handover.js", "lib/ingest.js");
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

  async function onCaptured(m) {
    if (m.site !== "chatgpt" && m.site !== "claude") return;
    const check = TV.handover.parseReply(JSON.stringify(m.content)); // never trust the sender's shape
    if (!check.ok) return;
    const id = U.randomId("pend");
    await pendingSet(id, {
      site: m.site, adapterVersion: U.clip(String(m.adapterVersion), 32), title: U.clip(String(m.title), 200),
      content: check.content, warnings: (m.warnings || []).slice(0, 20).map((w) => U.clip(String(w), 200)),
      messages: Array.isArray(m.messages) ? m.messages.slice(0, TV.constants.MAX_MESSAGES).map((x) => ({
        role: ["user", "assistant"].includes(x.role) ? x.role : "user", text: U.clip(U.cleanText(x.text), TV.constants.MAX_MESSAGE_CHARS) })) : null,
      artifacts: Array.isArray(m.artifacts) ? m.artifacts.slice(0, 50).map((x) => ({ name: U.clip(String(x.name), 255), text: U.clip(U.cleanText(x.text), 1000000) })) : null,
      // Fixed at capture time: the vault hashes the whole request body, so a retry must be
      // byte-identical to the first attempt (SPEC 8.8).
      capturedAt: U.nowIso(),
      reqIds: { handover: U.randomId("req"), messages: U.randomId("req"), artifacts: U.randomId("req") },
      done: {}, keys: {}, acked: {},
    });
    await ext.tabs.create({ url: ext.runtime.getURL("pages/review.html?id=" + encodeURIComponent(id)) });
  }

  async function digest(text) {
    const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(d), (x) => x.toString(16).padStart(2, "0")).join("");
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
    const baseChoice = m.threadId && /^[A-Za-z0-9_-]{8,64}$/.test(m.threadId)
      ? { threadId: m.threadId } : { title: U.clip(String(m.title || p.title), 200), mode: wantMessages ? "full" : "handover" };
    const I = TV.ingest;
    const o = (rid) => ({ userReviewed: true, requestId: rid, capturedAt: p.capturedAt });

    const steps = [["handover", (c) => I.handoverRequest(p.site, p.adapterVersion, c, checked.content, o(p.reqIds.handover))]];
    if (wantMessages) steps.push(["messages", (c) => I.messagesRequest(p.site, p.adapterVersion, c,
      p.messages.map((x) => ({ role: x.role, text: x.text })), o(p.reqIds.messages))]);
    if (wantFiles) p.artifacts.forEach((f, i) => steps.push(["artifact" + i, (c) => I.fileRequest(
      p.site, p.adapterVersion, c, f, o(p.reqIds.artifacts + "_" + i))])); // stable id per file

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

  ext.runtime.onMessage.addListener((msg, sender, respond) => {
    if (!msg || typeof msg.type !== "string") return false;
    let task = null;
    if (msg.type === "captured" && fromChatTab(sender)) task = onCaptured(msg).then(() => ({}));
    else if (msg.type === "get_content_settings" && fromChatTab(sender)) {
      // Options only. The token never goes to a content script.
      task = ext.storage.local.get(["checkpointEvery", "checkpointMode", "fullMode"]);
    }
    else if (fromExtensionPage(sender)) {
      if (msg.type === "get_pending") task = pendingGet(String(msg.id)).then((p) => p || null);
      else if (msg.type === "submit") task = onSubmit(msg);
      else if (msg.type === "list_threads") task = settings().then((s) => TV.ingest.listThreads(fetch, s.port, s.token));
    }
    if (!task) return false; // unknown sender or type: ignored, no reply
    task.then(respond, () => respond({ status: "error", error: "internal error" })); // never leak details
    return true;
  });
})();
