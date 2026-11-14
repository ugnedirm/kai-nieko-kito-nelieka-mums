// Runs the real background.js against a fake browser, to test flows that span several messages.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const PNG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);

function boot({ sessionStorage = true } = {}) {
  const local = { token: "t".repeat(40), port: 8765 };
  const session = {};
  const calls = [];
  const toTab = [];
  const tabUrls = {};
  let continueReply = { ok: true, status: 200, json: async () => ({ text: "<security_notes>x</security_notes>", hidden: { email: 1 },
    files: [{ name: "a.png", media_type: "image/png", size: 12, data_base64: "AAAA" }], skipped: ["x.bin (may carry hidden data)"] }) };
  let listener = null;
  let threads = 0;
  const area = (obj) => ({
    get: async (k) => (k == null ? { ...obj } : typeof k === "string" ? { [k]: obj[k] }
      : Object.fromEntries(k.map((x) => [x, obj[x]]))),
    set: async (o) => Object.assign(obj, o),
    remove: async (k) => { delete obj[k]; },
    setAccessLevel: async () => {},
  });
  globalThis.chrome = {
    runtime: { id: "ext", onMessage: { addListener: (fn) => { listener = fn; } }, onInstalled: { addListener() {} },
      getURL: (p) => "chrome-extension://ext/" + p },
    storage: { local: area(local), session: sessionStorage ? area(session) : undefined },
    tabs: { create: async () => {},
      get: async (id) => ({ id, url: tabUrls[id] || "https://claude.ai/chat/abc" }),
      sendMessage: async (id, msg) => { toTab.push({ id, msg }); return { ok: true, attached: msg.files.length, offered: msg.files.length, note: "" }; } },
  };
  const TV = (globalThis.TV = {});
  const lib = path.join(__dirname, "..", "src", "lib");
  for (const n of ["constants", "util", "files", "handover", "ingest"]) TV[n] = require(path.join(lib, n + ".js"));
  globalThis.fetch = async (url, init) => {
    const body = init && init.body ? JSON.parse(init.body) : null;
    calls.push({ url, body });
    if (String(url).endsWith("/v1/ingest")) {
      const target = body.target;
      const id = target.thread_id || "thr_new" + ++threads + "xxxxxx";
      return { status: 200, ok: true, json: async () => ({ status: "accepted", thread_id: id, findings: [] }) };
    }
    if (String(url).endsWith("/v1/continue")) return continueReply;
    if (String(url).endsWith("/v1/threads")) {
      return { ok: true, status: 200, json: async () => Array.from({ length: threads }, (_, i) => ({ thread_id: "thr_new" + (i + 1) + "xxxxxx", title: "t" })) };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
  delete require.cache[require.resolve("../src/background.js")];
  require("../src/background.js");
  const send = (msg, sender) => new Promise((resolve) => {
    const kept = listener(msg, sender, resolve);
    if (!kept) resolve(undefined);
  });
  return { send, calls, toTab, tabUrls, setContinue: (r) => { continueReply = r; } };
}

const chatTab = (id) => ({ id: "ext", url: "https://claude.ai/new", tab: { id, url: "https://claude.ai/new" } });
const ownPage = { id: "ext", url: "chrome-extension://ext/pages/review.html" };
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const CONTENT = { decisions: [], open_questions: [], next_steps: [], files: [],
  key_facts: [{ text: "a fact", source_note: "chat" }], constraints: [], uncertain: [] };

test("a file attached first and the summary captured later share one thread", async () => {
  const { send, calls } = boot();
  const sender = chatTab(7);
  const first = await send({ type: "attach_file", site: "claude", adapterVersion: "1", title: "New chat - Claude",
    mode: "full", name: "pic.png", data_base64: b64(PNG) }, sender);
  assert.equal(first.status, "accepted");
  assert.ok(calls[0].body.target.new_thread, "first file creates the thread");
  const second = await send({ type: "attach_file", site: "claude", adapterVersion: "1", title: "New chat - Claude",
    mode: "full", name: "pic2.png", data_base64: b64(PNG) }, sender);
  assert.equal(calls[1].body.target.thread_id, first.thread_id, "second file reuses it");
  assert.equal(second.thread_id, first.thread_id);

  await send({ type: "captured", site: "claude", adapterVersion: "1", title: "Very cute? - Claude",
    content: CONTENT, warnings: [] }, sender);
  // find the pending capture id through the tabs.create URL is not available here, so list via storage
  const pendingId = Object.keys(await globalThis.chrome.storage.session.get(null)).find((k) => k.startsWith("pend_"));
  assert.ok(pendingId, "a pending capture exists");
  const pending = await send({ type: "get_pending", id: pendingId }, ownPage);
  assert.equal(pending.suggestedThreadId, first.thread_id, "review is told which thread to use");
});

test("a different tab does not borrow another chat's thread", async () => {
  const { send } = boot();
  const a = await send({ type: "attach_file", site: "claude", adapterVersion: "1", title: "A", mode: "full",
    name: "a.png", data_base64: b64(PNG) }, chatTab(1));
  const b = await send({ type: "attach_file", site: "claude", adapterVersion: "1", title: "B", mode: "full",
    name: "b.png", data_base64: b64(PNG) }, chatTab(2));
  assert.notEqual(a.thread_id, b.thread_id);
});

test("attach refuses unknown sites, bad types and senders that are not chat tabs", async () => {
  const { send } = boot();
  assert.equal((await send({ type: "attach_file", site: "evil", name: "a.png", data_base64: b64(PNG) }, chatTab(1))).status, "error");
  assert.equal((await send({ type: "attach_file", site: "claude", name: "a.exe", data_base64: b64([0x4d, 0x5a, 1]) }, chatTab(1))).status, "error");
  const stranger = { id: "other-ext", url: "https://claude.ai/", tab: { id: 1, url: "https://claude.ai/" } };
  assert.equal(await send({ type: "attach_file", site: "claude", name: "a.png", data_base64: b64(PNG) }, stranger), undefined);
});

test("when the tab cannot be matched, the review still suggests the thread of a recent attachment", async () => {
  const { send } = boot();
  const attached = await send({ type: "attach_file", site: "claude", adapterVersion: "1", title: "New chat",
    mode: "full", name: "a.png", data_base64: b64(PNG) }, chatTab(1));
  // the summary is captured in a different tab (or after a reload that forgot the tab)
  await send({ type: "captured", site: "claude", adapterVersion: "1", title: "Very cute?", content: CONTENT,
    warnings: [] }, chatTab(99));
  const id = Object.keys(await globalThis.chrome.storage.session.get(null)).find((k) => k.startsWith("pend_"));
  const pending = await send({ type: "get_pending", id }, ownPage);
  assert.equal(pending.suggestedThreadId, attached.thread_id);
  // ...but not from another site, and not when nothing was attached
  const fresh = boot();
  await fresh.send({ type: "captured", site: "chatgpt", adapterVersion: "1", title: "x", content: CONTENT,
    warnings: [] }, chatTab(5));
  const id2 = Object.keys(await globalThis.chrome.storage.session.get(null)).find((k) => k.startsWith("pend_"));
  assert.equal((await fresh.send({ type: "get_pending", id: id2 }, ownPage)).suggestedThreadId, null);
});

test("continue_start asks the vault for this site's destination and hands the result to the tab", async () => {
  const { send, calls, toTab } = boot();
  const r = await send({ type: "continue_start", threadId: "thr_abcdefgh12", tabId: 3 }, ownPage);
  assert.equal(r.ok, true);
  assert.equal(r.attached, 1);
  assert.deepEqual(r.hidden, { email: 1 });
  assert.match(r.skipped[0], /hidden data/);
  const asked = calls.find((c) => String(c.url).endsWith("/v1/continue"));
  assert.deepEqual(asked.body, { thread_id: "thr_abcdefgh12", destination: "claude" });
  assert.equal(toTab[0].id, 3);
  assert.equal(toTab[0].msg.type, "fill_continue");
  assert.ok(toTab[0].msg.text.startsWith("<security_notes>"));
});

test("continue_start picks the destination from the page, not from the caller", async () => {
  const { send, calls, tabUrls } = boot();
  tabUrls[4] = "https://chatgpt.com/c/xyz";
  await send({ type: "continue_start", threadId: "thr_abcdefgh12", tabId: 4, destination: "evil" }, ownPage);
  assert.equal(calls.find((c) => String(c.url).endsWith("/v1/continue")).body.destination, "chatgpt");
});

test("continue_start refuses other sites, bad ids, chat-page senders and vault refusals", async () => {
  const b = boot();
  b.tabUrls[5] = "https://evil.example/";
  assert.equal((await b.send({ type: "continue_start", threadId: "thr_abcdefgh12", tabId: 5 }, ownPage)).ok, false);
  assert.equal((await b.send({ type: "continue_start", threadId: "../etc", tabId: 3 }, ownPage)).ok, false);
  assert.equal(b.toTab.length, 0);
  // a hostile chat page cannot trigger it: only the extension's own pages may
  assert.equal(await b.send({ type: "continue_start", threadId: "thr_abcdefgh12", tabId: 3 }, chatTab(3)), undefined);
  b.setContinue({ ok: false, status: 409, json: async () => ({ error: "Blocked: this thread contains what looks like a secret (api_key)." }) });
  const r = await b.send({ type: "continue_start", threadId: "thr_abcdefgh12", tabId: 3 }, ownPage);
  assert.equal(r.ok, false);
  assert.match(r.error, /Blocked/);
  assert.equal(b.toTab.length, 0, "nothing is put in the chat when the vault refuses");
});
