// Build ingest requests and talk to the local vault service (SPEC section 8).
// The extension supplies content only. It never sets ids, hashes, versions or provenance.
(function (root) {
  const TV = (root.TV = root.TV || {});
  const load = (n) => (typeof module !== "undefined" ? require("./" + n + ".js") : TV[n]);
  const C = load("constants");
  const U = load("util");

  function baseRequest(site, adapterVersion, target, payload, opts) {
    const req = {
      spec_version: C.SPEC_VERSION,
      type: "ingest_request",
      request_id: (opts && opts.requestId) || U.randomId("req"),
      captured_at: (opts && opts.capturedAt) || U.nowIso(),
      client: { client_id: C.CLIENT_ID, version: C.VERSION, adapter: { site, version: adapterVersion } },
      user_reviewed: !!(opts && opts.userReviewed),
      target,
      payload,
    };
    if (opts && opts.acknowledged) req.acknowledged_findings = true;
    return req;
  }

  function targetFor(choice) {
    return choice.threadId
      ? { thread_id: choice.threadId }
      : { new_thread: { title: U.clip(choice.title, 200) || "Untitled chat", mode: choice.mode } };
  }

  function handoverRequest(site, adapterVersion, choice, content, opts) {
    const metadata = {
      author: { kind: "ai", client: `${site}-web` },
      created_at: (opts && opts.capturedAt) || U.nowIso(),
      prompt_version: C.PROMPT_VERSION,
      provenance: "ai-summary-user-saved", // the vault overrides this anyway (SPEC 8.3)
      thread_state: { source: "live-chat", user_reviewed: !!(opts && opts.userReviewed) },
    };
    return baseRequest(site, adapterVersion, targetFor(choice),
      { kind: "handover", content, metadata }, opts);
  }

  function messagesRequest(site, adapterVersion, choice, messages, opts) {
    const author = (role) => role === "assistant" ? { kind: "ai", client: `${site}-web` }
      : role === "user" ? { kind: "human" } : { kind: role === "tool" ? "tool" : "system" };
    const payload = {
      kind: "messages",
      messages: messages.slice(0, C.MAX_MESSAGES).map((m) => ({
        role: m.role,
        author: author(m.role),
        created_at: m.created_at || (opts && opts.capturedAt) || U.nowIso(),
        content: U.clip(U.cleanText(m.text), C.MAX_MESSAGE_CHARS),
      })).filter((m) => m.content.trim()),
    };
    return baseRequest(site, adapterVersion, targetFor(choice), payload, opts);
  }

  function toBase64(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(bin);
  }

  function fileRequest(site, adapterVersion, choice, file, opts) {
    const bytes = new TextEncoder().encode(U.cleanText(file.text));
    if (bytes.length > C.MAX_FILE_BYTES) throw new Error("file too large");
    const payload = { kind: "file", file: {
      name: U.clip(file.name, 255) || "artifact.txt",
      media_type: "text/plain", size: bytes.length, data_base64: toBase64(bytes) } };
    return baseRequest(site, adapterVersion, targetFor(choice), payload, opts);
  }

  function endpoint(port, path) {
    if (!U.validPort(port)) throw new Error("invalid port");
    return `http://${C.API_HOST}:${port}${path}`;
  }

  async function post(fetchFn, port, token, request) {
    if (typeof token !== "string" || token.length < 16) return { status: "error", error: "no token set" };
    let res;
    try {
      res = await fetchFn(endpoint(port, "/v1/ingest"), {
        method: "POST", credentials: "omit", redirect: "error", cache: "no-store",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify(request),
      });
    } catch (_) {
      return { status: "error", error: "vault service not reachable" };
    }
    if (res.status === 401) return { status: "error", error: "Your vault no longer recognises this browser. Click the threadvault icon and press Connect to my vault, then press Save again." };
    if (res.status === 403) return { status: "error", error: "This browser is not connected to your vault yet. Click the threadvault icon, press Connect to my vault, allow it, then press Save again." };
    let body;
    try { body = await res.json(); } catch (_) { return { status: "error", error: "unreadable response" }; }
    if (!body || typeof body.status !== "string") return { status: "error", error: "unexpected response" };
    // Only whitelisted, length-capped fields are passed on to the UI.
    return {
      status: body.status,
      thread_id: typeof body.thread_id === "string" ? body.thread_id : undefined,
      error: typeof body.error === "string" ? U.clip(body.error, 200) : undefined,
      findings: Array.isArray(body.findings) ? body.findings.slice(0, 50).map((f) => ({
        kind: U.clip(String(f.kind), 40), severity: U.clip(String(f.severity), 10), path: U.clip(String(f.path), 100),
      })) : [],
    };
  }

  async function listThreads(fetchFn, port, token) {
    try {
      const res = await fetchFn(endpoint(port, "/v1/threads"), {
        credentials: "omit", redirect: "error", cache: "no-store",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) return [];
      const body = await res.json();
      return (Array.isArray(body) ? body : []).slice(0, 200)
        .filter((t) => t && /^[A-Za-z0-9_-]{8,64}$/.test(t.thread_id))
        .map((t) => ({ thread_id: t.thread_id, title: U.clip(String(t.title), 200) }));
    } catch (_) {
      return [];
    }
  }

  // Vault connection helpers for the popup and welcome page (called from the background worker).
  async function health(fetchFn, port) {
    try {
      const res = await fetchFn(endpoint(port, "/v1/health"), { credentials: "omit", redirect: "error", cache: "no-store" });
      return res.ok;
    } catch (_) {
      return false;
    }
  }

  // POST on purpose: a save is a POST, and a POST carries the extension's Origin header, so this
  // proves the vault accepts both the token and this browser (a GET can pass without either).
  async function tokenWorks(fetchFn, port, token) {
    if (typeof token !== "string" || token.length < 16) return false;
    try {
      const res = await fetchFn(endpoint(port, "/v1/ping"), {
        method: "POST", credentials: "omit", redirect: "error", cache: "no-store",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: "{}" });
      return res.ok;
    } catch (_) {
      return false;
    }
  }

  async function pairRequest(fetchFn, port) {
    try {
      const res = await fetchFn(endpoint(port, "/v1/pair/request"), {
        method: "POST", credentials: "omit", redirect: "error", cache: "no-store",
        headers: { "Content-Type": "application/json" }, body: "{}" });
      if (!res.ok) return { ok: false, error: res.status === 429 ? "too many attempts: wait a minute" : "the vault refused" };
      const b = await res.json();
      return typeof b.poll === "string" ? { ok: true, poll: b.poll } : { ok: false, error: "unexpected answer" };
    } catch (_) {
      return { ok: false, error: "vault service not reachable" };
    }
  }

  async function pairStatus(fetchFn, port, poll) {
    try {
      const res = await fetchFn(endpoint(port, "/v1/pair/status?poll=" + encodeURIComponent(poll)), {
        credentials: "omit", redirect: "error", cache: "no-store" });
      const b = await res.json();
      if (b.status === "approved" && typeof b.token === "string") return { status: "approved", token: b.token };
      return { status: ["pending", "denied"].includes(b.status) ? b.status : "expired" };
    } catch (_) {
      return { status: "error" };
    }
  }

  // "Continue here": the vault prepares text and files for one destination (hidden details removed,
  // secrets block). Everything it sends back is treated as untrusted data by the page code.
  async function continueRequest(fetchFn, port, token, threadId, destination) {
    if (typeof token !== "string" || token.length < 16) return { ok: false, error: "not connected to your vault" };
    let res;
    try {
      res = await fetchFn(endpoint(port, "/v1/continue"), {
        method: "POST", credentials: "omit", redirect: "error", cache: "no-store",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ thread_id: threadId, destination }) });
    } catch (_) {
      return { ok: false, error: "vault service not reachable" };
    }
    let body = {};
    try { body = await res.json(); } catch (_) { /* handled below */ }
    if (res.status === 401 || res.status === 403) {
      return { ok: false, error: "your vault does not allow this: connect again, or run: thread init --update-policy" };
    }
    if (!res.ok) return { ok: false, error: U.clip(String(body.error || "the vault refused"), 300) };
    if (typeof body.text !== "string") return { ok: false, error: "unexpected answer from the vault" };
    return { ok: true, text: body.text, files: Array.isArray(body.files) ? body.files : [],
      hidden: body.hidden && typeof body.hidden === "object" ? body.hidden : {},
      skipped: Array.isArray(body.skipped) ? body.skipped.slice(0, 20).map((x) => U.clip(String(x), 200)) : [] };
  }

  async function openUrl(fetchFn, port, token) {
    try {
      const res = await fetchFn(endpoint(port, "/v1/open"), {
        method: "POST", credentials: "omit", redirect: "error", cache: "no-store",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: "{}" });
      if (!res.ok) return null;
      const b = await res.json();
      // Only ever our own service: never open a URL the response merely claims.
      const want = `http://${C.API_HOST}:${port}/s/`;
      return typeof b.url === "string" && b.url.startsWith(want) ? b.url : null;
    } catch (_) {
      return null;
    }
  }

  // A picture or document already checked by lib/files.js (`size` is the decoded byte count).
  function binaryFileRequest(site, adapterVersion, choice, file, opts) {
    const payload = { kind: "file", file: {
      name: U.clip(file.name, 255) || "attachment", media_type: U.clip(file.media_type, 127),
      size: file.size, data_base64: file.data_base64 } };
    return baseRequest(site, adapterVersion, targetFor(choice), payload, opts);
  }

  const api = { handoverRequest, messagesRequest, fileRequest, binaryFileRequest, post, listThreads, endpoint,
    health, tokenWorks, pairRequest, pairStatus, openUrl, continueRequest };
  if (typeof module !== "undefined") module.exports = api;
  else TV.ingest = api;
})(globalThis);
