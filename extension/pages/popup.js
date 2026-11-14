(async function () {
  const ext = globalThis.browser || globalThis.chrome;
  const $ = (id) => document.getElementById(id);
  const state = $("state"), list = $("checks"), status = $("status"), body = $("body");
  const send = (type) => ext.runtime.sendMessage({ type });
  const open = (page) => ext.tabs.create({ url: ext.runtime.getURL(page) });

  function el(tag, props, ...kids) {
    const e = document.createElement(tag);
    Object.assign(e, props || {});
    e.append(...kids);
    return e;
  }

  async function tabMessage(type) {
    const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
    if (!tab) throw new Error("no tab");
    return ext.tabs.sendMessage(tab.id, { type });
  }

  async function selftest() {
    list.replaceChildren();
    try {
      const r = await tabMessage("selftest");
      state.textContent = r.ok ? `${r.site} page check v${r.version}: OK` : `${r.site} page check v${r.version}: this page layout is not recognised, saving is disabled`;
      for (const c of r.checks) list.append(el("li", { textContent: `${c.ok ? "ok" : c.required ? "FAIL" : "missing"}: ${c.name}` }));
      return r.ok;
    } catch (_) {
      state.textContent = "Open a ChatGPT or Claude chat to check it.";
      return null; // not on a chat page
    }
  }

  async function connect() {
    status.textContent = "Opening your vault... click Allow on the page that opens.";
    const r = await send("pair_start");
    if (!r || !r.ok) { status.textContent = (r && r.error) || "Could not reach your vault."; return; }
    for (let i = 0; i < 150; i++) { // about five minutes
      await new Promise((ok) => setTimeout(ok, 2000));
      const c = await send("pair_check");
      if (c.status === "approved") { render(); return; }
      if (c.status === "denied") { status.textContent = "You chose not to connect."; return; }
      if (c.status !== "pending" && c.status !== "error") break;
    }
    status.textContent = "Not connected. Press Connect to try again.";
  }

  async function render() {
    body.replaceChildren();
    await send("pair_check"); // finishes a connection the person approved while this popup was closed
    const v = await send("vault_status");
    const onChat = await selftest();
    if (!v.running) {
      status.className = "bad";
      status.textContent = "Your vault is not running";
      body.append(el("p", { textContent: "threadvault is a small program on your computer that keeps your saved chats. It isn't running yet." }),
        el("button", { className: "big", textContent: "Show me how to start it", onclick: () => open("pages/welcome.html") }));
      return;
    }
    if (!v.connected) {
      status.className = "bad";
      status.textContent = "Not connected yet";
      body.append(el("p", { textContent: "Connect this browser to your vault once. You will be asked to click Allow on a page that opens." }),
        el("button", { className: "big", textContent: "Connect to my vault", onclick: connect }));
      return;
    }
    status.className = "ok";
    status.textContent = "Connected to your vault";
    if (onChat === null) {
      body.append(el("p", { textContent: "Open a ChatGPT or Claude chat, then click this icon again to save it." }));
    } else if (onChat === false) {
      body.append(el("p", { className: "bad", textContent: "This page's layout is not recognised, so saving is turned off (the site may have changed)." }));
    } else {
      const msg = el("p", { className: "muted" });
      body.append(el("button", { className: "big", textContent: "Save this chat's summary", onclick: async () => {
        try {
          const res = await tabMessage("start_handover");
          msg.textContent = res.ok ? "Done: a request was typed into the chat box." : res.error;
        } catch (_) { msg.textContent = "Open a ChatGPT or Claude chat first."; }
      } }), el("ol", {}, el("li", { textContent: "Click the button above." }),
        el("li", { textContent: "Press send in the chat (the AI writes a short summary)." }),
        el("li", { textContent: "A review page opens: check it, then press Save." })), msg);
    }
    if (onChat === true) {
      const pick = el("select", { style: "width:100%;margin:4px 0" }, el("option", { value: "", textContent: "Continue a saved thread here..." }));
      const out = el("p", { className: "muted" });
      send("list_threads").then((list) => {
        for (const t of Array.isArray(list) ? list : []) pick.append(el("option", { value: t.thread_id, textContent: t.title }));
      });
      body.append(pick, el("button", { textContent: "Bring it into this chat", onclick: async () => {
        if (!pick.value) { out.textContent = "Choose a thread first."; return; }
        out.textContent = "Preparing... private details are hidden first.";
        const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
        const r = await ext.runtime.sendMessage({ type: "continue_start", threadId: pick.value, tabId: tab && tab.id });
        if (!r || !r.ok) { out.textContent = (r && r.error) || "Could not do that."; return; }
        const hid = Object.entries(r.hidden || {}).map(([k, n]) => `${n} ${k}`).join(", ");
        out.textContent = "Done. Check the chat box, then press send." +
          (r.attached ? ` ${r.attached} file(s) attached.` : "") + (r.note ? " " + r.note : "") +
          (hid ? ` Hidden before sharing: ${hid}.` : "") +
          ((r.skipped || []).length ? " Left out: " + r.skipped.join("; ") + "." : "");
      } }), out);
    }
    body.append(el("button", { textContent: "Open my saved threads", onclick: async () => {
      const r = await send("open_vault");
      if (!r || !r.ok) status.textContent = "Could not open your vault. Is it running?";
    } }));
  }

  $("test").onclick = selftest;
  $("help").onclick = () => open("pages/welcome.html");
  $("options").onclick = () => ext.runtime.openOptionsPage();
  render();
})();
