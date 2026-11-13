// Review-and-edit screen. Everything shown came from a chat page: it is set with textContent or
// input.value only (never parsed as markup). Nothing is saved until the user presses Save here.
(async function () {
  const ext = globalThis.browser || globalThis.chrome;
  const C = globalThis.TV.constants;
  const root = document.getElementById("root");
  const id = new URLSearchParams(location.search).get("id") || "";
  const NAMES = { decisions: "Decisions", open_questions: "Open questions", next_steps: "Next steps",
    key_facts: "Key facts (source required)", constraints: "Constraints", uncertain: "Uncertain" };

  function el(tag, props, ...kids) {
    const e = document.createElement(tag);
    Object.assign(e, props || {});
    e.append(...kids);
    return e;
  }
  const say = (cls, text) => el("div", { className: cls, textContent: text });

  const p = await ext.runtime.sendMessage({ type: "get_pending", id });
  root.replaceChildren(el("h1", { textContent: "Review before saving" }));
  if (!p) { root.append(say("err", "This capture has expired. Capture again from the chat page.")); return; }

  root.append(say("warn", "This summary was written by an AI. It may be wrong or incomplete. Saving marks it " +
    "as reviewed by you. Do not save anything you have not read."));
  for (const w of p.warnings) root.append(say("warn", w));

  const rows = {}; // section -> container
  function addRow(section, text, note) {
    const noteKey = section === "uncertain" ? "reason" : "source note";
    const row = el("div", { className: "item" },
      el("input", { value: text || "", maxLength: C.MAX_TEXT, placeholder: "text" }),
      el("input", { className: "note", value: note || "", maxLength: C.MAX_NOTE, placeholder: noteKey }),
      el("button", { type: "button", textContent: "Remove", onclick: () => row.remove() }));
    rows[section].append(row);
  }
  for (const s of C.SECTIONS) {
    rows[s] = el("div");
    root.append(el("h2", { textContent: NAMES[s] }), rows[s],
      el("button", { type: "button", textContent: "Add", onclick: () => addRow(s) }));
    for (const it of p.content[s]) addRow(s, it.text, it.source_note || it.reason);
  }

  const title = el("input", { value: p.title || "", maxLength: 200 });
  const threadSel = el("select", {}, el("option", { value: "", textContent: "New thread" }));
  const saveMessages = el("input", { type: "checkbox" });
  const saveArtifacts = el("input", { type: "checkbox" });
  root.append(el("h2", { textContent: "Where to save" }),
    el("label", {}, "Thread: ", threadSel), el("br"), el("label", {}, "New thread title: ", title));
  ext.runtime.sendMessage({ type: "list_threads" }).then((list) => {
    for (const t of Array.isArray(list) ? list : []) threadSel.append(el("option", { value: t.thread_id, textContent: t.title }));
  });
  if (p.messages && p.messages.length) {
    root.append(el("div", {}, el("label", {}, saveMessages, ` Also save the whole conversation (${p.messages.length} messages, stored as unverified)`)));
  }
  if (p.artifacts && p.artifacts.length) {
    root.append(el("div", {}, el("label", {}, saveArtifacts, ` Also save ${p.artifacts.length} code/text block(s) as files`)));
  }

  const status = el("div");
  const save = el("button", { type: "button", textContent: "Save" });
  let ackStep = null; // the step whose findings the user has just seen
  root.addEventListener("input", () => { ackStep = null; }); // edits need fresh confirmation
  save.onclick = async () => {
    const content = { files: [] };
    for (const s of C.SECTIONS) {
      content[s] = Array.from(rows[s].children).map((r) => {
        const [t, n] = r.querySelectorAll("input");
        const o = { text: t.value };
        if (n.value) o[s === "uncertain" ? "reason" : "source_note"] = n.value;
        return o;
      }).filter((o) => o.text.trim());
    }
    save.disabled = true;
    const res = await ext.runtime.sendMessage({ type: "submit", id, content, title: title.value,
      threadId: threadSel.value, saveMessages: saveMessages.checked, saveArtifacts: saveArtifacts.checked, ackStep });
    save.disabled = false;
    status.replaceChildren();
    ackStep = null;
    if (res.status === "accepted") { status.append(say("ok", "Saved.")); save.disabled = true; return; }
    if (res.status === "needs_confirmation") {
      status.append(say("warn", "The vault found items that may be sensitive (shown by type and place only). " +
        "Edit them out, or press Save again to keep them."));
      for (const f of res.findings) status.append(say("warn", `${f.kind} (${f.severity}) at ${f.path}`));
      ackStep = res.step || null;
      return;
    }
    status.append(say("err", (res.error || "Not saved.") + (res.step ? ` (step: ${res.step})` : "")));
    for (const f of res.findings || []) status.append(say("err", `${f.kind} at ${f.path}`));
  };
  root.append(el("p", {}, save), status);
})();
