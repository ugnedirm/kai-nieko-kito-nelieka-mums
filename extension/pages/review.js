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

  root.append(say("ok", "What is this? Your chat was summarised so you can carry on in another AI. " +
    "Read it, correct or remove anything wrong, then press Save at the bottom. Nothing is saved until you do."));
  root.append(say("warn", "This summary was written by an AI. It may be wrong or incomplete. Saving marks it " +
    "as reviewed by you. Do not save anything you have not read."));
  for (const w of p.warnings) root.append(say("warn", w));

  // Layout helpers: every part of the page is a card with a heading, and long text is shown in full.
  function card(titleText, ...kids) {
    const head = el("div", { className: "card-head" }, el("h2", { textContent: titleText }));
    const c = el("section", { className: "card" }, head, ...kids);
    c.head = head;
    return c;
  }
  const field = (label, control) => el("label", { className: "field" }, el("span", { textContent: label }), control);
  const check = (box, text) => el("label", { className: "check" }, box, el("span", { textContent: text }));
  const grow = (t) => { t.style.height = "auto"; t.style.height = (t.scrollHeight + 2) + "px"; };

  const rows = {}; // section -> container
  function addRow(section, text, note) {
    const noteKey = section === "uncertain" ? "reason" : "source note";
    const t = el("textarea", { rows: 1, value: text || "", maxLength: C.MAX_TEXT, placeholder: "text" });
    const n = el("textarea", { rows: 1, className: "note", value: note || "", maxLength: C.MAX_NOTE, placeholder: noteKey });
    const row = el("div", { className: "item" }, t, n,
      el("button", { type: "button", className: "secondary small", textContent: "Remove", onclick: () => row.remove() }));
    for (const x of [t, n]) x.addEventListener("input", () => grow(x));
    rows[section].append(row);
    grow(t);
    grow(n);
  }
  for (const s of C.SECTIONS) {
    rows[s] = el("div", { className: "rows" });
    const c = card(NAMES[s], rows[s]);
    c.head.append(el("button", { type: "button", className: "secondary small", textContent: "+ Add", onclick: () => addRow(s) }));
    root.append(c);
    for (const it of p.content[s]) addRow(s, it.text, it.source_note || it.reason);
  }

  const title = el("input", { value: p.title || "", maxLength: 200 });
  const threadNote = el("p", { className: "note-small" });
  const threadSel = el("select", {}, el("option", { value: "", textContent: "New thread" }));
  const saveMessages = el("input", { type: "checkbox" });
  const saveArtifacts = el("input", { type: "checkbox" });
  const where = card("Where to save", field("Thread", threadSel), threadNote, field("New thread title", title));
  ext.runtime.sendMessage({ type: "list_threads" }).then((list) => {
    for (const t of Array.isArray(list) ? list : []) threadSel.append(el("option", { value: t.thread_id, textContent: t.title }));
    // Files attached to this chat already went to one thread: save the summary there too.
    if (p.suggestedThreadId && Array.from(threadSel.options).some((o) => o.value === p.suggestedThreadId)) {
      threadSel.value = p.suggestedThreadId;
      threadNote.textContent = "Files you attached to this chat were saved in the thread selected above, " +
        "so the summary will be added to it. Choose \"New thread\" to keep it separate.";
    }
  });
  if (p.messages && p.messages.length) {
    where.append(check(saveMessages, `Also save the whole conversation (${p.messages.length} messages, stored as unverified)`));
  }
  if (p.artifacts && p.artifacts.length) {
    where.append(check(saveArtifacts, `Also save ${p.artifacts.length} code/text block(s) as files`));
  }
  root.append(where);

  const fileBoxes = [];
  const filesCard = card("Pictures and files from the chat");
  if (p.files && p.files.length) {
    filesCard.append(say("warn", "Tick the ones to save. Hidden data such as the location inside a photo is " +
      "removed by the vault before storing."));
    p.files.forEach((f) => {
      const box = el("input", { type: "checkbox", checked: true });
      fileBoxes.push(box);
      filesCard.append(check(box, `${f.name} (${f.size < 1024 ? f.size + " bytes" : Math.round(f.size / 1024) + " KB"})`));
    });
  } else {
    filesCard.append(el("p", { className: "note-small", textContent: "None found." }));
  }
  filesCard.append(el("p", { className: "note-small",
    textContent: "Some files, such as documents you uploaded, are not available to the extension and cannot be captured automatically." }));
  root.append(filesCard);

  const status = el("div");
  const save = el("button", { type: "button", textContent: "Save" });
  let ackStep = null; // the step whose findings the user has just seen
  root.addEventListener("input", () => { ackStep = null; }); // edits need fresh confirmation
  save.onclick = async () => {
    const content = { files: [] };
    for (const s of C.SECTIONS) {
      content[s] = Array.from(rows[s].children).map((r) => {
        const [t, n] = r.querySelectorAll("textarea");
        const o = { text: t.value };
        if (n.value) o[s === "uncertain" ? "reason" : "source_note"] = n.value;
        return o;
      }).filter((o) => o.text.trim());
    }
    save.disabled = true;
    const res = await ext.runtime.sendMessage({ type: "submit", id, content, title: title.value,
      threadId: threadSel.value, saveMessages: saveMessages.checked, saveArtifacts: saveArtifacts.checked,
      fileIndexes: fileBoxes.map((b, i) => (b.checked ? i : -1)).filter((i) => i >= 0), ackStep });
    save.disabled = false;
    status.replaceChildren();
    ackStep = null;
    if (res.status === "accepted") {
      status.append(say("ok", "Saved! Your summary is now in your vault."),
        el("button", { type: "button", textContent: "Open my saved threads",
          onclick: () => ext.runtime.sendMessage({ type: "open_vault" }) }));
      save.disabled = true;
      return;
    }
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
