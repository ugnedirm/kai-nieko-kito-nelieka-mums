// Adapter factory. An adapter is DATA (versioned selector lists) plus this shared, small logic.
// Every read goes through textContent/innerText; nothing from the page is ever evaluated or
// inserted as HTML. If the selectors stop matching, selfTest() says so and capture is refused:
// a broken adapter must fail loudly, never capture partial or wrong content (THREAT_MODEL 5.3).
(function (root) {
  const TV = (root.TV = root.TV || {});
  const U = typeof module !== "undefined" ? require("../lib/util.js") : TV.util;

  const MAX_ELEMENTS = 2000;

  function first(doc, selectors) {
    for (const s of selectors || []) {
      try {
        const el = doc.querySelector(s);
        if (el) return el;
      } catch (_) { /* invalid selector in this browser: try the next */ }
    }
    return null;
  }

  function all(doc, selectors) {
    for (const s of selectors || []) {
      try {
        const list = Array.from(doc.querySelectorAll(s)).slice(0, MAX_ELEMENTS);
        if (list.length) return list;
      } catch (_) { /* try the next */ }
    }
    return [];
  }

  const textOf = (el) => U.cleanText(el.innerText != null ? el.innerText : el.textContent || "");

  function makeAdapter(spec) {
    const a = {
      site: spec.site,
      version: spec.version,
      hosts: spec.hosts,

      inputElement: (doc) => first(doc, spec.selectors.input),

      conversation(doc) {
        // Role comes from the selector that matched, never from page text.
        const out = [];
        for (const role of ["user", "assistant"]) {
          for (const el of all(doc, spec.selectors[role])) {
            out.push({ role, el, text: textOf(el) });
          }
        }
        out.sort((x, y) => (x.el.compareDocumentPosition(y.el) & 4 ? -1 : 1)); // 4 = FOLLOWING
        return out.filter((m) => m.text.trim()).map(({ role, text }) => ({ role, text }));
      },

      assistantTurns: (doc) => all(doc, spec.selectors.assistant).length,

      lastAssistantText(doc) {
        const list = all(doc, spec.selectors.assistant);
        return list.length ? textOf(list[list.length - 1]) : "";
      },

      isGenerating: (doc) => !!first(doc, spec.selectors.generating),

      noticeTexts: (doc) => all(doc, spec.selectors.notices).map(textOf),

      artifacts(doc) {
        return all(doc, spec.selectors.artifacts).slice(0, 50).map((el, i) => ({
          name: `${spec.site}-artifact-${i + 1}.txt`, text: textOf(el) })).filter((f) => f.text.trim());
      },

      // Pictures and file links shown inside chat messages. Returns plain strings only: the
      // content script decides whether any of them may be fetched (lib/files.js urlAllowed).
      attachments(doc) {
        const out = [];
        const seen = new Set();
        const roots = [].concat(all(doc, spec.selectors.user), all(doc, spec.selectors.assistant));
        for (const el of roots) {
          if (typeof el.querySelectorAll !== "function") continue;
          for (const img of Array.from(el.querySelectorAll("img[src]")).slice(0, 40)) {
            const big = (img.naturalWidth || 0) >= 64 && (img.naturalHeight || 0) >= 64;
            const url = String(img.currentSrc || img.src || "");
            if (big && url && !seen.has(url)) {
              seen.add(url);
              out.push({ kind: "image", url, name: String(img.alt || "").slice(0, 120) });
            }
          }
          for (const a of Array.from(el.querySelectorAll("a[href]")).slice(0, 40)) {
            const url = String(a.href || "");
            const name = String(a.getAttribute("download") || (url.split("?")[0].split("/").pop() || "")).slice(0, 120);
            if (url && !seen.has(url) && (a.hasAttribute("download") || /\.[A-Za-z0-9]{2,5}$/.test(name))) {
              seen.add(url);
              out.push({ kind: "link", url, name });
            }
          }
        }
        return out.slice(0, 60);
      },

      pageTitle: (doc) => U.clip(U.cleanText(doc.title || ""), 200).trim(),

      // Put text into the chat box. Never presses send: the user does that.
      fillInput(doc, text) {
        const el = a.inputElement(doc);
        if (!el) return "missing";
        const existing = typeof el.value === "string" ? el.value : textOf(el);
        if (existing.trim()) return "busy"; // never overwrite something the user is typing
        el.focus();
        if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
          const proto = el.tagName === "TEXTAREA" ? root.HTMLTextAreaElement : root.HTMLInputElement;
          Object.getOwnPropertyDescriptor(proto.prototype, "value").set.call(el, text);
          el.dispatchEvent(new root.Event("input", { bubbles: true }));
          return "ok";
        }
        const sel = doc.getSelection();
        sel.selectAllChildren(el);
        if (!doc.execCommand("insertText", false, text)) {
          el.textContent = text;
          el.dispatchEvent(new root.Event("input", { bubbles: true }));
        }
        return "ok";
      },

      selfTest(doc) {
        const checks = [
          { name: "input box", required: true, ok: !!first(doc, spec.selectors.input) },
          { name: "assistant messages", required: false, ok: all(doc, spec.selectors.assistant).length > 0 },
          { name: "user messages", required: false, ok: all(doc, spec.selectors.user).length > 0 },
        ];
        const ok = checks.every((c) => c.ok || !c.required);
        const conversationOk = checks[1].ok && checks[2].ok;
        return { site: spec.site, version: spec.version, ok, conversationOk, checks };
      },
    };
    return a;
  }

  const api = { makeAdapter };
  if (typeof module !== "undefined") module.exports = api;
  else TV.adapterBase = api;
})(globalThis);
