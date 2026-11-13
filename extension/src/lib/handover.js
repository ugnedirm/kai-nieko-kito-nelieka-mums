// Turn an AI reply into a handover `content` object. The reply is UNTRUSTED: only known fields
// are copied, strings are cleaned and length-capped, and file hashes are never accepted (the
// vault owns them). The vault validates again; this is for a good review screen.
(function (root) {
  const TV = (root.TV = root.TV || {});
  const load = (n) => (typeof module !== "undefined" ? require("./" + n + ".js") : TV[n]);
  const C = load("constants");
  const U = load("util");

  const ALL = [...C.SECTIONS];

  function candidates(reply) {
    // Every balanced top-level {...} that parses to an object with a handover section.
    const found = [];
    for (let i = 0; i < reply.length && found.length < 5; i++) {
      if (reply[i] !== "{") continue;
      let depth = 0, inStr = false, esc = false;
      for (let j = i; j < reply.length; j++) {
        const ch = reply[j];
        if (inStr) {
          if (esc) esc = false;
          else if (ch === "\\") esc = true;
          else if (ch === '"') inStr = false;
        } else if (ch === '"') inStr = true;
        else if (ch === "{") depth++;
        else if (ch === "}" && --depth === 0) {
          try {
            const obj = JSON.parse(reply.slice(i, j + 1));
            if (obj && typeof obj === "object" && !Array.isArray(obj) && ALL.some((k) => k in obj)) {
              found.push(obj);
              i = j;
            }
          } catch (_) { /* not JSON: keep scanning */ }
          break;
        }
      }
    }
    return found;
  }

  function item(section, raw, problems, warnings, where) {
    if (typeof raw === "string") raw = { text: raw };
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      problems.push(`${where} must be an object`);
      return null;
    }
    const noteKey = section === "uncertain" ? "reason" : "source_note";
    const text = U.clip(U.cleanText(raw.text), C.MAX_TEXT).trim();
    if (!text) {
      warnings.push(`${where} had no text; dropped`);
      return null;
    }
    if (text === "...") {
      problems.push(`${where} still contains the placeholder "..."`);
      return null;
    }
    const out = { text };
    const note = U.clip(U.cleanText(raw[noteKey]), C.MAX_NOTE).trim();
    if (note) out[noteKey] = note;
    if (section === "key_facts" && !note) problems.push(`${where} (key_facts) needs a source_note`);
    return out;
  }

  function parseReply(reply) {
    const problems = [], warnings = [];
    if (typeof reply !== "string" || reply.length > C.MAX_REPLY_CHARS) {
      return { ok: false, content: null, problems: ["reply missing or too long"], warnings };
    }
    const found = candidates(reply);
    if (!found.length) {
      return { ok: false, content: null, warnings,
        problems: ["no complete JSON handover found; the reply may have been cut off"] };
    }
    if (found.length > 1) warnings.push("reply contained several JSON objects; only the first was used");
    const raw = found[0];
    const content = { files: [] }; // the extension never supplies file hashes
    if (Array.isArray(raw.files) && raw.files.length) {
      warnings.push("file list ignored: the vault links files it captured itself");
    }
    for (const section of ALL) {
      let list = raw[section];
      if (list === undefined) {
        warnings.push(`section "${section}" was missing; treated as empty`);
        list = [];
      }
      if (!Array.isArray(list)) {
        problems.push(`section "${section}" must be a list`);
        continue;
      }
      if (list.length > C.MAX_ITEMS) warnings.push(`section "${section}" cut to ${C.MAX_ITEMS} items`);
      content[section] = list.slice(0, C.MAX_ITEMS)
        .map((r, i) => item(section, r, problems, warnings, `${section}[${i}]`))
        .filter(Boolean);
    }
    const extra = Object.keys(raw).filter((k) => !ALL.includes(k) && k !== "files");
    if (extra.length) warnings.push(`ignored unknown fields: ${extra.slice(0, 5).join(", ")}`);
    return problems.length
      ? { ok: false, content: null, problems, warnings }
      : { ok: true, content, problems, warnings };
  }

  const api = { parseReply, candidates };
  if (typeof module !== "undefined") module.exports = api;
  else TV.handover = api;
})(globalThis);
