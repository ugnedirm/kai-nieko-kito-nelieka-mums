// Pure helpers for capturing pictures and files shown in a chat. No network, no DOM: the
// content script does the guarded download, the background re-checks everything with these.
// The page is hostile: a URL or file it offers is only used if it passes every check here.
(function (root) {
  const TV = (root.TV = root.TV || {});
  const C = typeof module !== "undefined" ? require("./constants.js") : TV.constants;
  const U = typeof module !== "undefined" ? require("./util.js") : TV.util;

  const LIMITS = {
    MAX_FILES: 8,
    MAX_FILE_BYTES: 5 * 1024 * 1024, // one file
    MAX_TOTAL_BYTES: 5 * 1024 * 1024, // all files of one capture (kept in session storage)
    MAX_ATTACH_BYTES: 25 * 1024 * 1024, // a file the person attaches to the chat (saved at once, not kept)
  };
  // Types the vault can clean of hidden metadata (scanners/sanitize.py). Anything else would be
  // refused by the vault, so it is not offered.
  const EXT_BY_TYPE = { png: "png", jpeg: "jpg", pdf: "pdf", ooxml: "", text: "txt" };
  const TEXT_EXT = new Set(["txt", "md", "csv"]);
  const OOXML_EXT = new Set(["docx", "pptx", "xlsx"]);
  const CANDIDATE_EXT = new Set(["png", "jpg", "jpeg", "pdf", "txt", "md", "csv", "docx", "pptx", "xlsx"]);

  // Only the chat site itself, only https pages or its own blob: URLs, never credentials in the URL.
  function urlAllowed(urlString, pageOrigin) {
    let u;
    try { u = new URL(urlString); } catch (_) { return false; }
    if (u.username || u.password) return false;
    if (u.protocol === "blob:") return u.origin === pageOrigin;
    if (u.protocol === "https:") return u.origin === pageOrigin && C.ALLOWED_HOSTS.includes(u.hostname);
    return false;
  }

  function extensionOf(name) {
    const m = /\.([A-Za-z0-9]{1,8})$/.exec(String(name || ""));
    return m ? m[1].toLowerCase() : "";
  }

  // Is this link/picture worth downloading? Judged by its name only; the bytes decide later.
  function looksCapturable(name) {
    return CANDIDATE_EXT.has(extensionOf(name));
  }

  // What the bytes really are (never the server's Content-Type or the page's claim).
  function sniff(bytes, name) {
    const b = bytes;
    if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 &&
        b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a) return "png";
    if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "jpeg";
    if (b.length >= 5 && b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46 && b[4] === 0x2d) return "pdf";
    if (b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) {
      return OOXML_EXT.has(extensionOf(name)) ? "ooxml" : null;
    }
    if (TEXT_EXT.has(extensionOf(name)) && !b.includes(0)) {
      try { new TextDecoder("utf-8", { fatal: true }).decode(b); return "text"; } catch (_) { return null; }
    }
    return null;
  }

  function cleanName(name, type) {
    let n = U.cleanText(String(name || "")).split(/[\\/]/).pop();
    n = n.replace(/[^A-Za-z0-9._ -]/g, "_").replace(/^[. ]+/, "").slice(0, 120).trim() || "attachment";
    const want = EXT_BY_TYPE[type];
    if (want && extensionOf(n) !== want && !(type === "jpeg" && extensionOf(n) === "jpeg")) n += "." + want;
    return n;
  }

  const MEDIA = { png: "image/png", jpeg: "image/jpeg", pdf: "application/pdf", text: "text/plain",
    ooxml: "application/octet-stream" };

  function toBase64(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(bin);
  }

  function fromBase64(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // Background-side re-check of what a content script sent: shape, size budget and magic bytes.
  function validateCaptured(files, opts) {
    const maxFile = (opts && opts.maxFile) || LIMITS.MAX_FILE_BYTES;
    const maxTotal = (opts && opts.maxTotal) || LIMITS.MAX_TOTAL_BYTES;
    const out = [];
    let total = 0;
    for (const f of Array.isArray(files) ? files.slice(0, LIMITS.MAX_FILES) : []) {
      if (!f || typeof f.name !== "string" || typeof f.data_base64 !== "string") continue;
      if (f.data_base64.length > Math.ceil(maxFile * 4 / 3) + 8) continue;
      let bytes;
      try { bytes = fromBase64(f.data_base64); } catch (_) { continue; }
      if (bytes.length === 0 || bytes.length > maxFile || total + bytes.length > maxTotal) continue;
      const type = sniff(bytes, f.name);
      if (!type) continue;
      total += bytes.length;
      out.push({ name: cleanName(f.name, type), type, size: bytes.length,
        media_type: MEDIA[type], data_base64: f.data_base64 });
    }
    return out;
  }

  const api = { LIMITS, urlAllowed, extensionOf, looksCapturable, sniff, cleanName, toBase64, fromBase64,
    validateCaptured, MEDIA };
  if (typeof module !== "undefined") module.exports = api;
  else TV.files = api;
})(globalThis);
