(function (root) {
  const TV = (root.TV = root.TV || {});
  const C = typeof module !== "undefined" ? require("./constants.js") : TV.constants;

  function randomId(prefix) {
    const bytes = new Uint8Array(12);
    (root.crypto || require("node:crypto").webcrypto).getRandomValues(bytes);
    let hex = "";
    for (const b of bytes) hex += b.toString(16).padStart(2, "0");
    return (prefix || "req") + "_" + hex; // matches ^[A-Za-z0-9_-]{8,64}$
  }

  // RFC 3339, UTC, whole seconds (the vault forbids floats and wants date-time).
  function nowIso(d) {
    return (d || new Date()).toISOString().replace(/\.\d{3}Z$/, "Z");
  }

  function clip(s, max) {
    s = typeof s === "string" ? s : "";
    return s.length > max ? s.slice(0, max) : s;
  }

  function hostAllowed(urlString) {
    try {
      const u = new URL(urlString);
      return u.protocol === "https:" && C.ALLOWED_HOSTS.includes(u.hostname);
    } catch (_) {
      return false;
    }
  }

  function validPort(p) {
    return Number.isInteger(p) && p >= 1024 && p <= 65535;
  }

  // Mirrors importers/base.py `is_hidden`: drop format characters (Cf: tag, bidi, zero-width, soft
  // hyphen...) except ZWJ/ZWNJ, variation selectors except U+FE0E/U+FE0F, lone surrogates and
  // control characters (except newline and tab). Written with \u{...} escapes so no invisible
  // character appears in this source.
  const STRIP = /[\p{Cf}\p{Cs}\p{Cc}\u{FE00}-\u{FE0D}\u{E0100}-\u{E01EF}]/gu;
  const KEEP = new Set(["\n", "\t", "\u{200C}", "\u{200D}"]);
  function cleanText(s) {
    s = typeof s === "string" ? s.replace(/\r\n?/g, "\n") : "";
    return s.normalize("NFC").replace(STRIP, (ch) => (KEEP.has(ch) ? ch : ""));
  }

  const api = { randomId, nowIso, clip, hostAllowed, validPort, cleanText };
  if (typeof module !== "undefined") module.exports = api;
  else TV.util = api;
})(globalThis);
