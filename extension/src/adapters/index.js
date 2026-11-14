(function (root) {
  const TV = (root.TV = root.TV || {});
  const list = () => (typeof module !== "undefined"
    ? [require("./chatgpt.js"), require("./claude.js")] : Object.values(TV.adapters || {}));

  function adapterFor(hostname) {
    return list().find((a) => a.hosts.includes(hostname)) || null;
  }

  const api = { adapterFor };
  if (typeof module !== "undefined") module.exports = api;
  else TV.adapterIndex = api;
})(globalThis);
