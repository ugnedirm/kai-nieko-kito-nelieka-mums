// ChatGPT web adapter. Selector lists are tried in order. VERIFY against the live site and bump
// `version` whenever they change (the version is recorded with every ingest request).
(function (root) {
  const TV = (root.TV = root.TV || {});
  const B = typeof module !== "undefined" ? require("./base.js") : TV.adapterBase;
  const api = B.makeAdapter({
    site: "chatgpt",
    version: "1",
    hosts: ["chatgpt.com", "chat.openai.com"],
    selectors: {
      input: ["#prompt-textarea", "div[contenteditable='true'][id*='prompt']", "textarea[data-id='root']"],
      user: ["[data-message-author-role='user']"],
      assistant: ["[data-message-author-role='assistant']"],
      generating: ["button[data-testid='stop-button']", "button[aria-label='Stop streaming']"],
      notices: ["[role='alert']", "[data-testid*='limit']", "[data-testid*='banner']"],
      artifacts: ["[data-message-author-role='assistant'] pre"],
    },
  });
  if (typeof module !== "undefined") module.exports = api;
  else (TV.adapters = TV.adapters || {}).chatgpt = api;
})(globalThis);
