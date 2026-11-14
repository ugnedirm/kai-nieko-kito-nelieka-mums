// ChatGPT web adapter. Selector lists are tried in order. VERIFY against the live site and bump
// `version` whenever they change (the version is recorded with every ingest request).
(function (root) {
  const TV = (root.TV = root.TV || {});
  const B = typeof module !== "undefined" ? require("./base.js") : TV.adapterBase;
  const api = B.makeAdapter({
    site: "chatgpt",
    version: "2",
    hosts: ["chatgpt.com", "chat.openai.com"],
    selectors: {
      input: ["div[contenteditable='true'][role='textbox'][aria-label='Ask ChatGPT']", "#prompt-textarea",
        "div[contenteditable='true'].ProseMirror[role='textbox']",
        "div[contenteditable='true'][id*='prompt']", "textarea[data-id='root']"],
      user: ["[data-user-message-bubble='true']", "[data-message-author-role='user']"],
      assistant: ["[data-dil-response]", "[data-message-author-role='assistant']"],
      generating: ["button[data-testid='stop-button']", "button[aria-label='Stop streaming']"],
      notices: ["[role='alert']", "[data-testid*='limit']", "[data-testid*='banner']"],
      artifacts: ["[data-dil-response] pre", "[data-message-author-role='assistant'] pre"],
    },
  });
  if (typeof module !== "undefined") module.exports = api;
  else (TV.adapters = TV.adapters || {}).chatgpt = api;
})(globalThis);
