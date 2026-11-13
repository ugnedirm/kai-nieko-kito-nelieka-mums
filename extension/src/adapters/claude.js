// Claude web adapter. Same rules as chatgpt.js: VERIFY selectors on the live site, bump version.
(function (root) {
  const TV = (root.TV = root.TV || {});
  const B = typeof module !== "undefined" ? require("./base.js") : TV.adapterBase;
  const api = B.makeAdapter({
    site: "claude",
    version: "1",
    hosts: ["claude.ai"],
    selectors: {
      input: ["div[contenteditable='true'].ProseMirror", "div[contenteditable='true'][role='textbox']",
        "fieldset div[contenteditable='true']"],
      user: ["[data-testid='user-message']"],
      assistant: [".font-claude-message", "[data-is-streaming]"],
      generating: ["[data-is-streaming='true']", "button[aria-label='Stop response']"],
      notices: ["[role='alert']", "[data-testid*='limit']", "[data-testid*='banner']"],
      artifacts: ["[data-testid*='artifact'] pre", ".artifact-block-cell pre"],
    },
  });
  if (typeof module !== "undefined") module.exports = api;
  else (TV.adapters = TV.adapters || {}).claude = api;
})(globalThis);
