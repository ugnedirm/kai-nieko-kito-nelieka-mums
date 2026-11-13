// Shared constants. Classic script (no modules) so it loads in content scripts, the background
// worker and Node tests alike. Each file registers on the TV namespace.
(function (root) {
  const api = {
    CLIENT_ID: "browser-extension",
    VERSION: "0.1.0",
    SPEC_VERSION: "1",
    PROMPT_VERSION: "1",
    API_HOST: "127.0.0.1", // fixed: never configurable, never a remote host
    DEFAULT_PORT: 8765,
    MAX_TEXT: 4000,
    MAX_NOTE: 500,
    MAX_ITEMS: 200,
    MAX_REPLY_CHARS: 200000,
    MAX_MESSAGE_CHARS: 200000,
    MAX_MESSAGES: 1000,
    MAX_FILE_BYTES: 50 * 1024 * 1024,
    // The only pages the extension may read. Must match manifest.json (a test enforces it).
    ALLOWED_HOSTS: ["chatgpt.com", "chat.openai.com", "claude.ai"],
    SECTIONS: ["decisions", "open_questions", "next_steps", "key_facts", "constraints", "uncertain"],
    DEFAULT_CHECKPOINT_EVERY: 10,
  };
  if (typeof module !== "undefined") module.exports = api;
  else (root.TV = root.TV || {}).constants = api;
})(globalThis);
