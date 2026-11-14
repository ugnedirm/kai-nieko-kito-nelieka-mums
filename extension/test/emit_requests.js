// Prints sample ingest requests built by the extension code, for the Python contract test.
const H = require("../src/lib/handover.js");
const I = require("../src/lib/ingest.js");
const reply = "```json\n" + JSON.stringify({
  decisions: [{ text: "Use trains" }], open_questions: [], next_steps: [],
  key_facts: [{ text: "Budget 1200 EUR", source_note: "user said so" }],
  constraints: [], uncertain: [], files: [] }) + "\n```";
const content = H.parseReply(reply).content;
const out = {
  handover: I.handoverRequest("claude", "1", { title: "Trip", mode: "full" }, content, { userReviewed: true }),
  unreviewed: I.handoverRequest("chatgpt", "1", { title: "Trip", mode: "handover" }, content, { userReviewed: false }),
  messages: I.messagesRequest("chatgpt", "1", { title: "Trip", mode: "full" },
    [{ role: "user", text: "hi" }, { role: "assistant", text: "hello" }], {}),
  file: I.fileRequest("claude", "1", { title: "Trip", mode: "full" }, { name: "claude-artifact-1.txt", text: "print(1)" }, {}),
};
process.stdout.write(JSON.stringify(out));
