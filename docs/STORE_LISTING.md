# Store listing text (copy and paste)

For the Chrome Web Store, Edge Add-ons and Firefox Add-ons. Facts here match `docs/PRIVACY.md` and
`extension/PERMISSIONS.md`; if the extension changes, change them together. Screenshots (fake data
only) are in `docs/store/`; regenerate them with `python tools/make_store_screenshots.py`.

## Name

When nothing else is left

## Short description (Chrome: at most 132 characters)

Save a summary of your ChatGPT or Claude chat on your own computer and pick it up in another AI. Nothing leaves your machine.

## Short summary (Firefox)

Save a summary of a ChatGPT or Claude chat on your own computer, then continue it in another AI. Private by design.

## Detailed description

You spent an hour explaining a project to one AI. Then you hit your message limit, or you want a
second opinion from another AI. Normally you start over. This extension keeps the thread.

**What it does**
- Asks the AI for a short structured summary (what was decided, what is open, what to do next). You
  read it and fix anything wrong before anything is saved.
- Saves it, with the files you attached and optionally the whole conversation, to a vault on your
  own computer.
- Brings a saved thread into a new ChatGPT or Claude chat: it fills the message box with the
  summary and attaches the files. You press send.
- Reminds you every few replies to save a summary, so one already exists if you run out of
  messages.
- Hides emails, phone numbers, names and keys before anything goes to another AI, and refuses if it
  finds a secret.
- Treats saved text as data, not instructions, and flags text that looks like hidden instructions
  to an AI (prompt injection).

**Private by design**
Everything stays on your computer. There is no account, no server of ours, no analytics, no
tracking. The extension talks only to a small program on your own machine (127.0.0.1) and reads
only chatgpt.com, chat.openai.com and claude.ai.

**Important: it needs a companion program**
The extension saves into a vault program that runs on your computer. Install it first (one command
on macOS and Linux: see the project page), then open the extension and press "Connect to my vault".
Without it the extension cannot save anything.

Not affiliated with OpenAI or Anthropic.

## Category

Productivity (Chrome, Edge). Firefox: "Productivity" or "Other".

## Single purpose (Chrome)

Save a summary of a ChatGPT or Claude conversation, and bring a saved one into a new chat, using a
vault on the user's own computer.

## Permission justifications (Chrome asks for each)

- **storage**: keeps the secret token that links the extension to the user's own vault, the port
  number, and the user's options (checkpoint reminders, file attach choice).
- **Host access to chatgpt.com, chat.openai.com, claude.ai**: reads the conversation the user asks to
  save, and fills the message box and file picker when the user brings a saved thread into a chat.
  The extension never presses send.
- **Host access to http://127.0.0.1**: talks to the vault program running on the user's own computer.
  No other host is contacted.
- **Remote code**: none. All code ships in the package; the content security policy allows only the
  extension's own scripts.

## Data usage form (Chrome "Privacy practices")

Answer according to the current form. Our position, to be checked by the owner against that form:
the extension handles website content (the conversation the user chooses to save) and files the user
attaches, **locally only**. Nothing is transmitted off the user's device, sold, used for
advertising or creditworthiness, or used for anything other than the single purpose. Tick all three
certifications only if that is still true when you submit. Privacy policy URL: the rendered
`docs/PRIVACY.md` on GitHub (the repository must be public for this link to work).

## Notes for reviewers (paste into the submission)

The extension needs the companion program to function, so a reviewer cannot test it from the
extension alone. To test:
1. `python3 -m venv v && v/bin/pip install "threadvault[recommended] @ <release zip URL>"`, then
   `v/bin/thread setup`.
2. Open https://claude.ai or https://chatgpt.com in a chat, click the extension icon, press
   "Connect to my vault", then "Allow" on the page that opens.
3. Press "Save this chat's summary", press send in the chat, then Save on the review page.
4. Press "Open my saved threads" to see the result.
Network use: the extension contacts only 127.0.0.1. One `fetch` in the content script reads a
picture already shown in the user's own chat (same site only). See `extension/PERMISSIONS.md`.

## Screenshots (1280x800)

1. `docs/store/4-popup.png`: the popup, with the save button, thread picker and checkpoints.
2. `docs/store/2-review.png`: the review page, where the user checks the summary before saving.
3. `docs/store/1-thread.png`: a saved thread with the security check and the cleaned text to paste.
4. `docs/store/3-compare.png`: two threads side by side.

## Support

*Owner to fill in before submitting:* a support email or page. The store shows it publicly.
