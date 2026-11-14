# Privacy policy: When nothing else is left (threadvault)

*Last updated: see the file's date in the repository history.*

**The short version: your conversations stay on your computer. The extension and the program send
nothing to the authors, to any server, or to any third party. There is no account, no analytics and
no tracking.**

## What the extension reads

On `chatgpt.com`, `chat.openai.com` and `claude.ai` only, the extension can read the text of the
conversation you have open, pictures and files shown in it, and files you attach to a message. It
reads them only when you ask it to save (press "Save this chat's summary"), when you accept the
notice about an attached file, or when a checkpoint reminds you. It never reads other websites.

## Where the data goes

- **To the vault on your own computer**, and only to `http://127.0.0.1` (a program running on your
  machine). Nothing is sent to the internet by the extension.
- **Into a chat page you choose**, when you press "Bring it into this chat": the extension types
  saved text into that chat's message box and attaches files, then **you** decide whether to press
  send. Private details (emails, phone numbers, names, keys) are hidden first, and a secret blocks it.
- **Nowhere else.** No analytics, no crash reports, no advertising, no sharing, no selling.

Once you press send in a chat site, that site's own privacy policy applies to what you sent.

## What is stored, and where

- **In your browser profile** (extension storage): a secret token that lets the extension talk to
  your own vault, the port number, and your options (checkpoint reminders, file attach choice).
- **In your vault folder on your computer** (default `~/.threadvault`): the threads, summaries,
  files and an access log you chose to save. You can read, copy, back up and delete it. Threads can
  be set to delete themselves, and any file can be deleted everywhere. Hidden details in files
  (such as location in photos) are removed before saving where possible.

## Permissions the extension asks for, and why

| Permission | Why |
|---|---|
| `storage` | Keep the token, port and options in your browser |
| `chatgpt.com`, `chat.openai.com`, `claude.ai` | Read the conversation you ask it to save; fill the chat box |
| `http://127.0.0.1` | Talk to the vault program on your own computer |

It requests no access to your browsing history, tabs, cookies or other websites, and it contains no
remote code: everything it runs ships inside the package.

## Children, changes, contact

The tool is not directed at children. If this policy changes, the new version is published in the
repository with the date of the change. Questions: open an issue at
https://github.com/ugnedirm/kai-nieko-kito-nelieka-mums/issues.

*Owner to complete before submitting to a store: a support contact (email or web page) that the
store listing will show.*
