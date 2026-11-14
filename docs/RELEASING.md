# Releasing and distributing

What exists, what a release does, and what only the project owner can do. Read "Not done yet" first.

## Not done yet (needs the owner)

The project is MIT-licensed (`LICENSE`, `license = "MIT"` in `pyproject.toml`); that item is done.
A license is not strictly required by the Chrome Web Store, and Firefox Add-ons asks you to pick one
("all rights reserved" is allowed): check the current forms. It is needed so that others may legally
use the code, which the installer and the download links assume.

- **Store accounts and submission.** Nothing has been submitted to the Chrome Web Store or Firefox
  Add-ons. Both need an account in your name (Chrome charges a small one-time developer
  registration fee; check the current amount) and a review that can take days.
- **A public repository.** The installer's default download is `github.com/.../archive/refs/heads/main.zip`,
  and the privacy policy link points at the repository: both need it public.
- **A support contact** for the store listings (screenshots and listing text are ready).
- **Mac `.dmg` and Windows `.exe` installers are not built.** They need code-signing (an Apple
  Developer account, about US$99 a year, for macOS notarization; a signing certificate for
  Windows) or users see "unidentified developer" / SmartScreen warnings. What exists instead:
  `scripts/install.sh` for macOS and Linux, and a wheel for `pip`.
- **Windows is untested.** The Python program should run, but `thread setup` (start at login) is
  macOS and Linux only, and the installer script is not for Windows.
- The release workflow (`.github/workflows/release.yml`) has not run yet: its first real run is the
  first tag you push. Its steps were run by hand locally and passed.

## Cutting a release

1. Pick the version, say `0.2.0`. Set it in `pyproject.toml` (`version`), and in
   `extension/manifest.json`, `extension/manifest.firefox.json` and `extension/package.json`.
2. Make sure CI is green on `main`.
3. `git tag v0.2.0 && git push origin v0.2.0`.
4. The `release` workflow checks the tag matches `pyproject.toml`, runs ruff, mypy, pytest and the
   extension tests, builds the wheel and source archive and the two extension zips, smoke-tests the
   wheel in a clean environment, and publishes a GitHub Release with the files and `SHA256SUMS`.

By hand, the same steps: `pip install build && python -m build`, then
`cd extension && npm run build && cd .. && python tools/package_extension.py`. The zips land in
`extension/dist/release/` and are reproducible (same source, same bytes).

## What a user downloads

- **Mac/Linux:** `scripts/install.sh` (also attached to each release). It needs Python 3.11+, installs
  into the user's home folder only, and `sh install.sh --uninstall` removes it without touching
  saved threads. Then `thread setup`, then the extension.
- **Any system:** `pip install "threadvault[recommended] @ <release wheel or zip URL>"`.
- **The extension:** from the store once listed; until then, the zip from the release page, loaded
  with Developer mode (Chrome: Load unpacked after unzipping; Firefox: Load Temporary Add-on).

The extension alone does nothing: it needs the local program (`thread setup`). Say so in the listing.

## Chrome Web Store (also accepted by Edge Add-ons)

1. Register at https://chrome.google.com/webstore/devconsole and pay the one-time fee.
2. New item, upload `when-nothing-else-is-left-chrome-<version>.zip`.
3. Listing: name "When nothing else is left"; the 128 px icon is `extension/icons/icon-128.png`;
   at least one screenshot (1280x800 or 640x400); category Productivity.
4. Privacy tab: **single purpose** "Save a summary of a ChatGPT or Claude conversation, and bring a
   saved one into a new chat, using a vault on the user's own computer." Paste the permission
   reasons from `docs/PRIVACY.md`. State that no user data is collected or transmitted off the
   device. Privacy policy URL: the rendered `docs/PRIVACY.md` on GitHub.
5. Submit. Mention in the notes that it requires the companion program and how to test it
   (`thread setup`, then Connect and Allow).

## Firefox Add-ons (AMO)

1. https://addons.mozilla.org/developers/, submit `when-nothing-else-is-left-firefox-<version>.zip`.
2. The add-on id is fixed in `manifest.firefox.json` (`browser_specific_settings.gecko.id`): never
   change it, or existing users' settings are lost. It declares no data collection.
3. The code is plain, unminified JavaScript. `src/generated/prompt.js` is generated from
   `src/threadvault/agent/prompts/handover_v1.txt` by `extension/tools/build.mjs`; if the reviewers ask
   for source, send the repository and say to run `cd extension && npm run build`.

## Listing text and screenshots

Ready to paste: `docs/STORE_LISTING.md` (names, descriptions, single purpose, permission reasons,
reviewer notes). Four 1280x800 screenshots with fake data are in `docs/store/`; regenerate them after a
design change with `python tools/make_store_screenshots.py` (needs the built extension and Chrome).

## Updating

Bump the version (step 1), tag, publish. Re-upload the new zips to each store. Users of the Mac and
Linux installer re-run `install.sh` to upgrade.
