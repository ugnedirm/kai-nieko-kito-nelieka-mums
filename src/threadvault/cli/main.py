"""`thread` command line. Depends on the `Vault` Protocol only (see cli/context.py)."""

from __future__ import annotations

import json
import os
import time
import urllib.request
import webbrowser
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer

from threadvault import schemas
from threadvault.agent.handover import parse_reply
from threadvault.cli import attach, autostart, lifecycle
from threadvault.cli import serve as serve_mod
from threadvault.cli.context import load_policy, open_log, open_vault, vault_root
from threadvault.cli.redact import ExportRefused, apply_profile
from threadvault.cli.safe import terminal_safe
from threadvault.core.accesslog import FileAccessLog, filter_entries, format_entries
from threadvault.core.lineage import ForkError
from threadvault.core.render import handover_text
from threadvault.core.vault import Vault
from threadvault.importers import chatgpt, claude, gemini, markdown
from threadvault.importers.base import ImportedThread, ImportRefused
from threadvault.importers.scan import scan_import, summarize
from threadvault.importers.store import store_import
from threadvault.policy.engine import check_policy, destination_profile
from threadvault.policy.plugins import PINS_FORMAT, Pins, PluginRefused, pin_entry
from threadvault.scanners.basic import scan_record
from threadvault.types import SECRET_KINDS

app = typer.Typer(help="threadvault: portable AI conversation threads", no_args_is_help=True)
import_app = typer.Typer(help="Import conversations from an export file", no_args_is_help=True)
app.add_typer(import_app, name="import")
token_app = typer.Typer(help="The token the browser extension uses", no_args_is_help=True)
app.add_typer(token_app, name="token")
file_app = typer.Typer(help="Files attached to a thread", no_args_is_help=True)
app.add_typer(file_app, name="file")
policy_app = typer.Typer(help="Who may do what (policy.json)", no_args_is_help=True)
app.add_typer(policy_app, name="policy")
plugin_app = typer.Typer(help="Plugins you trust (pinned by hash)", no_args_is_help=True)
app.add_typer(plugin_app, name="plugin")
handover_app = typer.Typer(help="Work with handovers", no_args_is_help=True)
app.add_typer(handover_app, name="handover")
MAX_REPLY_BYTES = 1024 * 1024

VaultOpt = Annotated[Path | None, typer.Option("--vault", envvar="THREADVAULT_DIR",
                                               help="Vault directory")]


def _vault(ctx: typer.Context) -> Vault:
    return open_vault(ctx.obj)


def _version(value: bool) -> None:
    if value:
        from importlib.metadata import PackageNotFoundError, version

        try:
            typer.echo("When nothing else is left (threadvault) " + version("threadvault"))
        except PackageNotFoundError:
            typer.echo("When nothing else is left (threadvault), development checkout")
        raise typer.Exit()


@app.callback()
def main(ctx: typer.Context, vault: VaultOpt = None,
         version: Annotated[bool, typer.Option("--version", callback=_version, is_eager=True,
                                               help="Show the version and exit")] = False) -> None:
    ctx.obj = vault


def _echo(text: str) -> None:
    typer.echo(terminal_safe(text))


def _fail(msg: str) -> typer.Exit:
    typer.echo(terminal_safe(msg), err=True)
    return typer.Exit(1)


def _run_import(ctx: typer.Context, loader: Callable[[Path], list[ImportedThread]], file: Path) -> None:
    vault = _vault(ctx)
    try:
        threads = loader(file)
        for t in threads:
            tid = store_import(vault, t)
            note = f" (warnings: {', '.join(t.warnings)})" if t.warnings else ""
            _echo(f"{tid}  {len(t.messages)} messages  {t.title}{note}")
            found = summarize(scan_import(t))
            if found:
                _echo("  scan: " + ", ".join(f"{k} x{n}" for k, n in found.items())
                      + "  (heuristic; review before giving this thread to an AI)")
    except ImportRefused as e:
        raise _fail(f"import refused: {e.code}") from None
    except Exception:  # noqa: BLE001 - never show a traceback that could echo file content
        raise _fail("import failed: unexpected error") from None
    _echo(f"imported {len(threads)} thread(s) as imported-unverified")


@import_app.command("chatgpt")
def import_chatgpt(ctx: typer.Context, file: Path) -> None:
    """Import a ChatGPT export (conversations.json or the .zip). Stored as imported-unverified."""
    _run_import(ctx, chatgpt.import_chatgpt, file)


@import_app.command("claude")
def import_claude(ctx: typer.Context, file: Path) -> None:
    """Import a Claude export (conversations.json or the .zip)."""
    _run_import(ctx, claude.import_claude, file)


@import_app.command("gemini")
def import_gemini(ctx: typer.Context, file: Path) -> None:
    """Import Gemini Apps activity from a Google Takeout .zip or MyActivity.json."""
    _run_import(ctx, gemini.import_gemini, file)


@import_app.command("markdown")
def import_markdown(ctx: typer.Context, file: Path) -> None:
    """Import a Markdown/plain-text transcript with User:/Assistant: labels."""
    _run_import(ctx, markdown.import_markdown, file)


@app.command("list")
def list_threads(ctx: typer.Context) -> None:
    """List the threads in the vault."""
    for t in _vault(ctx).list_threads():
        _echo(f"{t.thread_id}  {t.mode}  {len(t.branches)} branch(es)  {t.updated_at}  {t.title}")


@app.command()
def fork(ctx: typer.Context, thread_id: str, branch: str | None = None,
         label: Annotated[str | None, typer.Option(help="Name for the new branch")] = None,
         at_hash: Annotated[str | None, typer.Option(
             help="Fork after the record with this hash (default: the branch's latest)")] = None,
         handover_version: Annotated[int | None, typer.Option(
             help="Fork at this handover version")] = None) -> None:
    """Start a new branch that shares history with an existing one, and make it current."""
    vault = _vault(ctx)
    try:
        bid = vault.fork(thread_id, branch, at_hash=at_hash, handover_version=handover_version,
                         label=label)
        vault.set_current_branch(thread_id, bid)
    except KeyError:
        raise _fail("no such thread or branch") from None
    except (ForkError, ValueError):
        raise _fail("cannot fork: fork point not found") from None
    _echo(f"forked {thread_id} as branch {bid} (now the current branch)")


@app.command()
def show(ctx: typer.Context, thread_id: str, branch: str | None = None) -> None:
    """Print a thread as plain text."""
    try:
        _echo(_vault(ctx).render_text(thread_id, branch))
    except KeyError:
        raise _fail("no such thread or branch") from None


@app.command()
def pack(ctx: typer.Context, thread_id: str, max_tokens: int = 4000,
         branch: str | None = None) -> None:
    """Print the latest handover (wrapped as historical context) plus the newest messages."""
    try:
        _echo(_vault(ctx).pack(thread_id, max_tokens, branch))
    except KeyError:
        raise _fail("no such thread or branch") from None


@app.command()
def verify(ctx: typer.Context,
           thread_id: Annotated[str | None, typer.Argument()] = None) -> None:
    """Recompute hashes and links. Exit code 1 if anything is wrong."""
    vault = _vault(ctx)
    ids = [thread_id] if thread_id else [t.thread_id for t in vault.list_threads()]
    ok = True
    for tid in ids:
        try:
            report = vault.verify(tid)
        except KeyError:
            raise _fail("no such thread") from None
        ok &= report.ok
        _echo(f"{tid}: {'ok' if report.ok else 'FAILED'}")
        for b in report.branches:
            for i in b.issues:
                where = f"record {i.index}" if i.index >= 0 else "branch"
                _echo(f"  {b.branch_id}: {i.code} ({where})")
            if b.unverified_after is not None:
                _echo(f"  {b.branch_id}: records from {b.unverified_after} on are unverified")
        for n in report.notices:
            _echo(f"  note: {n}")
    if not ok:
        raise typer.Exit(1)


@handover_app.command("add")
def handover_add(ctx: typer.Context, thread_id: str, reply_file: Path,
                 yes: Annotated[bool, typer.Option("--yes", help="Skip the review prompt")] = False,
                 ) -> None:
    """Save an AI-written handover (the AI's reply, in a file) after you review it."""
    vault = _vault(ctx)
    try:
        if reply_file.stat().st_size > MAX_REPLY_BYTES:
            raise _fail("reply file too large")
        reply = reply_file.read_text(encoding="utf-8", errors="replace")
        data = vault.load_thread(thread_id)
    except OSError:
        raise _fail("cannot read reply file") from None
    except KeyError:
        raise _fail("no such thread") from None
    known = {f["name"]: f["sha256"] for f in data.manifest["files"]}
    parsed = parse_reply(reply, known)
    for w in parsed.warnings:
        _echo(f"warning: {w}")
    if not parsed.ok or parsed.content is None:
        for p in parsed.problems:
            _echo(f"problem: {p}")
        raise _fail("handover not saved: fix the problems above and try again")

    findings = scan_record(parsed.content, "$.content")
    if any(f.kind in SECRET_KINDS for f in findings):
        raise _fail("handover not saved: it contains what looks like a secret "
                    f"({', '.join(sorted({f.kind for f in findings if f.kind in SECRET_KINDS}))})")
    for f in findings:
        _echo(f"finding: {f.kind} at {f.path}")

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    record_in = {"type": "handover", "content": parsed.content, "metadata": {
        "author": {"kind": "ai"}, "created_at": now, "prompt_version": "1",
        "provenance": "imported-unverified" if yes else "ai-summary-user-saved",
        "thread_state": {"source": "imported", "user_reviewed": not yes}}}
    _echo("--- handover to save ---")
    _echo(handover_text({"content": parsed.content}))
    if yes:
        _echo("note: --yes skips review, so this handover is saved as unreviewed")
    elif not typer.confirm("Save this handover? (it is saved as reviewed by you)"):
        raise _fail("not saved")
    branch_id = str(data.manifest["current_branch"])
    rec = vault.append(thread_id, branch_id, record_in)
    if schemas.errors("handover", rec):
        raise _fail("vault produced an invalid handover record")
    _echo(f"saved handover v{rec['version']}  {rec['hash']}")


@app.command()
def export(ctx: typer.Context, thread_id: str, destination: str, out: Path,
           max_tokens: int = 8000) -> None:
    """Write a thread for a destination in policy.json, after applying its redaction profile."""
    profile = destination_profile(load_policy(ctx.obj), destination)
    log = open_log(ctx.obj)
    if profile is None:
        log.record(client_id="cli", kind="cli", action="export", outcome="denied",
                   thread_id=thread_id, detail="destination not allowed")
        raise _fail("destination not in policy: refused")
    try:
        text = apply_profile(_vault(ctx).pack(thread_id, max_tokens), profile)
    except KeyError:
        raise _fail("no such thread") from None
    except ExportRefused as e:
        log.record(client_id="cli", kind="cli", action="export", outcome="denied",
                   thread_id=thread_id, detail="blocked by profile")
        raise _fail(str(e)) from None
    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        raise _fail("cannot create output file (does it already exist?)") from None
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    log.record(client_id="cli", kind="cli", action="export", outcome="allowed",
               thread_id=thread_id, detail=f"destination={destination[:64]}")
    _echo(f"exported to {out}")


STARTER_POLICY = {
    "spec_version": "1", "type": "policy", "default_profile": "strict",
    "clients": [{"client_id": "browser-extension",
                 "capabilities": ["append", "save_handover", "export"]}],
    "destinations": [
        {"destination_id": "local", "kind": "local", "profile": "open"},
        {"destination_id": "chatgpt", "kind": "cloud-llm", "profile": "share",
         "allow_hosts": ["chatgpt.com", "chat.openai.com"]},
        {"destination_id": "claude", "kind": "cloud-llm", "profile": "share",
         "allow_hosts": ["claude.ai"]},
        {"destination_id": "gemini", "kind": "cloud-llm", "profile": "share",
         "allow_hosts": ["gemini.google.com"]},
        {"destination_id": "openai", "kind": "cloud-llm", "profile": "strict",
         "allow_hosts": ["api.openai.com"]},
        {"destination_id": "anthropic", "kind": "cloud-llm", "profile": "strict",
         "allow_hosts": ["api.anthropic.com"]}],
    "profiles": {
        "open": {"redact": [], "pseudonymize": False, "block_on_secrets": False,
                 "allow_attachments": True, "strip_file_metadata": False},
        "share": {"redact": ["email", "phone", "api_key", "secret", "person"],
                  "pseudonymize": False, "block_on_secrets": True,
                  "allow_attachments": True, "strip_file_metadata": True},
        "strict": {"redact": ["email", "phone", "api_key", "secret", "person"],
                   "pseudonymize": True, "block_on_secrets": True, "allow_attachments": False,
                   "strip_file_metadata": True}}}


@app.command()
def init(ctx: typer.Context,
         update_policy: Annotated[bool, typer.Option(
             "--update-policy", help="Replace policy.json with the current starter policy "
                                     "(the old file is kept as policy.json.bak)")] = False) -> None:
    """Create the vault, its extension token and a starter policy.json (extension may save)."""
    root = vault_root(ctx.obj)
    _vault(ctx)  # creates the directory layout
    token_path = root / serve_mod.TOKEN_FILE
    had_token = token_path.exists()
    serve_mod.ensure_token(root)
    policy_path = root / "policy.json"
    text = json.dumps(STARTER_POLICY, indent=2) + "\n"
    if policy_path.exists() and update_policy:
        policy_path.replace(root / "policy.json.bak")
        policy_path.write_text(text, encoding="utf-8")
        _echo("policy.json updated (the old one is kept as policy.json.bak)")
    elif policy_path.exists():
        _echo("policy.json already exists: left unchanged "
              "(use --update-policy to get the newest starter policy)")
    else:
        policy_path.write_text(text, encoding="utf-8")
        _echo("wrote policy.json: the browser extension may save and prepare text for ChatGPT, "
              "Claude and Gemini (private details hidden, secrets blocked); everything else is denied")
    _echo(f"vault ready at {root}" + ("" if had_token else "; token created (thread token show)"))


@token_app.command("show")
def token_show(ctx: typer.Context) -> None:
    """Print the extension token. Paste it into the extension options; treat it like a password."""
    typer.echo(serve_mod.ensure_token(vault_root(ctx.obj)))


@app.command()
def serve(ctx: typer.Context,
          port: Annotated[int, typer.Option(help="Port on 127.0.0.1")] = 8765,
          origin: Annotated[list[str] | None, typer.Option(
              help="Pre-approve an extension origin (normally not needed: use Connect)")] = None,
          ) -> None:
    """Run the local ingest service the browser extension saves to (127.0.0.1 only)."""
    root = vault_root(ctx.obj)
    origins = set(origin or [])
    for o in origins:
        if not serve_mod.valid_origin(o):
            raise _fail("origin must look like chrome-extension://<id> or moz-extension://<id>")
    policy, problems = serve_mod.load_policy(root)
    if policy is None:
        _echo("warning: no usable policy.json, so every request will be refused "
              "(run `thread init`): " + "; ".join(problems))
    try:
        # Changes made from the vault pages (merge, delete, forget, sweep) are logged as the "ui".
        server = serve_mod.serve(open_vault(ctx.obj, actor=("vault-page", "ui")), policy,
                                 open_log(ctx.obj),
                                 serve_mod.ensure_token(root), origins, port, root)
    except OSError:
        raise _fail("cannot listen on that port (in use?)") from None
    server.start_sweeper()
    _echo(f"serving on http://127.0.0.1:{server.server_address[1]}  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _echo("stopped")
    finally:
        server.server_close()


def _alive(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/health", timeout=1.5) as r:
            return bool(r.status == 200)
    except OSError:
        return False


@app.command("open")
def open_vault_pages(ctx: typer.Context,
                     port: Annotated[int, typer.Option(help="Port of the running service")] = 8765,
                     ) -> None:
    """Open your saved threads in the browser (a readable page: no terminal needed after this)."""
    root = vault_root(ctx.obj)
    if not _alive(port):
        raise _fail("the vault service is not running: run `thread setup` once (starts it "
                    "automatically), or `thread serve`")
    url = f"http://127.0.0.1:{port}/s/{serve_mod.make_login_code(root)}"
    _echo("opening your saved threads in the browser...")
    if not webbrowser.open(url):
        _echo("could not open a browser; open this link yourself (works once, for 2 minutes):")
        _echo(url)


@app.command()
def setup(ctx: typer.Context,
          port: Annotated[int, typer.Option(help="Port on 127.0.0.1")] = 8765,
          yes: Annotated[bool, typer.Option("--yes", help="Do not ask questions")] = False,
          remove: Annotated[bool, typer.Option("--remove", help="Undo the automatic start")] = False,
          ) -> None:
    """One-time setup: create the vault, start the service at every login, open your threads."""
    if remove:
        try:
            _echo(autostart.remove())
        except autostart.AutostartError as e:
            raise _fail(str(e)) from None
        return
    init(ctx)
    root = vault_root(ctx.obj)
    if not autostart.supported():
        _echo("Automatic start is not available here. Start the service yourself with "
              "`thread serve` whenever you want to save from the browser.")
    elif yes or typer.confirm("Start threadvault automatically when you log in? "
                              "(runs only on this computer, no administrator rights)", default=True):
        try:
            _echo(autostart.install(root, port))
        except autostart.AutostartError as e:
            raise _fail(f"could not set up automatic start: {e}") from None
        for _ in range(20):
            if _alive(port):
                break
            time.sleep(0.5)
    if _alive(port):
        _echo("The vault service is running.")
        _echo("Next: install the browser extension, click its icon and press "
              "'Connect to my vault'. To see saved threads later: click the icon, then "
              "'Open my saved threads' (or run `thread open`).")
    else:
        _echo("The service is not running yet: run `thread serve` in a terminal.")


@file_app.command("add")
def file_add(ctx: typer.Context, thread_id: str, path: Path,
             yes: Annotated[bool, typer.Option("--yes", help="Attach even if hidden details may remain")
                            ] = False) -> None:
    """Attach a file of yours to a thread. Hidden details (photo location, author) are removed."""
    try:
        raw = path.read_bytes() if path.stat().st_size <= attach.MAX_FILE_BYTES else None
    except OSError:
        raise _fail("file not found or unreadable") from None
    if raw is None:
        raise _fail("file too large")
    prepared = attach.prepare(raw, attach.clean_name(path.name))
    if not prepared.complete:
        _echo("This file may still contain hidden details the cleaner cannot remove:")
        for n in prepared.notes:
            _echo("  - " + n)
        if not yes and not typer.confirm("Attach it anyway?", default=False):
            raise _fail("not attached")
    try:
        ref = _vault(ctx).put_file(thread_id, attach.clean_name(path.name), prepared.media_type,
                                   prepared.cleaned)
    except (KeyError, ValueError):
        raise _fail("no such thread") from None
    _echo(f"attached {ref['name']} ({ref['size']} bytes) to {thread_id}")


@app.command()
def merge(ctx: typer.Context, source: str, target: str) -> None:
    """Move the files of a files-only thread into another thread, then remove the empty one."""
    try:
        moved = _vault(ctx).merge_files(source, target)
    except KeyError:
        raise _fail("no such thread") from None
    except ValueError as e:
        raise _fail(str(e)) from None
    _echo(f"moved {moved} file(s) into {target}; {source} was removed")


def _find_file(vault: Vault, thread_id: str, which: str) -> str:
    """A file of a thread by name or by sha256; refuses when a name is ambiguous."""
    files = vault.load_thread(thread_id).manifest["files"]
    hits = [f for f in files if which in (f["sha256"], f["name"])]
    if not hits:
        raise _fail("no such file in that thread (see `thread show`)")
    if len({f["sha256"] for f in hits}) > 1:
        raise _fail("several files have that name: use the sha256 from `thread show`")
    return str(hits[0]["sha256"])


@app.command()
def forget(ctx: typer.Context, thread_id: str, file: str,
           yes: Annotated[bool, typer.Option("--yes", help="Do not ask")] = False) -> None:
    """Delete a file everywhere (every thread that holds it) and leave a note in the history."""
    vault = _vault(ctx)
    try:
        sha = _find_file(vault, thread_id, file)
    except KeyError:
        raise _fail("no such thread") from None
    if not yes and not typer.confirm("Delete this file from EVERY thread that has it? "
                                     "This cannot be undone.", default=False):
        raise _fail("not deleted")
    vault.forget_file(sha)
    _echo(f"forgotten: {sha}")


@app.command()
def delete(ctx: typer.Context, thread_id: str,
           yes: Annotated[bool, typer.Option("--yes", help="Do not ask")] = False) -> None:
    """Delete a whole thread now. Files no other thread uses are deleted with it."""
    if not yes and not typer.confirm(f"Delete {thread_id} and everything in it? This cannot be "
                                     "undone.", default=False):
        raise _fail("not deleted")
    try:
        _vault(ctx).delete_thread(thread_id)
    except (KeyError, ValueError):
        raise _fail("no such thread") from None
    _echo(f"deleted {thread_id}")


@app.command()
def expire(ctx: typer.Context, thread_id: str,
           in_: Annotated[str | None, typer.Option("--in", help="Delete after this long: 12h, 7d, 2w")] = None,
           at: Annotated[str | None, typer.Option(help="Delete at this time, e.g. 2026-12-01T09:00:00Z")] = None,
           never: Annotated[bool, typer.Option("--never", help="Remove the expiry")] = False,
           file: Annotated[str | None, typer.Option(help="Apply to one file (name or sha256) instead")] = None,
           ) -> None:
    """Make a thread (or one file) delete itself later. Needs the service running, or `thread sweep`."""
    if sum([in_ is not None, at is not None, never]) != 1:
        raise _fail("give exactly one of --in, --at or --never")
    try:
        when = None if never else (lifecycle.expires_in(in_) if in_ else at)
    except lifecycle.BadDuration as e:
        raise _fail(str(e)) from None
    vault = _vault(ctx)
    try:
        if file:
            vault.set_file_expiry(thread_id, _find_file(vault, thread_id, file), when)
        else:
            vault.set_expiry(thread_id, when)
    except KeyError:
        raise _fail("no such thread or file") from None
    except ValueError:
        raise _fail("that is not a valid time") from None
    _echo("expiry removed" if when is None else f"will be deleted at {when}")


@app.command()
def sweep(ctx: typer.Context) -> None:
    """Delete everything whose expiry time has passed (the running service does this by itself)."""
    _echo(f"removed {_vault(ctx).sweep_expired()} expired thread(s) and file(s)")


@app.command("log")
def access_log(ctx: typer.Context,
               thread_id: Annotated[str | None, typer.Option("--thread", help="Only this thread")] = None,
               limit: Annotated[int, typer.Option(help="Newest entries to show")] = 40,
               denied: Annotated[bool, typer.Option("--denied", help="Only refused requests")] = False,
               ) -> None:
    """Show who opened or changed what and when (the append-only access log) and whether it is intact."""
    log = FileAccessLog(vault_root(ctx.obj) / "access.jsonl")
    entries = filter_entries(log.entries(), thread_id=thread_id, outcome="denied" if denied else None)
    _echo(format_entries(entries, issues=log.verify(), limit=limit))


# -- policy: who may do what ------------------------------------------------------------------------
CAPABILITIES = ("read", "append", "file_read", "save_handover", "export", "forget", "network")


def _policy_doc(ctx: typer.Context) -> tuple[Path, dict[str, Any]]:
    path = vault_root(ctx.obj) / "policy.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise _fail("no usable policy.json here: run `thread init` first") from None
    return path, doc


def _write_policy(path: Path, doc: dict[str, Any]) -> None:
    problems = check_policy(doc)
    if problems:
        raise _fail("that change would make policy.json invalid: " + "; ".join(problems[:3]))
    path.replace(path.with_suffix(".json.bak"))
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


@policy_app.command("show")
def policy_show(ctx: typer.Context) -> None:
    """Show which clients may do what, and where data may be sent. Everything else is denied."""
    _, doc = _policy_doc(ctx)
    for problem in check_policy(doc):
        _echo(f"PROBLEM: {problem}")
    _echo("Clients (default deny: anyone not listed gets nothing):")
    for c in doc["clients"]:
        _echo(f"  {c['client_id']}: {', '.join(c['capabilities']) or '(nothing)'}")
    _echo("Destinations (where text may be prepared or sent):")
    for d in doc["destinations"]:
        hosts = f"  hosts: {', '.join(d.get('allow_hosts', []))}" if d.get("allow_hosts") else ""
        prof = doc["profiles"].get(d["profile"], {})
        extra = "  blocks secrets" if prof.get("block_on_secrets") else ""
        _echo(f"  {d['destination_id']} ({d['kind']}, profile {d['profile']}){hosts}{extra}")


@policy_app.command("allow")
def policy_allow(ctx: typer.Context, client: str, capabilities: list[str]) -> None:
    """Give a client capabilities: read append file_read save_handover export forget network."""
    bad = [c for c in capabilities if c not in CAPABILITIES]
    if bad:
        raise _fail(f"unknown capability: {bad[0]} (choose from {', '.join(CAPABILITIES)})")
    path, doc = _policy_doc(ctx)
    entry = next((c for c in doc["clients"] if c["client_id"] == client), None)
    if entry is None:
        entry = {"client_id": client, "capabilities": []}
        doc["clients"].append(entry)
    entry["capabilities"] = sorted(set(entry["capabilities"]) | set(capabilities))
    _write_policy(path, doc)
    _echo(f"{client} may now: {', '.join(entry['capabilities'])}  (old policy kept as policy.json.bak)")


@policy_app.command("revoke")
def policy_revoke(ctx: typer.Context, client: str, capabilities: Annotated[
        list[str] | None, typer.Argument(help="Capabilities to remove (default: all)")] = None) -> None:
    """Take capabilities away from a client (all of them if none are named)."""
    path, doc = _policy_doc(ctx)
    entry = next((c for c in doc["clients"] if c["client_id"] == client), None)
    if entry is None:
        raise _fail("that client is not in the policy (so it already has nothing)")
    if capabilities:
        entry["capabilities"] = [c for c in entry["capabilities"] if c not in capabilities]
    else:
        doc["clients"].remove(entry)
    _write_policy(path, doc)
    _echo(f"updated {client}  (old policy kept as policy.json.bak)")


# -- plugins: pinned by hash --------------------------------------------------------------------------
def _pins_path(ctx: typer.Context) -> Path:
    return vault_root(ctx.obj) / "plugins.json"


def _load_pins_doc(ctx: typer.Context) -> dict[str, Any]:
    path = _pins_path(ctx)
    if not path.exists():
        return {"format": PINS_FORMAT, "plugins": []}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        Pins.parse(doc)
    except (OSError, ValueError, PluginRefused):
        raise _fail("plugins.json is damaged: no plugin will be loaded until it is fixed") from None
    return dict(doc)


@plugin_app.command("pin")
def plugin_pin(ctx: typer.Context, name: str, path: Path,
               note: Annotated[str, typer.Option(help="What it is, for you")] = "",
               yes: Annotated[bool, typer.Option("--yes", help="Do not ask")] = False) -> None:
    """Trust exactly this plugin file. If the file ever changes, it will be refused."""
    try:
        entry = pin_entry(name, path, note)
    except PluginRefused as e:
        raise _fail(str(e)) from None
    _echo(f"{name}: {entry['sha256']}")
    if not yes and not typer.confirm("You are about to trust this exact code to run with access to "
                                     "your vault. Have you read it?", default=False):
        raise _fail("not pinned")
    doc = _load_pins_doc(ctx)
    doc["plugins"] = [p for p in doc["plugins"] if p["name"] != name] + [entry]
    _pins_path(ctx).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    _echo(f"pinned. It still needs capabilities: thread policy allow plugin:{name} read ...")


@plugin_app.command("list")
def plugin_list(ctx: typer.Context) -> None:
    """Show the pinned plugins."""
    plugins = _load_pins_doc(ctx)["plugins"]
    if not plugins:
        _echo("no plugins are pinned, so none can load")
    for p in plugins:
        _echo(f"{p['name']}  {p['sha256']}  {p.get('note', '')}")


@plugin_app.command("check")
def plugin_check(ctx: typer.Context, name: str, path: Path) -> None:
    """Does this file still match what you pinned? Exit code 1 if not."""
    pins = Pins.parse(_load_pins_doc(ctx))
    try:
        data = path.read_bytes()
    except OSError:
        raise _fail("cannot read that file") from None
    decision = pins.check(name, data)
    _echo(("ok: " if decision.allowed else "REFUSED: ") + decision.reason)
    if not decision.allowed:
        raise typer.Exit(1)


@plugin_app.command("unpin")
def plugin_unpin(ctx: typer.Context, name: str) -> None:
    """Stop trusting a plugin."""
    doc = _load_pins_doc(ctx)
    if not any(p["name"] == name for p in doc["plugins"]):
        raise _fail("that plugin is not pinned")
    doc["plugins"] = [p for p in doc["plugins"] if p["name"] != name]
    _pins_path(ctx).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    _echo(f"{name} is no longer trusted")


# -- Claude Desktop (MCP) and a second opinion ----------------------------------------------------------
@app.command()
def mcp(ctx: typer.Context,
        client: Annotated[str, typer.Option(help="Policy client id")] = "claude-desktop",
        destination: Annotated[str, typer.Option(help="Policy destination id")] = "claude") -> None:
    """Run the connector that lets Claude Desktop read and save in your vault (started by it)."""
    from threadvault.connector import mcp_server

    mcp_server.run(vault_root(ctx.obj), client, destination)


@app.command("mcp-config")
def mcp_config(ctx: typer.Context,
               allow: Annotated[bool, typer.Option(
                   "--allow", help="Also let Claude Desktop read, append and save handovers")] = False,
               ) -> None:
    """Print the Claude Desktop setting that connects it to your vault (and optionally allow it)."""
    import sys as _sys

    root = vault_root(ctx.obj)
    command = str(Path(_sys.executable).parent / "thread")
    cfg = {"mcpServers": {"threadvault": {"command": command, "args": ["--vault", str(root), "mcp"]}}}
    _echo("Add this to Claude Desktop's config file (Settings > Developer > Edit Config):")
    _echo(json.dumps(cfg, indent=2))
    if allow:
        policy_allow(ctx, "claude-desktop", ["read", "append", "save_handover"])
    else:
        _echo("Claude Desktop gets nothing until you allow it:  thread policy allow claude-desktop "
              "read append save_handover   (or re-run with --allow). Handovers still ask you first.")


@app.command()
def ask(ctx: typer.Context, thread_id: str, branch: str, question: str,
        model: Annotated[str, typer.Option(help="e.g. openai/gpt-5 or anthropic/claude-sonnet-4-5")],
        to: Annotated[str, typer.Option(help="Destination in policy.json: openai or anthropic")] = "openai",
        ) -> None:
    """Ask a second AI the same question on a fork (private details hidden first). Needs API keys
    in your environment, the `llm` extra, and: thread policy allow second-ai read append network."""
    from threadvault.agent.second_ai import SecondAI, SecondAIError

    vault = _vault(ctx)
    policy = load_policy(ctx.obj)
    if policy is None:
        raise _fail("no usable policy.json: run `thread init`")
    try:
        out = SecondAI(vault, policy, open_log(ctx.obj)).ask(
            thread_id, branch, question, destination_id=to, model=model)
    except SecondAIError as e:
        raise _fail(f"refused: {e}") from None
    _echo(out.answer)
    if out.hidden:
        _echo("(hidden before sending: " + ", ".join(f"{n} {k}" for k, n in out.hidden.items()) + ")")
    for w in out.warnings:
        _echo(f"warning: {w}")
