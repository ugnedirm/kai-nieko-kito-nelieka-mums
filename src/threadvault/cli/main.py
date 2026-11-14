"""`thread` command line. Depends on the `Vault` Protocol only (see cli/context.py)."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from threadvault import schemas
from threadvault.agent.handover import parse_reply
from threadvault.cli import serve as serve_mod
from threadvault.cli.context import load_policy, open_log, open_vault, vault_root
from threadvault.cli.redact import ExportRefused, apply_profile
from threadvault.cli.safe import terminal_safe
from threadvault.core.lineage import ForkError
from threadvault.core.render import handover_text
from threadvault.core.vault import Vault
from threadvault.importers import chatgpt, claude, gemini, markdown
from threadvault.importers.base import ImportedThread, ImportRefused
from threadvault.importers.scan import scan_import, summarize
from threadvault.importers.store import store_import
from threadvault.policy.engine import destination_profile
from threadvault.scanners.basic import scan_record
from threadvault.types import SECRET_KINDS

app = typer.Typer(help="threadvault: portable AI conversation threads", no_args_is_help=True)
import_app = typer.Typer(help="Import conversations from an export file", no_args_is_help=True)
app.add_typer(import_app, name="import")
token_app = typer.Typer(help="The token the browser extension uses", no_args_is_help=True)
app.add_typer(token_app, name="token")
handover_app = typer.Typer(help="Work with handovers", no_args_is_help=True)
app.add_typer(handover_app, name="handover")
MAX_REPLY_BYTES = 1024 * 1024

VaultOpt = Annotated[Path | None, typer.Option("--vault", envvar="THREADVAULT_DIR",
                                               help="Vault directory")]


def _vault(ctx: typer.Context) -> Vault:
    return open_vault(ctx.obj)


@app.callback()
def main(ctx: typer.Context, vault: VaultOpt = None) -> None:
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
    "clients": [{"client_id": "browser-extension", "capabilities": ["append", "save_handover"]}],
    "destinations": [{"destination_id": "local", "kind": "local", "profile": "open"}],
    "profiles": {
        "open": {"redact": [], "pseudonymize": False, "block_on_secrets": False,
                 "allow_attachments": True, "strip_file_metadata": False},
        "strict": {"redact": ["email", "phone", "api_key", "secret", "person"],
                   "pseudonymize": True, "block_on_secrets": True, "allow_attachments": False,
                   "strip_file_metadata": True}}}


@app.command()
def init(ctx: typer.Context) -> None:
    """Create the vault, its extension token and a starter policy.json (extension may save)."""
    root = vault_root(ctx.obj)
    _vault(ctx)  # creates the directory layout
    token_path = root / serve_mod.TOKEN_FILE
    had_token = token_path.exists()
    serve_mod.ensure_token(root)
    policy_path = root / "policy.json"
    if policy_path.exists():
        _echo("policy.json already exists: left unchanged")
    else:
        policy_path.write_text(json.dumps(STARTER_POLICY, indent=2) + "\n", encoding="utf-8")
        _echo("wrote policy.json: only 'browser-extension' may append and save handovers; "
              "every other client and destination is denied")
    _echo(f"vault ready at {root}" + ("" if had_token else "; token created (thread token show)"))


@token_app.command("show")
def token_show(ctx: typer.Context) -> None:
    """Print the extension token. Paste it into the extension options; treat it like a password."""
    typer.echo(serve_mod.ensure_token(vault_root(ctx.obj)))


@app.command()
def serve(ctx: typer.Context,
          port: Annotated[int, typer.Option(help="Port on 127.0.0.1")] = 8765,
          origin: Annotated[list[str] | None, typer.Option(
              help="Allowed extension origin, e.g. chrome-extension://<id> (repeatable)")] = None,
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
    if not origins:
        _echo("warning: no --origin given: requests carrying an Origin header will be refused")
    try:
        server = serve_mod.serve(_vault(ctx), policy, open_log(ctx.obj),
                                 serve_mod.ensure_token(root), origins, port)
    except OSError:
        raise _fail("cannot listen on that port (in use?)") from None
    _echo(f"serving on http://127.0.0.1:{server.server_address[1]}  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _echo("stopped")
    finally:
        server.server_close()
