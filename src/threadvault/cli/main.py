"""`thread` command line. Depends on the `Vault` Protocol only (see cli/context.py)."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from threadvault import schemas
from threadvault.agent.handover import parse_reply
from threadvault.cli.context import load_policy, open_log, open_vault
from threadvault.cli.redact import ExportRefused, apply_profile
from threadvault.cli.safe import terminal_safe
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
    log = open_log()
    if profile is None:
        log.record(client_id="cli", kind="human", action="export", outcome="denied",
                   thread_id=thread_id, detail="destination not allowed")
        raise _fail("destination not in policy: refused")
    try:
        text = apply_profile(_vault(ctx).pack(thread_id, max_tokens), profile)
    except KeyError:
        raise _fail("no such thread") from None
    except ExportRefused as e:
        log.record(client_id="cli", kind="human", action="export", outcome="denied",
                   thread_id=thread_id, detail="blocked by profile")
        raise _fail(str(e)) from None
    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        raise _fail("cannot create output file (does it already exist?)") from None
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    log.record(client_id="cli", kind="human", action="export", outcome="allowed",
               thread_id=thread_id, detail=f"destination={destination[:64]}")
    _echo(f"exported to {out}")
