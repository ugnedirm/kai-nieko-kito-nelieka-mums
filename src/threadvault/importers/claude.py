"""Claude data-export importer (`conversations.json` in the export, bare or zipped)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from threadvault.importers.base import (
    MAX_NODES_PER_CONVERSATION,
    ImportedThread,
    ImportRefused,
    Stats,
    as_object_list,
    clean_title,
    iso_timestamp,
    load_json,
    make_message,
)

_ROLE = {"human": "user", "assistant": "assistant"}
_EPOCH = "1970-01-01T00:00:00Z"


def import_claude(path: Path) -> list[ImportedThread]:
    return [parse_conversation(c) for c in as_object_list(load_json(path, "conversations.json"))]


def parse_conversation(conv: dict[str, Any]) -> ImportedThread:
    msgs = conv.get("chat_messages")
    if not isinstance(msgs, list):
        raise ImportRefused("unexpected_shape", "conversation has no chat_messages")
    if len(msgs) > MAX_NODES_PER_CONVERSATION:
        raise ImportRefused("conversation_too_large")
    stats, out, ts = Stats(), [], iso_timestamp(conv.get("created_at"), _EPOCH)
    for m in msgs:
        if not isinstance(m, dict):
            stats.skipped += 1
            continue
        sender = m.get("sender")
        role = _ROLE.get(sender) if isinstance(sender, str) else None
        ts = iso_timestamp(m.get("created_at"), ts)
        made = make_message(role or "", _text(m), ts, stats, provider="anthropic") if role else None
        if role is None:
            stats.skipped += 1
        if made:
            out.append(made)
    title = clean_title(conv.get("name"), "Imported Claude conversation", stats)
    return ImportedThread(title=title, source="claude", messages=out, warnings=stats.warnings())


def _text(m: dict[str, Any]) -> str:
    """Text blocks only; tool use, attachments and thinking blocks are not imported."""
    content = m.get("content")
    if isinstance(content, list):
        parts = [b["text"] for b in content
                 if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)]
        if parts:
            return "\n".join(parts)
    text = m.get("text")
    return text if isinstance(text, str) else ""
