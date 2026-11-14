"""ChatGPT data-export importer (`conversations.json`, bare or inside the export .zip).

Hostile-input rules: size caps before and while decompressing, a nesting-depth cap, a node cap,
cycle-safe tree walk, only the single member named `conversations.json` is ever read (no
extraction, so no path traversal), no floats in the output. Text is data: it is never executed,
rendered or put in an error message.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from threadvault.importers.base import (
    MAX_MESSAGE_CHARS,
    MAX_NODES_PER_CONVERSATION,
    ImportedMessage,
    ImportedThread,
    ImportRefused,
    Stats,
    as_object_list,
    clean_text,
    clean_title,
    load_json,
)

MEMBER = "conversations.json"
ROLES = {"user", "assistant", "system", "tool"}
_AUTHOR_KIND = {"user": "human", "assistant": "ai", "system": "system", "tool": "tool"}
_EPOCH = "1970-01-01T00:00:00Z"


def load_conversations(path: Path) -> list[dict[str, Any]]:
    """Read the export and return the raw conversation objects (still untrusted)."""
    return as_object_list(load_json(path, MEMBER))


def import_chatgpt(path: Path) -> list[ImportedThread]:
    return [parse_conversation(c) for c in load_conversations(path)]


def parse_conversation(conv: dict[str, Any]) -> ImportedThread:
    mapping = conv.get("mapping")
    if not isinstance(mapping, dict):
        raise ImportRefused("unexpected_shape", "conversation has no mapping")
    if len(mapping) > MAX_NODES_PER_CONVERSATION:
        raise ImportRefused("conversation_too_large")
    warnings: list[str] = []

    # Follow the branch the user last saw: current_node up to the root. Seen-set stops cycles.
    chain: list[dict[str, Any]] = []
    seen: set[str] = set()
    node_id = conv.get("current_node")
    while isinstance(node_id, str) and node_id not in seen and node_id in mapping:
        seen.add(node_id)
        node = mapping[node_id]
        if not isinstance(node, dict):
            break
        chain.append(node)
        node_id = node.get("parent")
    if isinstance(node_id, str) and node_id in seen:
        warnings.append("cycle_in_tree")
    chain.reverse()

    messages: list[ImportedMessage] = []
    skipped = truncated = stripped = 0
    last_ts = _EPOCH
    for node in chain:
        msg = node.get("message")
        if not isinstance(msg, dict):
            continue
        role = _role(msg)
        text, hidden = clean_text(_text(msg.get("content")))
        stripped += hidden
        if role is None or not text.strip() or _hidden(msg):
            skipped += 1
            continue
        if len(text) > MAX_MESSAGE_CHARS:
            text, truncated = text[:MAX_MESSAGE_CHARS], truncated + 1
        last_ts = _timestamp(msg.get("create_time"), last_ts)
        author = {"kind": _AUTHOR_KIND[role]}
        if role == "assistant":
            author["provider"] = "openai"
            model = _model(msg)
            if model:
                author["model"] = model
        messages.append(ImportedMessage(role=role, author=author, created_at=last_ts, content=text))
    if skipped:
        warnings.append(f"skipped_messages:{skipped}")
    if truncated:
        warnings.append(f"truncated_messages:{truncated}")
    title_stats = Stats()
    title = clean_title(conv.get("title"), "Imported ChatGPT conversation", title_stats)
    stripped += title_stats.stripped
    if stripped:
        warnings.append(f"stripped_hidden_chars:{stripped}")
    return ImportedThread(title=title, source="chatgpt", messages=messages, warnings=warnings)


# -- helpers ---------------------------------------------------------------------------------
def _role(msg: dict[str, Any]) -> str | None:
    author = msg.get("author")
    role = author.get("role") if isinstance(author, dict) else None
    return role if isinstance(role, str) and role in ROLES else None


def _hidden(msg: dict[str, Any]) -> bool:
    meta = msg.get("metadata")
    return isinstance(meta, dict) and meta.get("is_visually_hidden_from_conversation") is True


def _model(msg: dict[str, Any]) -> str | None:
    meta = msg.get("metadata")
    slug = meta.get("model_slug") if isinstance(meta, dict) else None
    return slug[:128] if isinstance(slug, str) and slug else None


def _text(content: Any) -> str:
    """Only plain text parts are kept. Images, audio and other structured parts are dropped."""
    if not isinstance(content, dict):
        return ""
    parts = content.get("parts")
    if isinstance(parts, list):
        return "\n".join(p for p in parts if isinstance(p, str))
    text = content.get("text")
    return text if isinstance(text, str) else ""


def _timestamp(value: Any, fallback: str) -> str:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return fallback
    try:
        return datetime.fromtimestamp(int(value), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return fallback
