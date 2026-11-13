"""Shared pieces for importers. Every import file is untrusted input (THREAT_MODEL T9).

Errors raised here never contain file content: only a short reason code and a location.
"""

from __future__ import annotations

import json
import unicodedata
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

MAX_ARCHIVE_BYTES = 200 * 1024 * 1024  # compressed file on disk
MAX_JSON_BYTES = 100 * 1024 * 1024  # decompressed conversations file
MAX_JSON_DEPTH = 64
MAX_CONVERSATIONS = 10_000
MAX_NODES_PER_CONVERSATION = 50_000
MAX_MESSAGE_CHARS = 200_000  # message.schema.json maxLength
MAX_TITLE_CHARS = 200


class ImportRefused(Exception):
    """Import refused. `code` is stable and safe to show; the message holds no file content."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


class ImportedMessage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    role: str  # user | assistant | system | tool
    author: dict[str, str]
    created_at: str  # RFC 3339, UTC, whole seconds (no floats are ever stored)
    content: str


class ImportedThread(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    title: str
    source: str  # e.g. "chatgpt"
    messages: list[ImportedMessage]
    warnings: list[str] = []  # codes and counts only, never content


# Characters that hide text from a human reader but not from an AI. Dropped on import:
#  - all format characters (Unicode category Cf: tag characters, bidi controls, zero-width,
#    soft hyphen, invisible operators), EXCEPT ZWJ/ZWNJ, which emoji and several scripts need;
#  - variation selectors, EXCEPT U+FE0E/U+FE0F (text/emoji presentation);
#  - lone surrogates (they cannot be encoded as UTF-8) and control characters (except \n, \t).
# Code points are used instead of literals so no invisible character appears in this source.
_KEEP_FORMAT = {0x200C, 0x200D}
_KEEP_VS = {0xFE0E, 0xFE0F}


def is_hidden(ch: str) -> bool:
    cp = ord(ch)
    if ch in "\n\t":
        return False
    cat = unicodedata.category(ch)
    if cat == "Cf":
        return cp not in _KEEP_FORMAT
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return cp not in _KEEP_VS
    return cat in {"Cc", "Cs"}


def clean_text(text: str) -> tuple[str, int]:
    """Strip hidden characters and non-printing controls. Returns (text, number removed)."""
    text = unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n"))
    kept = [ch for ch in text if not is_hidden(ch)]
    return "".join(kept), len(text) - len(kept)


def clean_title(raw: object, default: str, stats: Stats) -> str:
    """Titles come from the file (or the file name): same cleaning, one line, capped."""
    text, hidden = clean_text(raw if isinstance(raw, str) else "")
    stats.stripped += hidden
    text = " ".join(text.split())[:MAX_TITLE_CHARS]
    return text or default


def iso_timestamp(value: Any, fallback: str) -> str:
    """RFC 3339 UTC with whole seconds from an ISO-8601 string; `fallback` if unusable."""
    if not isinstance(value, str) or len(value) > 64:
        return fallback
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return fallback
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def as_object_list(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, list):
        raise ImportRefused("unexpected_shape", "top level is not a list")
    if len(data) > MAX_CONVERSATIONS:
        raise ImportRefused("too_many_conversations")
    return [c for c in data if isinstance(c, dict)]


def read_text_file(path: Path) -> str:
    """Capped UTF-8 read for plain-text sources (invalid bytes are replaced)."""
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            raise ImportRefused("file_too_large")
        return path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        raise ImportRefused("unreadable") from None


def load_json(path: Path, member: str | None = None,
              member_suffix: str | None = None) -> Any:
    """Safely load JSON from a file or from ONE named member of a zip (never extracted).

    `member` is an exact member name; `member_suffix` matches the one member whose name ends with
    it (for Takeout layouts). Sizes are capped on the bytes actually read, nesting depth is capped,
    NaN/Infinity are refused.
    """
    try:
        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ImportRefused("file_too_large")
        with path.open("rb") as f:
            head = f.read(4)
    except OSError:
        raise ImportRefused("unreadable") from None
    if head.startswith(b"PK"):
        raw = _read_zip_member(path, member, member_suffix)
    else:
        with path.open("rb") as f:
            raw = f.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            raise ImportRefused("file_too_large")
    return _parse_json(raw)


def _read_zip_member(path: Path, member: str | None, suffix: str | None) -> bytes:
    try:
        with zipfile.ZipFile(path) as z:
            names = [n for n in z.namelist()
                     if (member is not None and n == member)
                     or (suffix is not None and n.endswith(suffix))]
            if len(names) != 1:
                raise ImportRefused("missing_member" if not names else "ambiguous_member")
            info = z.getinfo(names[0])
            if info.file_size > MAX_JSON_BYTES:
                raise ImportRefused("file_too_large")
            with z.open(info) as f:
                raw = f.read(MAX_JSON_BYTES + 1)  # header sizes can lie: cap the real read
    except zipfile.BadZipFile:
        raise ImportRefused("bad_archive") from None
    except (OSError, RuntimeError, NotImplementedError):
        raise ImportRefused("unreadable") from None
    if len(raw) > MAX_JSON_BYTES:
        raise ImportRefused("file_too_large")
    return raw


def _parse_json(raw: bytes) -> Any:
    try:
        data = json.loads(raw, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise ImportRefused("invalid_json") from None
    if _too_deep(data):
        raise ImportRefused("json_too_deep")
    return data


def _reject_constant(_: str) -> Any:
    raise ValueError("NaN/Infinity not allowed")


def _too_deep(data: Any) -> bool:
    stack: list[tuple[Any, int]] = [(data, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict | list):
            if depth > MAX_JSON_DEPTH:
                return True
            children = item.values() if isinstance(item, dict) else item
            stack.extend((c, depth + 1) for c in children)
    return False


AUTHOR_KIND = {"user": "human", "assistant": "ai", "system": "system", "tool": "tool"}


class Stats:
    """Counts only (never content) of what an importer dropped or changed."""

    def __init__(self) -> None:
        self.skipped = self.truncated = self.stripped = 0

    def warnings(self) -> list[str]:
        pairs = (("skipped_messages", self.skipped), ("truncated_messages", self.truncated),
                 ("stripped_hidden_chars", self.stripped))
        return [f"{name}:{n}" for name, n in pairs if n]


def make_message(role: str, text: str, created_at: str, stats: Stats,
                 provider: str | None = None, model: str | None = None) -> ImportedMessage | None:
    """Clean, cap and wrap one message. Returns None (and counts it) if nothing is left."""
    text, hidden = clean_text(text)
    stats.stripped += hidden
    if not text.strip() or role not in AUTHOR_KIND:
        stats.skipped += 1
        return None
    if len(text) > MAX_MESSAGE_CHARS:
        text, stats.truncated = text[:MAX_MESSAGE_CHARS], stats.truncated + 1
    author = {"kind": AUTHOR_KIND[role]}
    if role == "assistant" and provider:
        author["provider"] = provider
        if model:
            author["model"] = model[:128]
    return ImportedMessage(role=role, author=author, created_at=created_at, content=text)
