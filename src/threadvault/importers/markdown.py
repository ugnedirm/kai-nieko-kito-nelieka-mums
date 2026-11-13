"""Markdown / plain-text transcript importer.

A line that is only a speaker label starts a new message: `User:`, `## Assistant`, `**Human**:`
(case-insensitive; user/human, assistant/ai/claude/chatgpt/gemini, system). With no labels the
whole file becomes one user message. Nothing here is interpreted as Markdown or HTML.
"""

from __future__ import annotations

import re
from pathlib import Path

from threadvault.importers.base import (
    ImportedThread,
    ImportRefused,
    Stats,
    clean_title,
    make_message,
    read_text_file,
)

_EPOCH = "1970-01-01T00:00:00Z"
_ROLES = {"user": "user", "human": "user", "me": "user", "assistant": "assistant",
          "ai": "assistant", "claude": "assistant", "chatgpt": "assistant",
          "gemini": "assistant", "system": "system"}
_LABEL = re.compile(r"^\s*(?:#{1,6}\s*)?(?:\*\*|__)?([A-Za-z]{2,10})(?:\*\*|__)?\s*:?\s*(?:\*\*|__)?\s*$|"
                    r"^\s*(?:#{0,6}\s*)?(?:\*\*|__)?([A-Za-z]{2,10})(?::\s*(?:\*\*|__)?|(?:\*\*|__)?:)\s*(.*)$")


def parse_markdown(text: str, title: str = "Imported transcript") -> ImportedThread:
    stats = Stats()
    blocks: list[tuple[str, list[str]]] = []
    for line in text.splitlines():
        role, rest = _label(line)
        if role:
            blocks.append((role, [rest] if rest else []))
        elif blocks:
            blocks[-1][1].append(line)
        else:
            blocks.append(("user", [line]))
    out = [m for role, lines in blocks
           if (m := make_message(role, "\n".join(lines).strip(), _EPOCH, stats,
                                 provider="unknown" if role == "assistant" else None))]
    title = clean_title(title, "Imported transcript", stats)
    return ImportedThread(title=title, source="markdown", messages=out, warnings=stats.warnings())


def _label(line: str) -> tuple[str | None, str]:
    if len(line) > 400:
        return None, ""
    m = _LABEL.match(line)
    if not m:
        return None, ""
    word = (m.group(1) or m.group(2) or "").lower()
    role = _ROLES.get(word)
    # A bare word without markers or a colon ("Me", "AI") is ordinary text, not a label.
    if role and (m.group(2) or line.strip().startswith(("#", "*", "_")) or ":" in line):
        return role, (m.group(3) or "").strip()
    return None, ""


def import_markdown(path: Path) -> list[ImportedThread]:
    thread = parse_markdown(read_text_file(path), title=path.stem or "Imported transcript")
    if not thread.messages:
        raise ImportRefused("empty_import")
    return [thread]
