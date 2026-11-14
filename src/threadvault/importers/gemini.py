"""Gemini importer for Google Takeout (`My Activity` > `Gemini Apps` > `MyActivity.json`).

Takeout stores each prompt with its answer as one activity entry; the answer is HTML. The HTML is
reduced to plain text by a parser that drops every tag, script and style; nothing is rendered.
Activity entries are not grouped into conversations, so they become ONE thread, oldest first.
"""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from threadvault.importers.base import (
    MAX_NODES_PER_CONVERSATION,
    ImportedThread,
    ImportRefused,
    Stats,
    as_object_list,
    iso_timestamp,
    load_json,
)
from threadvault.importers.base import make_message as _make

SUFFIX = "Gemini Apps/MyActivity.json"
_EPOCH = "1970-01-01T00:00:00Z"
_PREFIXES = ("Prompted ", "Said ")
_BLOCK = {"p", "div", "br", "li", "ul", "ol", "h1", "h2", "h3", "h4", "pre", "tr"}


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._skip += 1
        elif tag in _BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._skip:
            self._skip -= 1
        elif tag in _BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    p = _Text()
    try:
        p.feed(html)
        p.close()
    except Exception:  # noqa: BLE001 - malformed HTML must never abort an import
        return ""
    lines = "".join(p.parts).split("\n")
    return "\n".join(ln.strip() for ln in lines).strip()


def import_gemini(path: Path) -> list[ImportedThread]:
    data = load_json(path, "MyActivity.json", SUFFIX)
    entries = as_object_list(data)
    if len(entries) > MAX_NODES_PER_CONVERSATION:
        raise ImportRefused("conversation_too_large")
    stats, out = Stats(), []
    for e in sorted(entries, key=lambda e: str(e.get("time", ""))):
        ts = iso_timestamp(e.get("time"), _EPOCH)
        title = e.get("title")
        if isinstance(title, str):
            for pre in _PREFIXES:
                if title.startswith(pre):
                    title = title[len(pre):]
                    break
            if m := _make("user", title, ts, stats):
                out.append(m)
        if m := _make("assistant", _answer(e), ts, stats, provider="google"):
            out.append(m)
    if not out:
        raise ImportRefused("empty_import")
    return [ImportedThread(title="Imported Gemini activity", source="gemini", messages=out,
                           warnings=stats.warnings())]


def _answer(entry: dict[str, Any]) -> str:
    items = entry.get("safeHtmlItem")
    if not isinstance(items, list):
        return ""
    return "\n\n".join(html_to_text(i["html"]) for i in items
                       if isinstance(i, dict) and isinstance(i.get("html"), str))
