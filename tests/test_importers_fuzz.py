"""Fuzzing (THREAT_MODEL T9): hostile input may be refused, but must never crash or hang."""

import json
import tempfile
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from threadvault.importers import chatgpt, claude, gemini, markdown
from threadvault.importers.base import ImportRefused

leaf = st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=50)
jsonish = st.recursive(leaf, lambda c: st.lists(c, max_size=5) | st.dictionaries(
    st.sampled_from(["mapping", "current_node", "parent", "message", "author", "role", "content",
                     "parts", "chat_messages", "sender", "text", "title", "time", "safeHtmlItem",
                     "html", "create_time", "created_at", "name", "a", "b"]), c, max_size=6),
    max_leaves=40)
FUZZ = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def run(fn: Any, data: Any) -> None:
    try:
        threads = fn(data)
    except ImportRefused:
        return
    for t in threads:
        assert all(0 < len(m.content) <= 200_000 for m in t.messages)
        json.dumps([m.model_dump() for m in t.messages])  # serialisable, no floats in records


def via_file(loader: Any, data: Any) -> None:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "conversations.json"
        p.write_text(json.dumps(data))
        run(lambda _: loader(p), None)


@FUZZ
@given(jsonish)
def test_chatgpt_fuzz(data: Any) -> None:
    via_file(chatgpt.import_chatgpt, data)
    if isinstance(data, dict):
        run(lambda d: [chatgpt.parse_conversation(d)], data)


@FUZZ
@given(jsonish)
def test_claude_fuzz(data: Any) -> None:
    via_file(claude.import_claude, data)
    if isinstance(data, dict):
        run(lambda d: [claude.parse_conversation(d)], data)


@FUZZ
@given(jsonish)
def test_gemini_fuzz(data: Any) -> None:
    via_file(gemini.import_gemini, data)


@FUZZ
@given(st.text(max_size=2000))
def test_markdown_and_html_fuzz(text: str) -> None:
    run(lambda t: [markdown.parse_markdown(t)], text)
    assert isinstance(gemini.html_to_text(text), str)
