"""Shared helpers for Person A's tests. No network, no OS keychain: keys live in MemoryKeyStore."""

from __future__ import annotations

import itertools
import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from threadvault.core.disk import DiskVault
from threadvault.core.pack import approx_tokens
from threadvault.core.signing import MemoryKeyStore

FIXTURE_VAULT = Path(__file__).parent / "fixtures" / "vault"
HUMAN = {"kind": "human"}
AI = {"kind": "ai", "provider": "anthropic", "model": "claude-example"}


def make_clock() -> Callable[[], str]:
    """Deterministic clock: one second per call."""
    counter = itertools.count()

    def clock() -> str:
        n = next(counter)
        return f"2026-11-14T{n // 3600 % 24:02d}:{n // 60 % 60:02d}:{n % 60:02d}Z"

    return clock


def message(content: str = "hello", **over: Any) -> dict[str, Any]:
    return {"type": "message", "role": "user", "author": HUMAN, "created_at": "2026-11-14T09:00:00Z",
            "content": content, "provenance": "user-asserted", **over}


def handover_content(fact: str = "Budget is 1200 EUR", files: list[dict[str, Any]] | None = None
                     ) -> dict[str, Any]:
    return {"decisions": [{"text": "Use Typer"}], "open_questions": [], "next_steps": [],
            "key_facts": [{"text": fact, "source_note": "stated by user"}],
            "files": files or [], "constraints": [], "uncertain": []}


def handover(fact: str = "Budget is 1200 EUR", files: list[dict[str, Any]] | None = None
             ) -> dict[str, Any]:
    return {"type": "handover", "content": handover_content(fact, files),
            "metadata": {"author": AI, "created_at": "2026-11-14T09:00:00Z", "prompt_version": "1",
                         "provenance": "ai-summary-user-saved",
                         "thread_state": {"source": "live-chat", "user_reviewed": True}}}


@pytest.fixture
def vault(tmp_path: Path) -> DiskVault:
    return DiskVault(tmp_path / "vault", clock=make_clock(), token_counter=approx_tokens)


@pytest.fixture
def keystore() -> MemoryKeyStore:
    return MemoryKeyStore()


@pytest.fixture
def signed_vault(tmp_path: Path, keystore: MemoryKeyStore) -> DiskVault:
    return DiskVault(tmp_path / "vault", keystore=keystore, clock=make_clock(),
                     token_counter=approx_tokens)


@pytest.fixture
def fixture_vault(tmp_path: Path) -> Iterator[DiskVault]:
    """A writable copy of the committed sample vault."""
    root = tmp_path / "sample"
    shutil.copytree(FIXTURE_VAULT, root)
    yield DiskVault(root, clock=make_clock(), token_counter=approx_tokens)
