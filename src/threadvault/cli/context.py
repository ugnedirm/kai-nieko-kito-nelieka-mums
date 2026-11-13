"""The one place the CLI decides which `Vault` implementation to use.

Person A's real on-disk vault replaces `open_vault`. Until then the CLI runs on the in-memory
`FixtureVault`, so writes do NOT persist between invocations.
"""

from __future__ import annotations

import json
from pathlib import Path

from threadvault import schemas
from threadvault.core.accesslog import AccessLog, MemoryAccessLog
from threadvault.core.vault import FixtureVault, Vault
from threadvault.types import Record


def open_vault(path: Path | None) -> Vault:
    return FixtureVault(path) if path else FixtureVault()


def load_policy(path: Path | None) -> Record | None:
    """policy.json of the vault directory, or None (default deny) if absent or invalid."""
    if path is None:
        return None
    try:
        policy = json.loads((path / "policy.json").read_text())
    except (OSError, ValueError):
        return None
    return policy if not schemas.errors("policy", policy) else None


def open_log() -> AccessLog:
    return MemoryAccessLog()  # A swaps in the append-only file log
