"""The one place the CLI decides which `Vault` implementation to use: the on-disk `DiskVault`.

The vault directory is `--vault`, else `$THREADVAULT_DIR`, else `~/.threadvault`.
Set `THREADVAULT_KEYCHAIN=1` to sign records with a key in the OS keychain (needs the `keychain`
extra); without it records are hash-chained but unsigned.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from threadvault import schemas
from threadvault.core.accesslog import AccessLog, FileAccessLog
from threadvault.core.disk import DiskVault
from threadvault.core.vault import Vault
from threadvault.types import Record


def vault_root(path: Path | None) -> Path:
    return path if path is not None else Path.home() / ".threadvault"


def open_vault(path: Path | None, actor: tuple[str, str] = ("cli", "cli")) -> Vault:
    keystore = None
    if os.environ.get("THREADVAULT_KEYCHAIN") == "1":
        from threadvault.core.signing import KeyringKeyStore

        keystore = KeyringKeyStore()
    return DiskVault(vault_root(path), keystore=keystore, actor=actor)


def load_policy(path: Path | None) -> Record | None:
    """policy.json of the vault directory, or None (default deny) if absent or invalid."""
    try:
        policy = json.loads((vault_root(path) / "policy.json").read_text())
    except (OSError, ValueError):
        return None
    return policy if not schemas.errors("policy", policy) else None


def open_log(path: Path | None = None) -> AccessLog:
    return FileAccessLog(vault_root(path) / "access.jsonl")
