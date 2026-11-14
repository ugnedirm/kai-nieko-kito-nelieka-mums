"""Write an imported thread into a vault through the `Vault` Protocol only."""

from __future__ import annotations

from threadvault import schemas
from threadvault.core.vault import Vault
from threadvault.importers.base import ImportedThread, ImportRefused


def store_import(vault: Vault, imported: ImportedThread) -> str:
    """Create a full-mode thread and append every message as `imported-unverified`.

    Records are validated on the way in: the importer never decides hashes, ids or seq.
    """
    # Check everything BEFORE creating the thread, so a bad import leaves nothing behind.
    try:
        imported.title.encode("utf-8")
        for m in imported.messages:
            m.content.encode("utf-8")
    except UnicodeEncodeError:
        raise ImportRefused("record_invalid", "text is not valid Unicode") from None
    thread_id = vault.create_thread(imported.title, "full")
    branch_id = str(vault.load_thread(thread_id).manifest["current_branch"])
    for m in imported.messages:
        rec = vault.append(thread_id, branch_id, {
            "type": "message", "role": m.role, "author": dict(m.author),
            "created_at": m.created_at, "content": m.content,
            "provenance": "imported-unverified"})
        if schemas.errors("message", rec):
            raise ImportRefused("record_invalid", "vault rejected an imported message")
    return thread_id
