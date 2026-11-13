"""Access log interface (SPEC.md section 11) and an in-memory stub.

Person A replaces `MemoryAccessLog` with an append-only file writer behind the same Protocol.
`detail` must never contain message text, file contents, tokens or secrets.
"""

from __future__ import annotations

from typing import Protocol

from threadvault.core.hashing import record_hash
from threadvault.types import Record


class AccessLog(Protocol):
    def record(self, *, client_id: str, kind: str, action: str, outcome: str,
               thread_id: str | None = None, detail: str | None = None) -> Record: ...
    def entries(self) -> list[Record]: ...


class MemoryAccessLog:
    def __init__(self) -> None:
        self._entries: list[Record] = []

    def record(self, *, client_id: str, kind: str, action: str, outcome: str,
               thread_id: str | None = None, detail: str | None = None) -> Record:
        entry: Record = {
            "spec_version": "1", "type": "access", "seq": len(self._entries),
            "ts": "2026-11-14T00:00:00Z",  # stub clock; the real log uses the current UTC time
            "actor": {"client_id": client_id, "kind": kind}, "action": action, "outcome": outcome,
            "prev_hash": self._entries[-1]["hash"] if self._entries else None}
        if thread_id:
            entry["thread_id"] = thread_id
        if detail:
            entry["detail"] = detail[:500]
        entry["hash"] = record_hash(entry)
        self._entries.append(entry)
        return dict(entry)

    def entries(self) -> list[Record]:
        return [dict(e) for e in self._entries]
