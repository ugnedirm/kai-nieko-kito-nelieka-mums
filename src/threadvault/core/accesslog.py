"""Access log (SPEC.md section 11): vault-wide, append-only, hash-chained.

`FileAccessLog` is the real implementation (``vault/access.jsonl``); `MemoryAccessLog` stays as
the in-memory stub for tests. Callers depend on the `AccessLog` Protocol.

`detail` must never contain message text, file contents, tokens or secrets. As defence in depth,
`FileAccessLog` runs the secret scanner over `detail` and withholds it if anything is found.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Protocol

from threadvault import schemas
from threadvault.core.hashing import record_hash
from threadvault.core.ids import Clock, utc_now
from threadvault.core.jsonio import StrictJSONError, append_line, loads, split_jsonl
from threadvault.types import Record, VerifyIssue

WITHHELD = "[detail withheld: it looked like it contained a secret or personal data]"


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


def _scrub(detail: str) -> str:
    from threadvault.scanners.engine import scan_text  # local import: scanners import core

    detail = detail[:500]
    return WITHHELD if scan_text(detail) else detail


def _tail_line(path: Path, max_back: int = 1 << 20) -> bytes | None:
    """Last non-empty line of a file without reading all of it."""
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return None
    with open(path, "rb") as fh:
        back = min(size, 4096)
        while True:
            fh.seek(size - back)
            chunk = fh.read(back)
            lines = split_jsonl(chunk)
            if lines and (back == size or chunk.rstrip(b"\r\n").rfind(b"\n") >= 0):
                return lines[-1]
            if back >= size or back >= max_back:
                return lines[-1] if lines else None
            back = min(size, back * 4)


class FileAccessLog:
    """Append-only access log file. One process should own a vault at a time; within a process,
    writes are serialised by a lock."""

    def __init__(self, path: Path, clock: Clock = utc_now) -> None:
        self.path = path
        self._clock = clock
        self._lock = threading.Lock()

    def _head(self) -> tuple[int, str | None]:
        line = _tail_line(self.path)
        if line is None:
            return 0, None
        try:
            last = loads(line)
            return int(last["seq"]) + 1, str(last["hash"])
        except (StrictJSONError, KeyError, TypeError, ValueError):
            # Broken tail: refuse to extend a chain we cannot link to.
            raise RuntimeError("access log tail is unreadable; run verify") from None

    def record(self, *, client_id: str, kind: str, action: str, outcome: str,
               thread_id: str | None = None, detail: str | None = None) -> Record:
        with self._lock:
            seq, prev = self._head()
            entry: Record = {
                "spec_version": "1", "type": "access", "seq": seq, "ts": self._clock(),
                "actor": {"client_id": client_id[:128], "kind": kind}, "action": action,
                "outcome": outcome, "prev_hash": prev}
            if thread_id:
                entry["thread_id"] = thread_id
            if detail:
                entry["detail"] = _scrub(detail)
            entry["hash"] = record_hash(entry)
            if schemas.errors("access_entry", entry):
                raise ValueError("access log entry does not match its schema")
            append_line(self.path, entry)
            return dict(entry)

    def raw_entries(self) -> list[Record | None]:
        """Every line, `None` where a line is not valid JSON."""
        if not self.path.exists():
            return []
        out: list[Record | None] = []
        for line in split_jsonl(self.path.read_bytes()):
            try:
                value = loads(line)
            except StrictJSONError:
                value = None
            out.append(value if isinstance(value, dict) else None)
        return out

    def entries(self) -> list[Record]:
        return [e for e in self.raw_entries() if e is not None]

    def verify(self) -> list[VerifyIssue]:
        from threadvault.core.verify import verify_access_chain

        return verify_access_chain(self.raw_entries())


# -- viewer -------------------------------------------------------------------------------------------
def filter_entries(entries: list[Record], *, thread_id: str | None = None,
                   client_id: str | None = None, action: str | None = None,
                   outcome: str | None = None, since: str | None = None) -> list[Record]:
    def keep(e: Record) -> bool:
        actor = e.get("actor") or {}
        return ((thread_id is None or e.get("thread_id") == thread_id)
                and (client_id is None or actor.get("client_id") == client_id)
                and (action is None or e.get("action") == action)
                and (outcome is None or e.get("outcome") == outcome)
                and (since is None or str(e.get("ts", "")) >= since))
    return [e for e in entries if keep(e)]


def _cell(value: object, width: int) -> str:
    text = "".join(ch if ch.isprintable() else "?" for ch in str(value if value is not None else "-"))
    return text if len(text) <= width else text[: width - 1] + "~"


def format_entries(entries: list[Record], *, issues: list[VerifyIssue] | None = None,
                   limit: int | None = None) -> str:
    """A plain-text table of access-log entries, newest last, with the chain status on top."""
    rows = entries[-limit:] if limit else entries
    if issues is None:
        status = "chain: not checked"
    elif issues:
        status = f"chain: BROKEN at entry {issues[0].index} (entries from there on are untrusted)"
    else:
        status = f"chain: ok ({len(entries)} entries)"
    cols = (("seq", 5), ("ts", 20), ("client", 20), ("kind", 9), ("action", 13), ("outcome", 7),
            ("thread", 16), ("detail", 40))
    head = "  ".join(name.ljust(w) for name, w in cols)
    lines = [status, head, "-" * len(head)]
    for e in rows:
        actor = e.get("actor") or {}
        values = (e.get("seq"), e.get("ts"), actor.get("client_id"), actor.get("kind"),
                  e.get("action"), e.get("outcome"), e.get("thread_id"), e.get("detail"))
        lines.append("  ".join(_cell(v, w).ljust(w) for v, (_, w) in zip(values, cols, strict=True)))
    return "\n".join(lines)
