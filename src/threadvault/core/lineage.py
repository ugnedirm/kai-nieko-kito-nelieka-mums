"""Branch model (SPEC.md sections 1, 3.4).

A branch is a chain file. A root branch's first record has `prev_hash: null`. A fork names its
parent and a fork point; its visible history (its *lineage*) is the parent's lineage up to and
including the fork point, followed by its own records. The fork's first record has
`prev_hash` = the fork point's hash, which makes the shared history verifiable.

Fork points come in two shapes (schemas/branch.schema.json):
  {"kind": "message",  "hash": "sha256:..."}   any record hash in the parent's lineage
  {"kind": "handover", "version": 2}           the handover with that version in the parent's lineage
"""

from __future__ import annotations

from dataclasses import dataclass, field

from threadvault.types import Record


class ForkError(ValueError):
    """Parent missing, fork point not in the parent, or a cycle of parents."""


@dataclass
class ThreadSnapshot:
    """Everything `verify` needs about one thread, read from disk but not yet trusted.

    `None` stands for something that could not be read or parsed (a broken line, a missing or
    unparseable file). `extra` collects per-record problems found while reading (e.g. a record
    that could not be decrypted), keyed by (branch_id, index).
    """

    thread_id: str
    manifest: Record | None
    branches: dict[str, Record | None]
    chains: dict[str, list[Record | None]]
    unreadable: set[tuple[str, int]] = field(default_factory=set)


def fork_point_hash(parent_lineage: list[Record], fork_point: Record) -> str:
    """Resolve a fork point against the parent's lineage. Raises ForkError if it is not there."""
    if fork_point.get("kind") == "handover":
        for r in parent_lineage:
            if r.get("type") == "handover" and r.get("version") == fork_point.get("version"):
                return str(r["hash"])
        raise ForkError("fork point handover version not in parent")
    wanted = fork_point.get("hash")
    if any(r.get("hash") == wanted for r in parent_lineage):
        return str(wanted)
    raise ForkError("fork point hash not in parent")


def lineage(branches: dict[str, Record | None], chains: dict[str, list[Record | None]],
            branch_id: str, _seen: frozenset[str] = frozenset()) -> list[Record]:
    """Records visible on `branch_id`, oldest first. Unparseable records are skipped."""
    if branch_id in _seen:
        raise ForkError("cycle in branch parents")
    branch = branches.get(branch_id)
    own = [r for r in chains.get(branch_id, []) if r is not None]
    parent = branch.get("parent") if branch else None
    if not parent:
        return own
    pid = parent.get("branch_id")
    if pid not in branches or branches[pid] is None:
        raise ForkError("parent branch missing")
    inherited = lineage(branches, chains, str(pid), _seen | {branch_id})
    fp_hash = fork_point_hash(inherited, parent.get("fork_point") or {})
    idx = next(i for i, r in enumerate(inherited) if r.get("hash") == fp_hash)
    return inherited[: idx + 1] + own


def owner_of(branches: dict[str, Record | None], chains: dict[str, list[Record | None]],
             branch_id: str, record_hash: str) -> str:
    """The branch whose own chain holds `record_hash`, searching `branch_id` then its ancestors."""
    current: str | None = branch_id
    seen: set[str] = set()
    while current is not None and current not in seen:
        seen.add(current)
        if any(r is not None and r.get("hash") == record_hash for r in chains.get(current, [])):
            return current
        branch = branches.get(current)
        parent = branch.get("parent") if branch else None
        current = str(parent["branch_id"]) if parent else None
    raise ForkError("record not in branch lineage")


def topo_order(branches: dict[str, Record | None]) -> list[str]:
    """Branch ids with parents before children; branches in cycles or with missing parents last."""
    done: list[str] = []
    placed: set[str] = set()
    pending = sorted(branches)
    progress = True
    while pending and progress:
        progress = False
        for bid in list(pending):
            b = branches[bid]
            parent = b.get("parent") if b else None
            pid = parent.get("branch_id") if parent else None
            if pid is None or pid in placed:
                done.append(bid)
                placed.add(bid)
                pending.remove(bid)
                progress = True
    return done + pending
