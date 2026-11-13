"""Data and diff logic for the compare page. No Streamlit here, so it is unit-testable.

Everything shown comes from untrusted chat text: callers must render it as plain text, never as
HTML or Markdown (the page uses `st.text` / `st.code` only).
"""

from __future__ import annotations

import difflib

from pydantic import BaseModel

from threadvault.core.render import handover_text
from threadvault.core.vault import Vault
from threadvault.types import Record, ThreadData

BADGES = {
    "provider-verified": "VERIFIED by provider",
    "ai-summary-user-saved": "AI summary, saved by you",
    "user-asserted": "typed by you",
    "imported-unverified": "IMPORTED, unverified",
}


class Row(BaseModel):
    seq: int
    role: str
    who: str
    text: str
    badge: str
    provenance: str


class ThreadView(BaseModel):
    thread_id: str
    title: str
    branch_id: str
    verified: bool
    warnings: list[str]
    rows: list[Row]
    handover_versions: list[int]


def lineage(data: ThreadData, branch_id: str) -> list[Record]:
    """Parent history up to the fork point, then the branch's own records."""
    branch = data.branches[branch_id]
    parent = branch.branch.get("parent")
    if not parent:
        return list(branch.records)
    inherited = lineage(data, parent["branch_id"])
    fork_hash = parent["fork_point"].get("hash")
    if fork_hash:
        idx = next((i for i, r in enumerate(inherited) if r["hash"] == fork_hash), None)
        if idx is not None:
            inherited = inherited[: idx + 1]
    return inherited + list(branch.records)


def build_view(vault: Vault, thread_id: str, branch_id: str | None = None) -> ThreadView:
    data = vault.load_thread(thread_id)
    bid = branch_id or str(data.manifest["current_branch"])
    report = vault.verify(thread_id)
    warnings = list(report.notices)
    for b in report.branches:
        warnings += [f"branch {b.branch_id}: {i.code}" for i in b.issues]
    recs = lineage(data, bid)
    rows = [Row(seq=r["seq"], role=r["role"], who=str(r["author"].get("model") or r["author"]["kind"]),
                text=r["content"], badge=BADGES.get(r["provenance"], "UNKNOWN provenance"),
                provenance=r["provenance"])
            for r in recs if r["type"] == "message"]
    if any(r.provenance == "imported-unverified" for r in rows):
        warnings.append("some messages are imported: authorship cannot be proven")
    return ThreadView(thread_id=thread_id, title=str(data.manifest["title"]), branch_id=bid,
                      verified=report.ok, warnings=warnings, rows=rows,
                      handover_versions=[r["version"] for r in recs if r["type"] == "handover"])


def diff_text(a: str, b: str) -> list[tuple[str, str]]:
    """Line diff as (marker, line): marker is ' ', '+' or '-'."""
    out: list[tuple[str, str]] = []
    for line in difflib.ndiff(a.splitlines(), b.splitlines()):
        if line[:1] in {" ", "+", "-"}:
            out.append((line[0], line[2:]))
    return out


def handover_diff(vault: Vault, thread_id: str, v_from: int, v_to: int,
                  branch_id: str | None = None) -> list[tuple[str, str]]:
    data = vault.load_thread(thread_id)
    bid = branch_id or str(data.manifest["current_branch"])
    by_version = {r["version"]: r for r in lineage(data, bid) if r["type"] == "handover"}
    return diff_text(handover_text(by_version[v_from]), handover_text(by_version[v_to]))


def first_divergence(a: ThreadView, b: ThreadView) -> int | None:
    """Index of the first row where two views differ, or None if one is a prefix of the other."""
    for i, (x, y) in enumerate(zip(a.rows, b.rows, strict=False)):
        if (x.role, x.text) != (y.role, y.text):
            return i
    return None
