"""The Vault interface (the contract B and C code against) and a stub implementation.

`FixtureVault` is an IN-MEMORY stand-in that loads the sample vault in tests/fixtures/vault.
Writes never touch disk. Person A replaces it with a real `DiskVault` that satisfies the same
`Vault` Protocol, so callers must depend on `Vault`, never on `FixtureVault`.
"""

from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path
from typing import Protocol

from threadvault.core.hashing import record_hash, sha256_bytes
from threadvault.core.lineage import ForkError
from threadvault.core.render import handover_text, historical_context, message_line
from threadvault.types import (
    BranchData,
    BranchReport,
    Record,
    ThreadData,
    ThreadInfo,
    VerifyIssue,
    VerifyReport,
)

FIXTURE_ROOT = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "vault"
HANDOVER_ONLY_NOTICE = (
    "No message history stored: the handover cannot be checked against a transcript. "
    "Only the handover versions and files are protected."
)


class Vault(Protocol):
    def list_threads(self) -> list[ThreadInfo]: ...
    def create_thread(self, title: str, mode: str) -> str: ...
    def load_thread(self, thread_id: str) -> ThreadData: ...
    def append(self, thread_id: str, branch_id: str, partial: Record) -> Record: ...
    def put_file(self, thread_id: str, name: str, media_type: str, data: bytes) -> Record: ...
    def get_file(self, sha256: str) -> bytes: ...
    def forget_file(self, sha256: str) -> None: ...
    def verify(self, thread_id: str) -> VerifyReport: ...
    def render_text(self, thread_id: str, branch_id: str | None = None) -> str: ...
    def pack(self, thread_id: str, max_tokens: int, branch_id: str | None = None) -> str: ...
    def fork(self, thread_id: str, from_branch: str | None = None, *, at_hash: str | None = None,
             handover_version: int | None = None, label: str | None = None) -> str:
        """New branch sharing history with `from_branch` up to a fork point; returns its id."""
        ...
    def set_current_branch(self, thread_id: str, branch_id: str) -> None: ...
    def merge_files(self, source_id: str, target_id: str) -> int:
        """Move a files-only thread's files into another thread and delete the source."""
        ...
    def delete_thread(self, thread_id: str) -> None: ...
    def set_expiry(self, thread_id: str, expires_at: str | None) -> None: ...
    def set_file_expiry(self, thread_id: str, sha256: str, expires_at: str | None) -> None: ...
    def sweep_expired(self) -> int:
        """Delete expired threads and forget expired files; returns how many were removed."""
        ...


class FixtureVault:
    def __init__(self, root: Path = FIXTURE_ROOT) -> None:
        self._manifests: dict[str, Record] = {}
        self._branches: dict[str, dict[str, Record]] = {}
        self._chains: dict[str, dict[str, list[Record]]] = {}
        self._blobs: dict[str, bytes] = {}
        for tdir in sorted((root / "threads").iterdir()):
            tid = tdir.name
            self._manifests[tid] = json.loads((tdir / "manifest.json").read_text())
            self._branches[tid] = {p.stem: json.loads(p.read_text())
                                   for p in sorted((tdir / "branches").glob("*.json"))}
            self._chains[tid] = {
                p.stem: [json.loads(line) for line in p.read_text().splitlines() if line]
                for p in sorted((tdir / "chains").glob("*.jsonl"))}
        for p in (root / "blobs").glob("*"):
            self._blobs["sha256:" + p.name] = p.read_bytes()

    # -- reading ---------------------------------------------------------------------------
    def list_threads(self) -> list[ThreadInfo]:
        return [ThreadInfo(thread_id=t, title=m["title"], mode=m["mode"], updated_at=m["updated_at"],
                           branches=[b["branch_id"] for b in m["branches"]])
                for t, m in self._manifests.items()]

    def load_thread(self, thread_id: str) -> ThreadData:
        return ThreadData(
            manifest=copy.deepcopy(self._manifests[thread_id]),
            branches={bid: BranchData(branch=copy.deepcopy(b),
                                      records=copy.deepcopy(self._chains[thread_id][bid]))
                      for bid, b in self._branches[thread_id].items()})

    def get_file(self, sha256: str) -> bytes:
        try:
            return self._blobs[sha256]
        except KeyError:
            raise FileNotFoundError("no such file in vault") from None

    def _lineage(self, thread_id: str, branch_id: str) -> list[Record]:
        """Records visible on a branch: parent history up to the fork point, then its own."""
        own = self._chains[thread_id][branch_id]
        parent = self._branches[thread_id][branch_id]["parent"]
        if not parent:
            return list(own)
        fork_hash = parent["fork_point"].get("hash")
        inherited = self._lineage(thread_id, parent["branch_id"])
        if fork_hash:
            idx = next((i for i, r in enumerate(inherited) if r["hash"] == fork_hash), len(inherited) - 1)
            inherited = inherited[: idx + 1]
        return inherited + own

    # -- writing (in memory only) --------------------------------------------------------------
    def create_thread(self, title: str, mode: str) -> str:
        tid = "thr_" + uuid.uuid4().hex[:12]
        bid = "main0001"
        now = "2026-11-14T00:00:00Z"
        self._manifests[tid] = {
            "spec_version": "1", "type": "manifest", "thread_id": tid, "title": title, "mode": mode,
            "created_at": now, "updated_at": now, "current_branch": bid,
            "branches": [{"branch_id": bid, "head_hash": None}], "files": []}
        self._branches[tid] = {bid: {"spec_version": "1", "type": "branch", "branch_id": bid,
                                     "thread_id": tid, "label": bid, "parent": None, "created_at": now,
                                     "created_by": {"kind": "human"}}}
        self._chains[tid] = {bid: []}
        return tid

    def fork(self, thread_id: str, from_branch: str | None = None, *, at_hash: str | None = None,
             handover_version: int | None = None, label: str | None = None) -> str:
        src = self._branch(thread_id, from_branch)
        visible = self._lineage(thread_id, src)
        if handover_version is not None:
            target = next((r for r in visible if r["type"] == "handover"
                           and r["version"] == handover_version), None)
        elif at_hash is not None:
            target = next((r for r in visible if r["hash"] == at_hash), None)
        else:
            target = visible[-1] if visible else None
        if target is None:
            raise ForkError("fork point not found on that branch")
        owner = next(b for b, chain in self._chains[thread_id].items()
                     if any(r["hash"] == target["hash"] for r in chain))
        point: Record = ({"kind": "handover", "version": target["version"]}
                         if target["type"] == "handover"
                         else {"kind": "message", "hash": target["hash"]})
        bid = "br_" + uuid.uuid4().hex[:12]
        now = "2026-11-14T00:00:00Z"
        self._branches[thread_id][bid] = {
            "spec_version": "1", "type": "branch", "branch_id": bid, "thread_id": thread_id,
            "label": (label or bid)[:100], "parent": {"branch_id": owner, "fork_point": point},
            "created_at": now, "created_by": {"kind": "human"}}
        self._chains[thread_id][bid] = []
        self._manifests[thread_id]["branches"].append({"branch_id": bid, "head_hash": None})
        return bid

    def delete_thread(self, thread_id: str) -> None:
        for table in (self._manifests, self._branches, self._chains):
            del table[thread_id]

    def set_expiry(self, thread_id: str, expires_at: str | None) -> None:
        if expires_at is None:
            self._manifests[thread_id].pop("expires_at", None)
        else:
            self._manifests[thread_id]["expires_at"] = expires_at

    def set_file_expiry(self, thread_id: str, sha256: str, expires_at: str | None) -> None:
        entry = next((f for f in self._manifests[thread_id]["files"] if f["sha256"] == sha256), None)
        if entry is None:
            raise KeyError("file not in this thread")
        if expires_at is None:
            entry.pop("expires_at", None)
        else:
            entry["expires_at"] = expires_at

    def sweep_expired(self) -> int:
        return 0  # the in-memory stub never expires anything

    def merge_files(self, source_id: str, target_id: str) -> int:
        if source_id == target_id:
            raise ValueError("cannot merge a thread into itself")
        if any(self._chains[source_id].values()):
            raise ValueError("that thread has saved text; only a thread with nothing but files "
                             "can be merged")
        have = {f["sha256"] for f in self._manifests[target_id]["files"]}
        added = [dict(f) for f in self._manifests[source_id]["files"] if f["sha256"] not in have]
        self._manifests[target_id]["files"].extend(added)
        for table in (self._manifests, self._branches, self._chains):
            del table[source_id]
        return len(added)

    def set_current_branch(self, thread_id: str, branch_id: str) -> None:
        if branch_id not in self._branches[thread_id]:
            raise KeyError("no such branch")
        self._manifests[thread_id]["current_branch"] = branch_id

    def append(self, thread_id: str, branch_id: str, partial: Record) -> Record:
        chain = self._chains[thread_id][branch_id]
        lineage = self._lineage(thread_id, branch_id)
        parent = self._branches[thread_id][branch_id]["parent"]
        prev = chain[-1]["hash"] if chain else (parent["fork_point"].get("hash") if parent else None)
        rec: Record = {"spec_version": "1", "thread_id": thread_id, "branch_id": branch_id, **partial}
        if rec["type"] == "message":
            rec["seq"] = 1 + max((r["seq"] for r in lineage if r["type"] == "message"), default=-1)
            rec["id"] = f"msg_{branch_id}_{rec['seq']}"
        elif rec["type"] == "handover":
            rec["version"] = 1 + max((r["version"] for r in lineage if r["type"] == "handover"), default=0)
        rec["prev_hash"] = prev
        rec["hash"] = record_hash(rec)
        chain.append(rec)
        manifest = self._manifests[thread_id]
        for b in manifest["branches"]:
            if b["branch_id"] == branch_id:
                b["head_hash"] = rec["hash"]
        return copy.deepcopy(rec)

    def put_file(self, thread_id: str, name: str, media_type: str, data: bytes) -> Record:
        ref: Record = {"sha256": sha256_bytes(data), "name": name, "media_type": media_type, "size": len(data)}
        self._blobs[ref["sha256"]] = data
        files = self._manifests[thread_id]["files"]
        if not any(f["sha256"] == ref["sha256"] for f in files):
            files.append(ref)
        return ref

    def forget_file(self, sha256: str) -> None:
        self._blobs.pop(sha256, None)
        for tid, chains in self._chains.items():
            manifest = self._manifests[tid]
            referenced = any(f["sha256"] == sha256 for f in manifest["files"]) or any(
                sha256 in json.dumps(r) for chain in chains.values() for r in chain)
            manifest["files"] = [f for f in manifest["files"] if f["sha256"] != sha256]
            if referenced:
                for bid in chains:
                    self.append(tid, bid, {"type": "tombstone", "target": {"kind": "file", "sha256": sha256},
                                           "removed_at": "2026-11-14T00:00:00Z", "reason": "user-forget"})

    # -- verify: minimal reference version; Person A replaces with the full SPEC section 6 --------
    def verify(self, thread_id: str) -> VerifyReport:
        manifest = self._manifests[thread_id]
        reports: list[BranchReport] = []
        tombstoned = {r["target"].get("sha256") for ch in self._chains[thread_id].values()
                      for r in ch if r["type"] == "tombstone"}
        for bid, branch in self._branches[thread_id].items():
            records = self._chains[thread_id][bid]
            parent = branch["parent"]
            prev = parent["fork_point"].get("hash") if parent else None
            issues: list[VerifyIssue] = []
            if parent and not any(r["hash"] == prev for r in self._chains[thread_id][parent["branch_id"]]):
                issues.append(VerifyIssue(code="fork_link_mismatch", branch_id=bid, index=-1))
            bad_at: int | None = None
            for i, r in enumerate(records):
                code = ("prev_mismatch" if r["prev_hash"] != prev
                        else "hash_mismatch" if r["hash"] != record_hash(r) else None)
                if code:
                    issues.append(VerifyIssue(code=code, branch_id=bid, index=i, seq=r.get("seq"),
                                              version=r.get("version")))
                    bad_at = i
                    break
                prev = r["hash"]
            wanted = [f["sha256"] for f in manifest["files"]] + [
                f["sha256"] for r in records if r["type"] == "handover" for f in r["content"]["files"]]
            issues += [VerifyIssue(code="missing_blob", branch_id=bid, index=-1)
                       for sha in wanted if sha not in self._blobs and sha not in tombstoned]
            reports.append(BranchReport(
                branch_id=bid, ok=not issues, issues=issues,
                unverified_after=(bad_at + 1 if bad_at is not None and bad_at + 1 < len(records) else None)))
        notices = [HANDOVER_ONLY_NOTICE] if manifest["mode"] == "handover" else []
        return VerifyReport(thread_id=thread_id, mode=manifest["mode"], ok=all(r.ok for r in reports),
                            branches=reports, notices=notices)

    # -- views -----------------------------------------------------------------------------------
    def _branch(self, thread_id: str, branch_id: str | None) -> str:
        return branch_id or str(self._manifests[thread_id]["current_branch"])

    def render_text(self, thread_id: str, branch_id: str | None = None) -> str:
        recs = self._lineage(thread_id, self._branch(thread_id, branch_id))
        lines = [message_line(r) for r in recs if r["type"] == "message"]
        handovers = [r for r in recs if r["type"] == "handover"]
        if handovers:
            lines.append("--- handover ---\n" + handover_text(handovers[-1]))
        return "\n".join(lines)

    def pack(self, thread_id: str, max_tokens: int, branch_id: str | None = None) -> str:
        """Latest handover plus as many newest messages as fit. Token count is a rough len/4 here;
        Person A swaps in tiktoken."""
        recs = self._lineage(thread_id, self._branch(thread_id, branch_id))
        verified = self.verify(thread_id).ok
        handovers = [r for r in recs if r["type"] == "handover"]
        head = historical_context(handovers[-1], verified=verified) if handovers else ""
        budget = max_tokens * 4 - len(head)
        kept: list[str] = []
        for r in reversed([r for r in recs if r["type"] == "message"]):
            line = message_line(r)
            if len(line) + 1 > budget:
                break
            kept.append(line)
            budget -= len(line) + 1
        return "\n".join(([head] if head else []) + list(reversed(kept)))

