"""`verify` (SPEC.md section 6). Recomputes everything; trusts no stored value.

Works on a `ThreadSnapshot` (what was read from disk), so it is independent of how the vault
stores things and can be fed hostile input directly in tests.

Per branch, the chain is checked record by record and reported at its FIRST bad record; records
after it are "unverified after". Checks per record, in order: readable and schema-valid (and in the
right thread/branch), `prev_hash` link (`fork_link_mismatch` for a fork's first record), `hash`,
`signature`, then `seq` / `version` continuity along the lineage. Independently of that, every
branch gets `head_mismatch` and blob checks.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel

from threadvault import schemas
from threadvault.core.hashing import record_hash
from threadvault.core.lineage import ForkError, ThreadSnapshot, fork_point_hash, lineage, topo_order
from threadvault.core.signing import check_signature, keys_from_manifest
from threadvault.types import BranchReport, Record, VerifyIssue, VerifyReport

HANDOVER_ONLY_NOTICE = (
    "No message history stored: the handover cannot be checked against a transcript. "
    "Only the handover versions and files are protected."
)
SELF_KEYS_NOTICE = (
    "Signatures were checked against keys listed inside the thread itself. That detects "
    "accidental changes, not a deliberate forger; verify with a trusted key store."
)
NO_KEYS_NOTICE = (
    "No trusted keys were available, so signatures were not required: someone who can write to "
    "the vault could rewrite it and recompute every hash without this report noticing."
)
MANIFEST_BRANCH = "manifest"
RECORD_TYPES = ("handover", "message", "tombstone")

BlobCheck = Callable[[str], str | None]  # sha256 -> None | "missing_blob" | "blob_hash_mismatch"


class VaultVerifyReport(BaseModel):
    ok: bool
    threads: list[VerifyReport]
    access_log_issues: list[VerifyIssue] = []
    policy_ok: bool = True
    orphan_blob_issues: list[str] = []  # sha256 ids of unreferenced blobs that fail their hash


def _record_valid(rec: Record, thread_id: str, branch_id: str) -> bool:
    if rec.get("type") not in RECORD_TYPES or schemas.errors(rec["type"], rec):
        return False
    return rec.get("thread_id") == thread_id and rec.get("branch_id") == branch_id


def _file_refs(rec: Record) -> list[str]:
    if rec.get("type") == "handover":
        return [str(f.get("sha256")) for f in rec.get("content", {}).get("files", [])]
    if rec.get("type") == "message":
        return [str(s) for s in rec.get("file_refs", [])]
    return []


def _int_field(rec: Record | None, key: str) -> int | None:
    value = rec.get(key) if isinstance(rec, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _tombstoned(records: list[Record]) -> set[str]:
    return {str(r["target"].get("sha256")) for r in records
            if r.get("type") == "tombstone" and isinstance(r.get("target"), dict)
            and r["target"].get("kind") == "file"}


def verify_snapshot(snap: ThreadSnapshot, blob_check: BlobCheck, *,
                    trusted_keys: dict[str, Ed25519PublicKey] | None = None,
                    require_signatures: bool = False) -> VerifyReport:
    """Verify one thread.

    trusted_keys: public keys to check signatures against. None means "use the keys the manifest
        lists", which only detects accidents (a notice says so).
    require_signatures: every record must carry a valid signature (set when the vault signs).
    """
    tid = snap.thread_id
    notices: list[str] = []
    manifest_issues: list[VerifyIssue] = []
    manifest = snap.manifest
    if manifest is None or schemas.errors("manifest", manifest) or manifest.get("thread_id") != tid:
        manifest_issues.append(VerifyIssue(code="schema_invalid", branch_id=MANIFEST_BRANCH, index=-1))
    m: Record = manifest if isinstance(manifest, dict) else {}
    mode: Literal["handover", "full"] = "handover" if m.get("mode") == "handover" else "full"

    keys = trusted_keys
    if keys is None:
        keys = keys_from_manifest(m)
        if keys:
            notices.append(SELF_KEYS_NOTICE)
        elif not require_signatures:
            notices.append(NO_KEYS_NOTICE)

    branches: dict[str, Record | None] = dict(snap.branches)
    for bid, b in snap.branches.items():
        if b is not None and (schemas.errors("branch", b) or b.get("branch_id") != bid
                              or b.get("thread_id") != tid):
            branches[bid] = None
    # Records that pass the per-record checks; used for lineage (counters, fork points, refs).
    good: dict[str, list[Record | None]] = {}
    reports: dict[str, BranchReport] = {}

    for bid in topo_order(branches):
        issues: list[VerifyIssue] = []
        if snap.branches.get(bid) is not None and branches[bid] is None:
            issues.append(VerifyIssue(code="schema_invalid", branch_id=bid, index=-1))
        branch = branches[bid]
        parent = branch.get("parent") if branch else None
        records = snap.chains.get(bid, [])

        # Starting point: null for a root, the fork point's hash for a fork.
        start_prev: str | None = None
        inherited: list[Record] = []
        fork_ok = True
        if parent:
            try:
                inherited = lineage(branches, good, str(parent["branch_id"]),
                                    frozenset({bid}))
                start_prev = fork_point_hash(inherited, parent["fork_point"])
                idx = next(i for i, r in enumerate(inherited) if r.get("hash") == start_prev)
                inherited = inherited[: idx + 1]
            except (ForkError, KeyError, StopIteration):
                fork_ok = False
                issues.append(VerifyIssue(code="fork_link_mismatch", branch_id=bid, index=-1))

        last_seq = max((int(r["seq"]) for r in inherited if r.get("type") == "message"), default=-1)
        last_ver = max((int(r["version"]) for r in inherited if r.get("type") == "handover"),
                       default=0)
        # Once a record in the lineage is signed, every later one must be: stripping signatures
        # from the tail of a chain is tampering, even when signatures are not required.
        signed_seen = any("signature" in r for r in inherited)
        prev = start_prev
        bad_at: int | None = None
        kept: list[Record | None] = []
        for i, rec in enumerate(records):
            code: str | None = None
            if rec is None or (bid, i) in snap.unreadable or not _record_valid(rec, tid, bid):
                code = "schema_invalid"
            elif rec["prev_hash"] != prev:
                code = "fork_link_mismatch" if (i == 0 and parent) else "prev_mismatch"
            elif rec["hash"] != record_hash(rec):
                code = "hash_mismatch"
            elif (("signature" in rec or require_signatures or signed_seen)
                  and not check_signature(rec, keys)):
                code = "signature_invalid"
            elif rec["type"] == "message" and rec["seq"] != last_seq + 1:
                code = "seq_gap"
            elif rec["type"] == "handover" and rec["version"] != last_ver + 1:
                code = "version_gap"
            if code is not None:
                if not (code == "fork_link_mismatch" and not fork_ok):  # already reported
                    issues.append(VerifyIssue(code=code, branch_id=bid, index=i,
                                              seq=_int_field(rec, "seq"),
                                              version=_int_field(rec, "version")))
                bad_at = i
                break
            assert rec is not None
            signed_seen = signed_seen or "signature" in rec
            if rec["type"] == "message":
                last_seq = rec["seq"]
            elif rec["type"] == "handover":
                last_ver = rec["version"]
            prev = rec["hash"]
            kept.append(rec)
        good[bid] = kept
        reports[bid] = BranchReport(
            branch_id=bid, ok=False, issues=issues,
            unverified_after=(bad_at + 1 if bad_at is not None and bad_at + 1 < len(records)
                              else None))

    # head_hash in the manifest must equal the real last record (as stored) of each chain.
    listed = {b.get("branch_id"): b.get("head_hash") for b in m.get("branches", [])
              if isinstance(b, dict)}
    for listed_id, head in listed.items():
        lb = str(listed_id)
        rows = snap.chains.get(lb)
        real: str | None = None
        if rows is None:
            if lb not in reports:
                reports[lb] = BranchReport(branch_id=lb, ok=False, issues=[
                    VerifyIssue(code="schema_invalid", branch_id=lb, index=-1)])
        elif rows:
            last = rows[-1]
            real = str(last.get("hash")) if isinstance(last, dict) else "(unreadable)"
        if head != real:
            reports[lb].issues.append(VerifyIssue(code="head_mismatch", branch_id=lb, index=-1))

    # Blobs: every referenced file must exist and hash correctly unless a tombstone covers it.
    # Coverage is thread-wide: `forget` works on a hash across the whole vault, and a fork made at
    # a point before the tombstone legitimately inherits references to the forgotten file. Only
    # tombstones in records that verified count, so an attacker cannot add one undetected.
    all_records = [r for rs in good.values() for r in rs if r is not None]
    thread_tombs = _tombstoned(all_records)
    checked: dict[str, str | None] = {}

    def blob_issue(sha: str) -> str | None:
        if sha not in checked:
            checked[sha] = blob_check(sha)
        return checked[sha]

    current = str(m.get("current_branch", ""))
    reported: dict[str, set[str]] = {}  # branch -> file hashes already reported there
    for f in m.get("files", []) or []:
        sha = str(f.get("sha256")) if isinstance(f, dict) else ""
        code = None if sha in thread_tombs else blob_issue(sha)
        target = current if current in reports else MANIFEST_BRANCH
        if code:
            reported.setdefault(target, set()).add(sha)
            if target == MANIFEST_BRANCH:
                manifest_issues.append(VerifyIssue(code=code, branch_id=target, index=-1))
            else:
                reports[target].issues.append(VerifyIssue(code=code, branch_id=target, index=-1))
    for bid in list(reports):
        try:
            seen = lineage(branches, good, bid)
        except ForkError:
            seen = [r for r in good.get(bid, []) if r is not None]
        done = reported.setdefault(bid, set())
        for rec in seen:
            for sha in _file_refs(rec):
                if sha in thread_tombs or sha in done:
                    continue
                code = blob_issue(sha)
                if code:
                    done.add(sha)
                    reports[bid].issues.append(VerifyIssue(code=code, branch_id=bid, index=-1))
    lingering = {sha for sha in thread_tombs if blob_issue(sha) != "missing_blob"}

    notices += [f"File {sha} was forgotten but its blob is still in the vault."
                for sha in sorted(lingering)]
    out: list[BranchReport] = []
    for bid in sorted(reports, key=lambda b: (b != current, b)):
        r = reports[bid]
        r.ok = not r.issues
        out.append(r)
    if manifest_issues:
        out.insert(0, BranchReport(branch_id=MANIFEST_BRANCH, ok=False, issues=manifest_issues))
    if mode == "handover":
        notices.insert(0, HANDOVER_ONLY_NOTICE)
    return VerifyReport(thread_id=tid, mode=mode, ok=all(r.ok for r in out) and bool(out),
                        branches=out, notices=notices)


def verify_access_chain(entries: list[Record | None]) -> list[VerifyIssue]:
    """SPEC section 11: the access log follows the chain rules. Reported at the first bad entry."""
    prev: str | None = None
    for i, e in enumerate(entries):
        bad = (e is None or bool(schemas.errors("access_entry", e)) or e.get("seq") != i
               or e.get("prev_hash") != prev or e.get("hash") != record_hash(e))
        if bad:
            return [VerifyIssue(code="access_chain_broken", branch_id="access", index=i,
                                seq=_int_field(e, "seq"))]
        assert e is not None
        prev = e["hash"]
    return []
