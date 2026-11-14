"""Every SPEC section 6 error code, produced by a concrete attack (THREAT_MODEL T1, T2, T12, T13, T17)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import handover, message
from threadvault.core.accesslog import FileAccessLog
from threadvault.core.disk import DiskVault
from threadvault.core.hashing import record_hash
from threadvault.core.signing import MemoryKeyStore


def chain_path(v: DiskVault, tid: str, bid: str = "main0001") -> Path:
    return v.root / "threads" / tid / "chains" / f"{bid}.jsonl"


def read_lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]


def write_lines(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in rows))


def rehash_from(rows: list[dict[str, Any]], start: int, start_prev: str | None = None) -> None:
    """What an attacker with write access does: recompute hashes and links after an edit."""
    for i in range(start, len(rows)):
        rows[i]["prev_hash"] = rows[i - 1]["hash"] if i else start_prev
        rows[i]["hash"] = record_hash(rows[i])


def fix_head(v: DiskVault, tid: str, bid: str = "main0001") -> None:
    rows = read_lines(chain_path(v, tid, bid))
    mpath = v.root / "threads" / tid / "manifest.json"
    m = json.loads(mpath.read_text(encoding="utf-8"))
    for b in m["branches"]:
        if b["branch_id"] == bid:
            b["head_hash"] = rows[-1]["hash"] if rows else None
    mpath.write_text(json.dumps(m), encoding="utf-8")


def codes(v: DiskVault, tid: str) -> list[tuple[str, int]]:
    return [(i.code, i.index) for b in v.verify(tid).branches for i in b.issues]


@pytest.fixture
def full(vault: DiskVault) -> tuple[DiskVault, str]:
    tid = vault.create_thread("t", "full")
    for i in range(4):
        vault.append(tid, "main0001", message(f"m{i}"))
    vault.append(tid, "main0001", handover())
    return vault, tid


def test_silent_edit_is_hash_mismatch(full: tuple[DiskVault, str]) -> None:
    v, tid = full
    rows = read_lines(chain_path(v, tid))
    rows[1]["content"] = "edited"
    write_lines(chain_path(v, tid), rows)
    report = v.verify(tid)
    assert codes(v, tid) == [("hash_mismatch", 1)]
    assert report.branches[0].unverified_after == 2


def test_reorder_and_delete_are_prev_mismatch(full: tuple[DiskVault, str]) -> None:
    v, tid = full
    rows = read_lines(chain_path(v, tid))
    write_lines(chain_path(v, tid), [rows[0], rows[2], rows[1], *rows[3:]])
    assert codes(v, tid)[0] == ("prev_mismatch", 1)
    write_lines(chain_path(v, tid), [rows[0], *rows[2:]])
    assert codes(v, tid)[0] == ("prev_mismatch", 1)


def test_rehashed_deletion_is_seq_gap(full: tuple[DiskVault, str]) -> None:
    v, tid = full
    rows = read_lines(chain_path(v, tid))
    del rows[1]
    rehash_from(rows, 1)
    write_lines(chain_path(v, tid), rows)
    fix_head(v, tid)
    assert codes(v, tid) == [("seq_gap", 1)]


def test_rehashed_handover_renumbering_is_version_gap(vault: DiskVault) -> None:
    tid = vault.create_thread("t", "handover")
    vault.append(tid, "main0001", handover("v1"))
    vault.append(tid, "main0001", handover("v2"))
    rows = read_lines(chain_path(vault, tid))
    rows[1]["version"] = 3
    rehash_from(rows, 1)
    write_lines(chain_path(vault, tid), rows)
    fix_head(vault, tid)
    assert codes(vault, tid) == [("version_gap", 1)]


def test_truncated_tail_is_head_mismatch(full: tuple[DiskVault, str]) -> None:
    v, tid = full
    rows = read_lines(chain_path(v, tid))
    write_lines(chain_path(v, tid), rows[:-1])
    assert codes(v, tid) == [("head_mismatch", -1)]


def test_garbage_line_float_and_duplicate_key_are_schema_invalid(full: tuple[DiskVault, str]) -> None:
    v, tid = full
    path = chain_path(v, tid)
    original = path.read_bytes()
    lines = original.split(b"\n")
    for bad in (b"{not json", lines[2].replace(b'"seq":2', b'"seq":2.0'),
                lines[2][:-1] + b',"seq":2}', b"[1,2,3]"):
        path.write_bytes(b"\n".join([*lines[:2], bad, *lines[3:]]))
        assert codes(v, tid)[0] == ("schema_invalid", 2), bad
    path.write_bytes(original)
    assert v.verify(tid).ok


def test_record_moved_to_another_thread_is_detected(vault: DiskVault) -> None:
    a = vault.create_thread("a", "full")
    b = vault.create_thread("b", "full")
    rec = vault.append(a, "main0001", message("from a"))
    write_lines(chain_path(vault, b), [rec])
    fix_head(vault, b)
    assert codes(vault, b) == [("schema_invalid", 0)]


def test_spliced_fork_is_fork_link_mismatch(vault: DiskVault) -> None:
    tid = vault.create_thread("t", "full")
    vault.append(tid, "main0001", message("q"))
    m1 = vault.append(tid, "main0001", message("a"))
    fork = vault.fork(tid, at_hash=m1["hash"])
    vault.append(tid, fork, message("fork"))
    # 1) the fork's first record points somewhere else
    rows = read_lines(chain_path(vault, tid, fork))
    rehash_from(rows, 0, start_prev="sha256:" + "ab" * 32)
    write_lines(chain_path(vault, tid, fork), rows)
    fix_head(vault, tid, fork)
    assert ("fork_link_mismatch", 0) in codes(vault, tid)
    # 2) the branch claims a fork point that is not in the parent
    bpath = vault.root / "threads" / tid / "branches" / f"{fork}.json"
    b = json.loads(bpath.read_text(encoding="utf-8"))
    b["parent"]["fork_point"]["hash"] = "sha256:" + "ab" * 32
    bpath.write_text(json.dumps(b), encoding="utf-8")
    assert ("fork_link_mismatch", -1) in codes(vault, tid)


def test_parent_cycle_is_reported_not_infinite(vault: DiskVault) -> None:
    tid = vault.create_thread("t", "full")
    m = vault.append(tid, "main0001", message("q"))
    fork = vault.fork(tid, at_hash=m["hash"])
    bpath = vault.root / "threads" / tid / "branches" / "main0001.json"
    b = json.loads(bpath.read_text(encoding="utf-8"))
    b["parent"] = {"branch_id": fork, "fork_point": {"kind": "message", "hash": m["hash"]}}
    bpath.write_text(json.dumps(b), encoding="utf-8")
    assert not vault.verify(tid).ok


def test_missing_and_swapped_blobs(vault: DiskVault) -> None:
    tid = vault.create_thread("t", "handover")
    ref = vault.put_file(tid, "a.txt", "text/plain", b"contract terms")
    vault.append(tid, "main0001", handover(files=[{"sha256": ref["sha256"], "name": "a.txt",
                                                   "description": "terms"}]))
    blob = vault.root / "blobs" / ref["sha256"].removeprefix("sha256:")
    blob.write_bytes(b"other terms")
    assert codes(vault, tid) == [("blob_hash_mismatch", -1)]  # reported once, not per reference
    blob.unlink()
    assert codes(vault, tid) == [("missing_blob", -1)]


# -- signatures (T2) --------------------------------------------------------------------------------
@pytest.fixture
def signed(signed_vault: DiskVault) -> tuple[DiskVault, str]:
    tid = signed_vault.create_thread("t", "full")
    for i in range(3):
        signed_vault.append(tid, "main0001", message(f"m{i}"))
    return signed_vault, tid


def test_signed_records_verify(signed: tuple[DiskVault, str]) -> None:
    v, tid = signed
    rows = read_lines(chain_path(v, tid))
    assert all(r["signature"]["alg"] == "ed25519" for r in rows)
    assert json.loads((v.root / "threads" / tid / "manifest.json").read_text())["signing_keys"]
    assert v.verify(tid).ok


def test_edit_with_recomputed_hashes_fails_on_signature(signed: tuple[DiskVault, str]) -> None:
    v, tid = signed
    rows = read_lines(chain_path(v, tid))
    rows[1]["content"] = "1000 EUR"
    rehash_from(rows, 1)
    write_lines(chain_path(v, tid), rows)
    fix_head(v, tid)
    assert codes(v, tid) == [("signature_invalid", 1)]


def test_stripping_signatures_is_detected(signed: tuple[DiskVault, str], tmp_path: Path) -> None:
    v, tid = signed
    rows = read_lines(chain_path(v, tid))
    rows[1]["content"] = "edited"
    for r in rows[1:]:
        r.pop("signature")
    rehash_from(rows, 1)
    write_lines(chain_path(v, tid), rows)
    fix_head(v, tid)
    assert codes(v, tid) == [("signature_invalid", 1)]
    # even a verifier that does not require signatures sees that the chain stopped being signed
    lax = DiskVault(v.root, log=v.log)
    assert [(i.code, i.index) for b in lax.verify(tid).branches for i in b.issues] == [
        ("signature_invalid", 1)]


def test_attacker_key_in_manifest_is_not_trusted(signed: tuple[DiskVault, str]) -> None:
    v, tid = signed
    attacker = MemoryKeyStore().signer()
    rows = read_lines(chain_path(v, tid))
    rows[0]["content"] = "forged"
    for i, r in enumerate(rows):
        r["prev_hash"] = rows[i - 1]["hash"] if i else None
        r.pop("signature")
        r["hash"] = record_hash(r)
        r["signature"] = attacker.signature(r)
    write_lines(chain_path(v, tid), rows)
    mpath = v.root / "threads" / tid / "manifest.json"
    m = json.loads(mpath.read_text(encoding="utf-8"))
    m["signing_keys"] = [attacker.manifest_entry()]
    m["branches"][0]["head_hash"] = rows[-1]["hash"]
    mpath.write_text(json.dumps(m), encoding="utf-8")
    assert codes(v, tid) == [("signature_invalid", 0)]  # the key store does not know that key
    # Without a key store the forgery passes, and the report says why it cannot be trusted.
    report = DiskVault(v.root, log=v.log).verify(tid)
    assert report.ok and any("keys listed inside the thread" in n for n in report.notices)


def test_signature_does_not_change_hashes(signed: tuple[DiskVault, str]) -> None:
    v, tid = signed
    for r in read_lines(chain_path(v, tid)):
        assert record_hash(r) == r["hash"]  # hash excludes the signature


# -- access log (T13) -------------------------------------------------------------------------------
def test_access_log_edit_is_access_chain_broken(tmp_path: Path) -> None:
    log = FileAccessLog(tmp_path / "access.jsonl")
    for action in ("load", "append", "verify"):
        log.record(client_id="cli", kind="cli", action=action, outcome="allowed")
    assert log.verify() == []
    rows = read_lines(log.path)
    rows[1]["outcome"] = "denied"
    write_lines(log.path, rows)
    issues = log.verify()
    assert [(i.code, i.index) for i in issues] == [("access_chain_broken", 1)]
    write_lines(log.path, [rows[0], rows[2]])  # removing an entry
    assert log.verify()[0].index == 1
