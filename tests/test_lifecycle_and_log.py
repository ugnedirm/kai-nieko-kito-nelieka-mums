"""Phase 3: forget with tombstones, expiry and sweep (T12); the file access log and viewer (T13, T14)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import handover, message
from threadvault import schemas
from threadvault.core.accesslog import WITHHELD, FileAccessLog, filter_entries, format_entries
from threadvault.core.disk import DiskVault


def file_ref(v: DiskVault, tid: str, data: bytes = b"CONFIDENTIAL terms") -> dict[str, str]:
    return v.put_file(tid, "terms.txt", "text/plain", data)


def ho_files(ref: dict[str, str]) -> list[dict[str, str]]:
    return [{"sha256": ref["sha256"], "name": "terms.txt", "description": "terms"}]


# -- forget -----------------------------------------------------------------------------------------
def test_forget_follows_spec_section_5(vault: DiskVault) -> None:
    tid = vault.create_thread("t", "handover")
    ref = file_ref(vault, tid)
    vault.append(tid, "main0001", handover(files=ho_files(ref)))
    vault.forget_file(ref["sha256"])

    with pytest.raises(FileNotFoundError):
        vault.get_file(ref["sha256"])
    data = vault.load_thread(tid)
    assert data.manifest["files"] == []
    last = data.branches["main0001"].records[-1]
    assert last["type"] == "tombstone" and last["reason"] == "user-forget"
    assert last["target"] == {"kind": "file", "sha256": ref["sha256"]}
    assert schemas.is_valid("tombstone", last)
    # the handover still names the file (chained history), the tombstone covers it
    assert data.branches["main0001"].records[0]["content"]["files"][0]["sha256"] == ref["sha256"]
    assert vault.verify(tid).ok
    entry = vault.log.entries()[-1]
    assert entry["action"] == "forget" and entry["thread_id"] == tid
    assert b"CONFIDENTIAL" not in b"".join(p.read_bytes() for p in vault.root.rglob("*")
                                           if p.is_file())


def test_forget_tombstones_every_referencing_branch_and_thread(vault: DiskVault) -> None:
    a = vault.create_thread("a", "full")
    b = vault.create_thread("b", "handover")
    ref = file_ref(vault, a)
    m0 = vault.append(a, "main0001", message("see file"))
    fork = vault.fork(a, at_hash=m0["hash"])
    vault.append(a, fork, message("attached", file_refs=[ref["sha256"]]))  # only the fork refs it
    vault.append(b, "main0001", handover(files=ho_files(ref)))
    other = vault.create_thread("c", "full")  # never referenced the file

    vault.forget_file(ref["sha256"])
    for tid in (a, b):
        assert vault.verify(tid).ok, tid
    tomb = lambda tid, bid: [r for r in vault.load_thread(tid).branches[bid].records
                             if r["type"] == "tombstone"]
    assert len(tomb(a, "main0001")) == 1  # manifest listed it: every branch gets one
    assert len(tomb(a, fork)) == 1
    assert len(tomb(b, "main0001")) == 1
    assert vault.load_thread(other).branches["main0001"].records == []
    assert {e["thread_id"] for e in vault.log.entries() if e["action"] == "forget"} == {a, b}


def test_fork_made_after_forget_at_an_earlier_point_still_verifies(vault: DiskVault) -> None:
    """Regression found by the property tests: the fork inherits a reference to the forgotten
    file but not the tombstone (which comes after the fork point)."""
    tid = vault.create_thread("t", "full")
    ref = file_ref(vault, tid)
    m = vault.append(tid, "main0001", message("attached", file_refs=[ref["sha256"]]))
    vault.forget_file(ref["sha256"])
    fork = vault.fork(tid, at_hash=m["hash"])
    vault.append(tid, fork, message("later"))
    assert vault.verify(tid).ok


def test_forget_without_tombstone_would_be_missing_blob(vault: DiskVault) -> None:
    tid = vault.create_thread("t", "handover")
    ref = file_ref(vault, tid)
    vault.append(tid, "main0001", handover(files=ho_files(ref)))
    vault.blobs.delete(ref["sha256"])  # deleting behind the vault's back is tampering
    # one issue, although both the manifest and the handover reference the file
    assert [i.code for b in vault.verify(tid).branches for i in b.issues] == ["missing_blob"]


def test_forgotten_but_lingering_blob_is_flagged(vault: DiskVault) -> None:
    tid = vault.create_thread("t", "handover")
    ref = file_ref(vault, tid)
    vault.append(tid, "main0001", handover(files=ho_files(ref)))
    data = vault.get_file(ref["sha256"])
    vault.forget_file(ref["sha256"])
    vault.blobs.put(data)  # the "forget doesn't forget" bug, simulated
    report = vault.verify(tid)
    assert report.ok and any("was forgotten but its blob" in n for n in report.notices)


# -- expiry and sweep -------------------------------------------------------------------------------
def test_sweep_forgets_expired_files_and_deletes_expired_threads(vault: DiskVault) -> None:
    keep = vault.create_thread("keep", "handover")
    doomed = vault.create_thread("doomed", "handover", expires_at="2026-11-15T00:00:00Z")
    shared = vault.put_file(keep, "shared.txt", "text/plain", b"shared bytes")
    vault.put_file(doomed, "shared.txt", "text/plain", b"shared bytes")
    only_doomed = vault.put_file(doomed, "mine.txt", "text/plain", b"only in doomed")
    temp = vault.put_file(keep, "temp.txt", "text/plain", b"temporary",
                          expires_at="2026-11-14T12:00:00Z")
    vault.append(keep, "main0001", handover(files=ho_files(temp)))

    early = vault.sweep(now="2026-11-14T11:00:00Z")
    assert early.threads_deleted == [] and early.files_forgotten == []

    mid = vault.sweep(now="2026-11-14T13:00:00Z")
    assert mid.files_forgotten == [temp["sha256"]] and mid.threads_deleted == []
    tomb = vault.load_thread(keep).branches["main0001"].records[-1]
    assert tomb["type"] == "tombstone" and tomb["reason"] == "expired"
    assert vault.verify(keep).ok

    late = vault.sweep(now="2026-11-16T00:00:00Z")
    assert late.threads_deleted == [doomed]
    assert not (vault.root / "threads" / doomed).exists()
    assert vault.blobs.has(shared["sha256"])  # still used by "keep"
    assert not vault.blobs.has(only_doomed["sha256"])
    assert any(e["action"] == "sweep" for e in vault.log.entries())


def test_expiry_can_be_set_and_cleared(vault: DiskVault) -> None:
    tid = vault.create_thread("t", "handover")
    ref = file_ref(vault, tid)
    vault.set_expiry(tid, "2027-01-01T00:00:00Z")
    vault.set_file_expiry(tid, ref["sha256"], "2026-12-01T00:00:00Z")
    m = vault.load_thread(tid).manifest
    assert m["expires_at"] == "2027-01-01T00:00:00Z" and m["files"][0]["expires_at"]
    vault.set_expiry(tid, None)
    assert "expires_at" not in vault.load_thread(tid).manifest
    with pytest.raises(ValueError):
        vault.set_expiry(tid, "next tuesday")


# -- access log -------------------------------------------------------------------------------------
def test_file_access_log_appends_a_valid_chain(tmp_path: Path) -> None:
    log = FileAccessLog(tmp_path / "access.jsonl", clock=lambda: "2026-11-14T09:00:00Z")
    e0 = log.record(client_id="claude-desktop", kind="ai", action="load", outcome="allowed",
                    thread_id="thr_full0001")
    e1 = log.record(client_id="gpt-reader", kind="ai", action="append", outcome="denied")
    assert (e0["seq"], e1["seq"]) == (0, 1) and e1["prev_hash"] == e0["hash"]
    assert all(schemas.is_valid("access_entry", e) for e in log.entries())
    # a fresh instance continues the same chain
    e2 = FileAccessLog(log.path).record(client_id="cli", kind="cli", action="verify",
                                        outcome="allowed")
    assert e2["seq"] == 2 and e2["prev_hash"] == e1["hash"] and log.verify() == []


def test_access_log_withholds_details_that_look_secret(tmp_path: Path) -> None:
    log = FileAccessLog(tmp_path / "access.jsonl")
    e = log.record(client_id="cli", kind="cli", action="ingest", outcome="error",
                   detail="failed for key AKIAIOSFODNN7EXAMPLE from maria@example.com")
    assert e["detail"] == WITHHELD
    assert "AKIA" not in log.path.read_text(encoding="utf-8")
    ok = log.record(client_id="cli", kind="cli", action="ingest", outcome="allowed",
                    detail="status=accepted")
    assert ok["detail"] == "status=accepted"


def test_access_log_rejects_invalid_entries(tmp_path: Path) -> None:
    log = FileAccessLog(tmp_path / "access.jsonl")
    with pytest.raises(ValueError):
        log.record(client_id="cli", kind="cli", action="rm -rf", outcome="allowed")
    with pytest.raises(ValueError):
        log.record(client_id="cli", kind="root", action="load", outcome="allowed")
    assert not log.path.exists()


def test_access_log_refuses_to_extend_a_broken_tail(tmp_path: Path) -> None:
    log = FileAccessLog(tmp_path / "access.jsonl")
    log.record(client_id="cli", kind="cli", action="load", outcome="allowed")
    with open(log.path, "ab") as fh:
        fh.write(b'{"half a line\n')
    with pytest.raises(RuntimeError):
        log.record(client_id="cli", kind="cli", action="load", outcome="allowed")


def test_viewer_filters_and_shows_chain_status(tmp_path: Path) -> None:
    log = FileAccessLog(tmp_path / "access.jsonl")
    log.record(client_id="claude-desktop", kind="ai", action="load", outcome="allowed",
               thread_id="thr_full0001")
    log.record(client_id="gpt-reader", kind="ai", action="append", outcome="denied",
               thread_id="thr_full0001", detail="capability 'append' not granted")
    log.record(client_id="cli", kind="cli", action="verify", outcome="allowed")
    denied = filter_entries(log.entries(), outcome="denied")
    assert [e["actor"]["client_id"] for e in denied] == ["gpt-reader"]
    assert len(filter_entries(log.entries(), thread_id="thr_full0001")) == 2
    text = format_entries(log.entries(), issues=log.verify())
    assert text.splitlines()[0] == "chain: ok (3 entries)"
    assert "gpt-reader" in text and "denied" in text
    broken = format_entries(log.entries(), issues=[*log.verify(), *FileAccessLog(
        tmp_path / "x.jsonl").verify()] or None)
    assert broken.startswith("chain: not checked")
    tail = format_entries(log.entries(), issues=[], limit=1)
    assert "gpt-reader" not in tail and "verify" in tail


def test_viewer_neutralises_control_characters() -> None:
    entry = {"seq": 0, "ts": "t", "actor": {"client_id": "evil\x1b[2J", "kind": "ai"},
             "action": "load", "outcome": "allowed"}
    assert "\x1b" not in format_entries([entry])
