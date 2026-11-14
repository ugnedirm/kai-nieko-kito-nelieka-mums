"""Phase 2/3: RFC 3161 timestamps (mock TSA, no network) and selective signed export."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from tests.conftest import handover, make_clock, message
from threadvault.core import timestamps as ts
from threadvault.core.disk import DiskVault, SecretBlockedError
from threadvault.core.export import export_thread, verify_export
from threadvault.core.pack import approx_tokens
from threadvault.core.signing import MemoryKeyStore


# -- RFC 3161 -----------------------------------------------------------------------------------------
def fake_tsa(*, status: int = 0, wrong_digest: bool = False, wrong_nonce: bool = False,
             seen: list[bytes] | None = None) -> ts.Transport:
    """A TSA that answers with a structurally valid (unsigned) TimeStampResp."""

    def answer(url: str, body: bytes) -> bytes:
        if seen is not None:
            seen.append(body)
        req = ts.children(ts.parse(body)[1])
        imprint = req[1]
        digest = ts.children(imprint[1])[1][1]
        nonce = int.from_bytes(req[2][1], "big", signed=True)
        if wrong_digest:
            digest = bytes(32)
        if wrong_nonce:
            nonce += 1
        tst = ts.seq(ts.der_int(1), ts.der_oid("1.2.3.4"),
                     ts.seq(ts.seq(ts.der_oid(ts.OID_SHA256), b"\x05\x00"), ts.tlv(0x04, digest)),
                     ts.der_int(42), ts.tlv(0x18, b"20261114090000Z"), ts.der_int(nonce))
        encap = ts.seq(ts.der_oid(ts.OID_TST_INFO), ts.tlv(0xA0, ts.tlv(0x04, tst)))
        signed_data = ts.seq(ts.der_int(3), ts.tlv(0x31, b""), encap, ts.tlv(0x31, b""))
        token = ts.seq(ts.der_oid(ts.OID_SIGNED_DATA), ts.tlv(0xA0, signed_data))
        parts = [ts.seq(ts.der_int(status))] + ([token] if status in (0, 1) else [])
        return ts.seq(*parts)

    return answer


HASH = "sha256:" + "ab" * 32


def test_timestamp_request_and_storage(tmp_path: Path) -> None:
    seen: list[bytes] = []
    token = ts.request_timestamp(HASH, "https://tsa.example/", transport=fake_tsa(seen=seen))
    assert token.gen_time == "20261114090000Z" and token.serial == 42 and token.policy == "1.2.3.4"
    assert bytes.fromhex("ab" * 32) in seen[0] and len(seen[0]) < 100  # only the hash is sent
    path = ts.store_token(tmp_path, token)
    assert path.name == "ab" * 32 + ".tsr"
    assert ts.check_stored(tmp_path, HASH) == "20261114090000Z"
    assert ts.check_stored(tmp_path, "sha256:" + "cd" * 32) is None


@pytest.mark.parametrize(("kwargs", "message"), [
    ({"status": 2}, "refused"), ({"wrong_digest": True}, "imprint"), ({"wrong_nonce": True}, "nonce")])
def test_timestamp_responses_are_checked(kwargs: dict[str, object], message: str) -> None:
    with pytest.raises(ts.TimestampError, match=message):
        ts.request_timestamp(HASH, "https://tsa.example/", transport=fake_tsa(**kwargs))  # type: ignore[arg-type]


@pytest.mark.parametrize("garbage", [b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", b"\x02\x01\x00",
                                     b"\x30\x03\x30\x01\x02", b"\x30\x05\x30\x03\x02\x01\x00"])
def test_hostile_tsa_responses_raise_cleanly(garbage: bytes) -> None:
    with pytest.raises(ts.TimestampError):
        ts.request_timestamp(HASH, "https://tsa.example/", transport=lambda u, b: garbage)


def test_der_helpers_roundtrip() -> None:
    for n in (0, 1, 127, 128, 255, 256, 2**62):
        tag, body, _ = ts.parse(ts.der_int(n))
        assert tag == 0x02 and int.from_bytes(body, "big", signed=True) == n
    assert ts.oid_str(ts.parse(ts.der_oid(ts.OID_SHA256))[1]) == ts.OID_SHA256
    big = ts.tlv(0x04, b"x" * 300)
    assert ts.parse(big)[1] == b"x" * 300
    with pytest.raises(ts.TimestampError):
        ts.request_timestamp(HASH, "file:///etc/passwd")


# -- export --------------------------------------------------------------------------------------------
@pytest.fixture
def ks() -> MemoryKeyStore:
    return MemoryKeyStore()


@pytest.fixture
def sv(tmp_path: Path, ks: MemoryKeyStore) -> DiskVault:
    return DiskVault(tmp_path / "v", keystore=ks, clock=make_clock(), token_counter=approx_tokens)


def build_thread(v: DiskVault) -> tuple[str, str, dict[str, str], dict[str, str]]:
    tid = v.create_thread("export me", "full")
    a = v.put_file(tid, "a.txt", "text/plain", b"file A")
    b = v.put_file(tid, "b.txt", "text/plain", b"file B")
    v.append(tid, "main0001", message("q"))
    m1 = v.append(tid, "main0001", message("a", file_refs=[a["sha256"]]))
    v.append(tid, "main0001", message("main only"))
    v.append(tid, "main0001", handover(files=[{"sha256": b["sha256"], "name": "b.txt",
                                               "description": "B"}]))
    fork = v.fork(tid, at_hash=m1["hash"])
    v.append(tid, fork, message("fork reply"))
    return tid, fork, a, b


def test_full_export_verifies_with_trusted_key(sv: DiskVault, ks: MemoryKeyStore,
                                               tmp_path: Path) -> None:
    tid, _, a, b = build_thread(sv)
    res = export_thread(sv, tid, tmp_path / "out.zip")
    assert res.files_withheld == [] and set(res.files_included) == {a["sha256"], b["sha256"]}
    report = verify_export(tmp_path / "out.zip", ks.trusted_keys())
    assert report.ok and report.signature_ok and report.signer_trusted and report.thread
    assert report.thread.ok
    assert sv.log.entries()[-1]["action"] == "export"
    untrusted = verify_export(tmp_path / "out.zip")
    assert untrusted.ok and not untrusted.signer_trusted
    assert any("not in your trusted keys" in n for n in untrusted.notices)


def test_selective_branch_export_cuts_ancestor_at_fork_point(sv: DiskVault, ks: MemoryKeyStore,
                                                            tmp_path: Path) -> None:
    tid, fork, _, _ = build_thread(sv)
    export_thread(sv, tid, tmp_path / "fork.zip", branches=[fork], files=False)
    zf = zipfile.ZipFile(tmp_path / "fork.zip")
    main_chain = zf.read(f"threads/{tid}/chains/main0001.jsonl").decode()
    assert "main only" not in main_chain and len(main_chain.splitlines()) == 2
    assert not any(n.startswith("blobs/") for n in zf.namelist())
    report = verify_export(tmp_path / "fork.zip", ks.trusted_keys())
    assert report.ok, report.problems
    assert any("deliberately left out" in n for n in report.notices)


def test_handover_only_export(sv: DiskVault, ks: MemoryKeyStore, tmp_path: Path) -> None:
    tid, _, _, b = build_thread(sv)
    res = export_thread(sv, tid, tmp_path / "h.zip", mode="handovers", files=[b["sha256"]])
    zf = zipfile.ZipFile(tmp_path / "h.zip")
    assert "handovers.jsonl" in zf.namelist()
    assert not any(n.startswith("threads/") for n in zf.namelist())
    assert res.files_included == [b["sha256"]]
    assert b"main only" not in b"".join(zf.read(n) for n in zf.namelist())
    report = verify_export(tmp_path / "h.zip", ks.trusted_keys())
    assert report.ok and any("cannot be checked" in n for n in report.notices)


def _rewrite(src: Path, dst: Path, change: dict[str, bytes | None]) -> None:
    zin = zipfile.ZipFile(src)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        for n in zin.namelist():
            if n in change:
                if change[n] is not None:
                    zout.writestr(n, change[n])  # type: ignore[arg-type]
            else:
                zout.writestr(n, zin.read(n))
        for n, data in change.items():
            if n not in zin.namelist() and data is not None:
                zout.writestr(n, data)
    dst.write_bytes(buf.getvalue())


def test_tampered_bundles_fail(sv: DiskVault, ks: MemoryKeyStore, tmp_path: Path) -> None:
    tid, _, a, _ = build_thread(sv)
    good = tmp_path / "good.zip"
    export_thread(sv, tid, good)
    blob = f"blobs/{a['sha256'].removeprefix('sha256:')}"
    chain = f"threads/{tid}/chains/main0001.jsonl"
    desc = json.loads(zipfile.ZipFile(good).read("export.json"))
    desc_no_withheld = dict(desc, files_withheld=[*desc["files_withheld"], a["sha256"]])
    cases: dict[str, dict[str, bytes | None]] = {
        "altered blob": {blob: b"evil"},
        "removed blob": {blob: None},
        "extra file": {"payload.exe": b"MZ"},
        "edited chain": {chain: zipfile.ZipFile(good).read(chain).replace(b'"q"', b'"Q"')},
        "edited descriptor": {"export.json": json.dumps(desc_no_withheld).encode()},
        "unsafe path": {"../escape.txt": b"x"},
    }
    for name, change in cases.items():
        bad = tmp_path / f"{name.replace(' ', '_')}.zip"
        _rewrite(good, bad, change)
        report = verify_export(bad, ks.trusted_keys())
        assert not report.ok, name
        assert "evil" not in json.dumps(report.model_dump())


def test_export_refuses_unsigned_vaults_secrets_and_broken_threads(tmp_path: Path,
                                                                  vault: DiskVault) -> None:
    tid = vault.create_thread("t", "full")
    vault.append(tid, "main0001", message("x"))
    with pytest.raises(ValueError, match="key store"):
        export_thread(vault, tid, tmp_path / "x.zip")

    sv = DiskVault(tmp_path / "s", keystore=MemoryKeyStore(), clock=make_clock())
    tid = sv.create_thread("t", "full")
    sv.append(tid, "main0001", message("key AKIAIOSFODNN7EXAMPLE"))
    with pytest.raises(SecretBlockedError):
        export_thread(sv, tid, tmp_path / "s.zip")
    export_thread(sv, tid, tmp_path / "s.zip", allow_secrets=True)

    chain = sv.root / "threads" / tid / "chains" / "main0001.jsonl"
    chain.write_bytes(chain.read_bytes().replace(b"AKIA", b"AKIB"))
    with pytest.raises(ValueError, match="does not verify"):
        export_thread(sv, tid, tmp_path / "t.zip", allow_secrets=True)


def test_encrypted_vault_exports_plaintext_bundle(tmp_path: Path) -> None:
    ks = MemoryKeyStore()
    v = DiskVault(tmp_path / "e", keystore=ks, encrypt=True, clock=make_clock())
    tid = v.create_thread("t", "full")
    v.append(tid, "main0001", message("readable after export"))
    export_thread(v, tid, tmp_path / "e.zip")
    report = verify_export(tmp_path / "e.zip", ks.trusted_keys())
    assert report.ok
    assert b"readable after export" in zipfile.ZipFile(tmp_path / "e.zip").read(
        f"threads/{tid}/chains/main0001.jsonl")
