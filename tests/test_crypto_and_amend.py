"""Phase 2: age encryption at rest, Ed25519 primitives, signed amendments, provenance rules."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from tests.conftest import AI, HUMAN, handover, handover_content, make_clock, message
from threadvault.core import crypto_age, provenance
from threadvault.core.crypto_age import AgeCipher, DecryptionError
from threadvault.core.disk import DiskVault
from threadvault.core.pack import approx_tokens
from threadvault.core.signing import MemoryKeyStore, Signer, check_signature, keys_from_manifest


# -- age format --------------------------------------------------------------------------------------
@pytest.mark.parametrize("size", [0, 1, 1000, crypto_age.CHUNK - 1, crypto_age.CHUNK,
                                  crypto_age.CHUNK + 1, 3 * crypto_age.CHUNK])
def test_age_roundtrip_across_chunk_boundaries(size: int) -> None:
    ident = crypto_age.generate_identity()
    data = bytes(i % 251 for i in range(size))
    ct = crypto_age.encrypt(data, [ident.public_key()])
    assert ct.startswith(b"age-encryption.org/v1\n-> X25519 ")
    assert crypto_age.decrypt(ct, ident) == data


def test_age_rejects_wrong_key_tampering_and_truncation() -> None:
    ident, other = crypto_age.generate_identity(), crypto_age.generate_identity()
    data = b"x" * (crypto_age.CHUNK + 10)
    ct = crypto_age.encrypt(data, [ident.public_key()])
    with pytest.raises(DecryptionError):
        crypto_age.decrypt(ct, other)
    flipped = bytearray(ct)
    flipped[-5] ^= 1
    with pytest.raises(DecryptionError):
        crypto_age.decrypt(bytes(flipped), ident)
    header_end = ct.index(b"\n---") + 4
    with pytest.raises(DecryptionError):  # cut at the chunk boundary: last-chunk flag is wrong
        crypto_age.decrypt(ct[: len(ct) - 26], ident)
    with pytest.raises(DecryptionError):  # header MAC covers the stanzas
        crypto_age.decrypt(ct[:20] + b"Y" + ct[21:], ident)
    assert header_end < len(ct)


def test_age_multiple_recipients_and_key_strings() -> None:
    a, b = crypto_age.generate_identity(), crypto_age.generate_identity()
    ct = crypto_age.encrypt(b"shared", [a.public_key(), b.public_key()])
    assert crypto_age.decrypt(ct, b) == b"shared"
    s = crypto_age.identity_to_str(a)
    assert s.startswith("AGE-SECRET-KEY-1")
    assert crypto_age.recipient_to_str(crypto_age.identity_from_str(s).public_key()).startswith("age1")
    r = crypto_age.recipient_to_str(a.public_key())
    assert crypto_age.recipient_from_str(r).public_bytes_raw() == a.public_key().public_bytes_raw()
    with pytest.raises(ValueError):
        crypto_age.recipient_from_str(r[:-1] + ("q" if r[-1] != "q" else "p"))


def test_encrypted_vault_keeps_plaintext_off_disk_and_hashes_unchanged(tmp_path: Path) -> None:
    ks = MemoryKeyStore()
    v = DiskVault(tmp_path / "v", keystore=ks, encrypt=True, clock=make_clock(),
                  token_counter=approx_tokens)
    tid = v.create_thread("t", "full")
    ref = v.put_file(tid, "secret.txt", "text/plain", b"CONFIDENTIAL draft")
    rec = v.append(tid, "main0001", message("the price is 100 EUR", file_refs=[ref["sha256"]]))
    on_disk = b"".join(p.read_bytes() for p in (tmp_path / "v").rglob("*") if p.is_file())
    assert b"CONFIDENTIAL" not in on_disk and b"100 EUR" not in on_disk
    assert v.get_file(ref["sha256"]) == b"CONFIDENTIAL draft"
    assert v.load_thread(tid).branches["main0001"].records[0]["hash"] == rec["hash"]
    assert v.load_thread(tid).manifest["encryption"] == {"enabled": True, "scheme": "age"}
    assert v.verify(tid).ok
    # without the key nothing is readable, and verify says so instead of passing
    blind = DiskVault(tmp_path / "v", log=v.log)
    assert blind.load_thread(tid).branches["main0001"].records == []
    assert not blind.verify(tid).ok


def test_age_cipher_reports_recipient() -> None:
    c = AgeCipher(crypto_age.generate_identity())
    assert c.recipient.startswith("age1") and c.decrypt(c.encrypt(b"x")) == b"x"


# -- Ed25519 primitives -------------------------------------------------------------------------------
def test_signature_covers_every_field_except_hash_and_signature() -> None:
    s = MemoryKeyStore().signer()
    rec = {"type": "message", "content": "a", "hash": "sha256:" + "0" * 64}
    rec["signature"] = s.signature(rec)
    keys = {s.key_id: s.public_key}
    assert check_signature(rec, keys)
    assert check_signature({**rec, "hash": "sha256:" + "1" * 64}, keys)  # hash is not signed
    assert not check_signature({**rec, "content": "b"}, keys)
    assert not check_signature(rec, {})
    assert not check_signature({**rec, "signature": {**rec["signature"], "sig": "!!"}}, keys)


def test_manifest_keys_with_wrong_key_id_are_ignored() -> None:
    s = Signer(MemoryKeyStore().signer()._key)
    other = MemoryKeyStore().signer()
    good = s.manifest_entry()
    bad = {"key_id": s.key_id, "public_key": other.manifest_entry()["public_key"]}
    assert set(keys_from_manifest({"signing_keys": [good]})) == {s.key_id}
    assert keys_from_manifest({"signing_keys": [bad, {"key_id": "x", "public_key": "!!"}]}) == {}


def test_keystore_trusts_only_matching_key_ids() -> None:
    ks, other = MemoryKeyStore(), MemoryKeyStore().signer()
    entry = other.manifest_entry()
    with pytest.raises(ValueError):
        ks.trust(ks.signer().key_id, entry["public_key"])
    ks.trust(entry["key_id"], entry["public_key"])
    assert set(ks.trusted_keys()) == {ks.signer().key_id, other.key_id}


def test_keyring_store_uses_the_os_keychain_api(monkeypatch: pytest.MonkeyPatch) -> None:
    import keyring

    store: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(keyring, "get_password", lambda s, u: store.get((s, u)))
    monkeypatch.setattr(keyring, "set_password", lambda s, u, p: store.__setitem__((s, u), p))
    from threadvault.core.signing import KeyringKeyStore

    ks = KeyringKeyStore("test")
    first = ks.signer().key_id
    assert KeyringKeyStore("test").signer().key_id == first  # persisted, not regenerated
    assert ("threadvault", "test:signing") in store
    ident = ks.age_identity()
    assert ks.age_identity().public_key().public_bytes_raw() == ident.public_key().public_bytes_raw()
    other = MemoryKeyStore().signer().manifest_entry()
    ks.trust(other["key_id"], other["public_key"])
    assert other["key_id"] in KeyringKeyStore("test").trusted_keys()
    assert all("PRIVATE" not in v for v in store.values())
    base64.b64decode(store[("threadvault", "test:signing")], validate=True)


# -- amendments and provenance ------------------------------------------------------------------------
def test_signed_amendment_keeps_original(signed_vault: DiskVault) -> None:
    v = signed_vault
    tid = v.create_thread("t", "full")
    orig = v.append(tid, "main0001", message("price 100 EUR", role="assistant", author=AI,
                                             provenance="provider-verified"))
    fix = v.amend_message(tid, "main0001", orig["id"], "price 110 EUR", author=HUMAN)
    assert fix["amends"] == orig["id"] and fix["role"] == "assistant"
    assert fix["provenance"] == "user-asserted" and "signature" in fix
    recs = v.load_thread(tid).branches["main0001"].records
    assert [r["content"] for r in recs] == ["price 100 EUR", "price 110 EUR"]
    assert v.verify(tid).ok
    assert "(amends " in v.render_text(tid)


def test_amendment_never_upgrades_provenance(vault: DiskVault) -> None:
    tid = vault.create_thread("t", "full")
    orig = vault.append(tid, "main0001", message("scraped", provenance="imported-unverified"))
    fix = vault.amend_message(tid, "main0001", orig["id"], "fixed",
                              author=HUMAN, requested_provenance="provider-verified")
    assert fix["provenance"] == "imported-unverified"
    with pytest.raises(ValueError, match="more trust"):
        vault.append(tid, "main0001", message("x", amends=orig["id"], provenance="user-asserted"))
    with pytest.raises(ValueError, match="no such message"):
        vault.amend_message(tid, "main0001", "msg_nonexistent", "x", author=HUMAN)


def test_handover_edit_is_a_new_version(vault: DiskVault) -> None:
    tid = vault.create_thread("t", "handover")
    vault.append(tid, "main0001", handover("v1 fact"))
    edited = vault.edit_handover(tid, "main0001", handover_content("corrected fact"), author=HUMAN)
    assert edited["version"] == 2 and edited["metadata"]["provenance"] == "user-asserted"
    assert edited["metadata"]["author"] == HUMAN
    assert vault.verify(tid).ok


def test_provenance_order() -> None:
    assert provenance.LEVELS[0] == "provider-verified"
    assert provenance.is_upgrade("user-asserted", "provider-verified")
    assert not provenance.is_upgrade("provider-verified", "imported-unverified")
    assert provenance.at_most("provider-verified", "user-asserted") == "user-asserted"
    assert provenance.at_most("imported-unverified", "user-asserted") == "imported-unverified"
    with pytest.raises(ValueError):
        provenance.check("ai-summary/user-saved")


def test_signing_key_is_listed_in_manifest(signed_vault: DiskVault) -> None:
    tid = signed_vault.create_thread("t", "full")
    m = json.loads((signed_vault.root / "threads" / tid / "manifest.json").read_text())
    assert m["signing_keys"][0]["key_id"].startswith("ed25519:")
