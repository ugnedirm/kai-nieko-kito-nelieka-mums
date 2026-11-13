"""`DiskVault`: the real vault on disk (SPEC.md sections 2-6), behind the `Vault` Protocol.

Layout (SPEC section 2):
    vault/policy.json, vault/access.jsonl, vault/blobs/<hex>,
    vault/threads/<tid>/{manifest.json, branches/<bid>.json, chains/<bid>.jsonl}

Rules this class enforces:
- The vault assigns ids, seq, versions, prev_hash, hash and signatures. A caller that supplies any
  of them gets a ValueError (CLAUDE.md security rule 5).
- Every record is schema-validated before it is written. Chain files are only appended to.
- File references must point at stored blobs; messages are refused in handover-only threads.
- `forget_file` follows SPEC section 5 and writes an access-log entry.

Optional features:
- Signing (`keystore=`): every new record gets an Ed25519 signature; the public key is listed in
  `manifest.signing_keys`; `verify` checks against the key store's trusted keys.
- Encryption at rest (`encrypt=True`, needs a key store): blobs become age files, and each chain
  line is `{"age": "<base64 age ciphertext of the record>"}`. Hashes are over the plaintext record,
  so they are identical with or without encryption. Manifests and branch files stay plaintext
  (thread titles are visible; see THREAT_MODEL section 4).

Concurrency: one writer process per vault. Within a process, writes are serialised by a lock.
"""

from __future__ import annotations

import base64
import binascii
import copy
import shutil
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from threadvault import schemas
from threadvault.core import provenance
from threadvault.core.accesslog import AccessLog, FileAccessLog
from threadvault.core.blobstore import BlobStore
from threadvault.core.crypto_age import AgeCipher, DecryptionError
from threadvault.core.hashing import record_hash
from threadvault.core.ids import (
    Clock,
    check_hash,
    check_id,
    is_hash,
    is_id,
    new_id,
    parse_ts,
    utc_now,
)
from threadvault.core.jsonio import (
    StrictJSONError,
    append_line,
    atomic_write_json,
    loads,
    read_json,
    split_jsonl,
)
from threadvault.core.lineage import ForkError, ThreadSnapshot, lineage, owner_of
from threadvault.core.pack import PackResult, TokenCounter, build_pack
from threadvault.core.render import thread_text
from threadvault.core.signing import KeyStore, Signer
from threadvault.core.verify import VaultVerifyReport, verify_access_chain, verify_snapshot
from threadvault.scanners.engine import scan_record
from threadvault.types import SECRET_KINDS, BranchData, Record, ThreadData, ThreadInfo, VerifyReport

VAULT_ASSIGNED = frozenset({"spec_version", "thread_id", "branch_id", "id", "seq", "version",
                            "prev_hash", "hash", "signature"})
ROOT_BRANCH = "main0001"


class SecretBlockedError(ValueError):
    """Content contains a high-severity secret and the vault was opened with block_secrets."""


class SweepReport(BaseModel):
    threads_deleted: list[str] = []
    files_forgotten: list[str] = []


class DiskVault:
    def __init__(self, root: Path, *, keystore: KeyStore | None = None, sign: bool | None = None,
                 encrypt: bool = False, require_signatures: bool | None = None,
                 block_secrets: bool = False, clock: Clock = utc_now,
                 log: AccessLog | None = None, actor: tuple[str, str] = ("cli", "cli"),
                 token_counter: TokenCounter | None = None) -> None:
        """
        keystore: where signing / encryption keys live (KeyringKeyStore for real use).
        sign: sign new records (default: True when a key store is given).
        encrypt: encrypt blobs and chain records at rest (needs a key store).
        require_signatures: verify fails on unsigned records (default: True whenever a key
            store is given, so stripping every signature cannot pass).
        block_secrets: refuse to store records with high-severity secret findings.
        actor: (client_id, kind) recorded in the access log for vault-level actions.
        """
        self.root = Path(root)
        self._keystore = keystore
        do_sign = keystore is not None if sign is None else sign
        if (do_sign or encrypt) and keystore is None:
            raise ValueError("signing and encryption need a key store")
        self._signer: Signer | None = keystore.signer() if (do_sign and keystore) else None
        self._cipher = AgeCipher(keystore.age_identity()) if (encrypt and keystore) else None
        self._require_sigs = (keystore is not None if require_signatures is None
                              else require_signatures)
        self._block_secrets = block_secrets
        self._clock = clock
        self._lock = threading.RLock()
        self.blobs = BlobStore(self.root / "blobs", self._cipher)
        self.log: AccessLog = log if log is not None else FileAccessLog(self.root / "access.jsonl",
                                                                      clock)
        self._actor = actor
        self._counter = token_counter
        (self.root / "threads").mkdir(parents=True, exist_ok=True)

    # -- paths and low-level io --------------------------------------------------------------------
    def thread_dir(self, thread_id: str) -> Path:
        return self.root / "threads" / check_id(thread_id, "thread id")

    def _chain_path(self, thread_id: str, branch_id: str) -> Path:
        return self.thread_dir(thread_id) / "chains" / f"{check_id(branch_id, 'branch id')}.jsonl"

    def _branch_path(self, thread_id: str, branch_id: str) -> Path:
        return self.thread_dir(thread_id) / "branches" / f"{check_id(branch_id, 'branch id')}.json"

    def _manifest(self, thread_id: str) -> Record:
        path = self.thread_dir(thread_id) / "manifest.json"
        if not path.is_file():
            raise KeyError("no such thread")
        m = read_json(path)
        if not isinstance(m, dict) or schemas.errors("manifest", m):
            raise ValueError("manifest does not match its schema; run verify")
        return m

    def _write_manifest(self, manifest: Record) -> None:
        if schemas.errors("manifest", manifest):
            raise ValueError("manifest would not match its schema")
        atomic_write_json(self.thread_dir(manifest["thread_id"]) / "manifest.json", manifest)

    def _encode_line(self, record: Record) -> Record:
        if self._cipher is None:
            return record
        from threadvault.core.hashing import canonical_json

        ct = self._cipher.encrypt(canonical_json(record))
        return {"age": base64.b64encode(ct).decode("ascii")}

    def _decode_line(self, line: bytes) -> Record | None:
        try:
            obj = loads(line)
        except StrictJSONError:
            return None
        if not isinstance(obj, dict):
            return None
        if set(obj) == {"age"}:
            if self._cipher is None:
                return None
            try:
                plain = self._cipher.decrypt(base64.b64decode(str(obj["age"]), validate=True))
                rec = loads(plain)
            except (binascii.Error, ValueError, DecryptionError):
                return None
            return rec if isinstance(rec, dict) else None
        return obj

    def snapshot(self, thread_id: str) -> ThreadSnapshot:
        """Read a thread's files without trusting them (input for `verify`)."""
        tdir = self.thread_dir(thread_id)
        if not tdir.is_dir():
            raise KeyError("no such thread")
        manifest: Record | None
        try:
            raw = read_json(tdir / "manifest.json")
            manifest = raw if isinstance(raw, dict) else None
        except (OSError, StrictJSONError):
            manifest = None
        branches: dict[str, Record | None] = {}
        for p in sorted((tdir / "branches").glob("*.json")):
            if not is_id(p.stem):
                continue
            try:
                b = read_json(p)
                branches[p.stem] = b if isinstance(b, dict) else None
            except (OSError, StrictJSONError):
                branches[p.stem] = None
        chains: dict[str, list[Record | None]] = {}
        for p in sorted((tdir / "chains").glob("*.jsonl")):
            if is_id(p.stem):
                chains[p.stem] = [self._decode_line(ln) for ln in split_jsonl(p.read_bytes())]
        for bid in branches:
            chains.setdefault(bid, [])
        return ThreadSnapshot(thread_id=thread_id, manifest=manifest, branches=branches,
                              chains=chains)

    def _lineage(self, snap: ThreadSnapshot, branch_id: str) -> list[Record]:
        if branch_id not in snap.branches:
            raise KeyError("no such branch")
        return lineage(snap.branches, snap.chains, branch_id)

    def _log(self, action: str, outcome: str = "allowed", thread_id: str | None = None,
             detail: str | None = None) -> None:
        self.log.record(client_id=self._actor[0], kind=self._actor[1], action=action,
                        outcome=outcome, thread_id=thread_id, detail=detail)

    # -- reading ------------------------------------------------------------------------------------
    def list_threads(self) -> list[ThreadInfo]:
        out: list[ThreadInfo] = []
        for tdir in sorted((self.root / "threads").iterdir()):
            if not (tdir.is_dir() and is_id(tdir.name)):
                continue
            try:
                m = self._manifest(tdir.name)
            except (KeyError, ValueError, OSError):
                continue  # unreadable threads are reported by verify, not listed
            out.append(ThreadInfo(thread_id=m["thread_id"], title=m["title"], mode=m["mode"],
                                  updated_at=m["updated_at"],
                                  branches=[b["branch_id"] for b in m["branches"]]))
        return out

    def load_thread(self, thread_id: str) -> ThreadData:
        snap = self.snapshot(thread_id)
        if snap.manifest is None:
            raise ValueError("manifest unreadable; run verify")
        return ThreadData(
            manifest=copy.deepcopy(snap.manifest),
            branches={bid: BranchData(branch=copy.deepcopy(b) if b else {},
                                      records=[copy.deepcopy(r) for r in snap.chains.get(bid, [])
                                               if r is not None])
                      for bid, b in snap.branches.items()})

    def get_file(self, sha256: str) -> bytes:
        return self.blobs.get(check_hash(sha256))

    def branch_records(self, thread_id: str, branch_id: str | None = None) -> list[Record]:
        """The lineage of a branch (inherited history plus its own records), oldest first."""
        snap = self.snapshot(thread_id)
        bid = branch_id or str((snap.manifest or {}).get("current_branch", ROOT_BRANCH))
        return copy.deepcopy(self._lineage(snap, bid))

    # -- creating -----------------------------------------------------------------------------------
    def create_thread(self, title: str, mode: str, *, expires_at: str | None = None) -> str:
        with self._lock:
            tid = new_id("thr")
            while self.thread_dir(tid).exists():
                tid = new_id("thr")
            now = self._clock()
            manifest: Record = {
                "spec_version": "1", "type": "manifest", "thread_id": tid, "title": title,
                "mode": mode, "created_at": now, "updated_at": now, "current_branch": ROOT_BRANCH,
                "branches": [{"branch_id": ROOT_BRANCH, "head_hash": None}], "files": []}
            if expires_at:
                parse_ts(expires_at)
                manifest["expires_at"] = expires_at
            if self._signer:
                manifest["signing_keys"] = [self._signer.manifest_entry()]
            if self._cipher:
                manifest["encryption"] = {"enabled": True, "scheme": "age"}
            branch = self._branch_doc(tid, ROOT_BRANCH, ROOT_BRANCH, None, now)
            if schemas.errors("manifest", manifest):
                raise ValueError("invalid thread: " + "; ".join(schemas.errors("manifest", manifest)))
            atomic_write_json(self._branch_path(tid, ROOT_BRANCH), branch)
            self._chain_path(tid, ROOT_BRANCH).parent.mkdir(parents=True, exist_ok=True)
            self._chain_path(tid, ROOT_BRANCH).touch()
            self._write_manifest(manifest)
            return tid

    @staticmethod
    def _branch_doc(tid: str, bid: str, label: str, parent: Record | None, now: str) -> Record:
        doc: Record = {"spec_version": "1", "type": "branch", "branch_id": bid, "thread_id": tid,
                       "label": label[:100], "parent": parent, "created_at": now,
                       "created_by": {"kind": "human"}}
        if schemas.errors("branch", doc):
            raise ValueError("invalid branch: " + "; ".join(schemas.errors("branch", doc)))
        return doc

    def fork(self, thread_id: str, from_branch: str | None = None, *, at_hash: str | None = None,
             handover_version: int | None = None, label: str | None = None) -> str:
        """Start a new branch that shares history with `from_branch` up to a fork point (default:
        its latest record). Returns the new branch id."""
        with self._lock:
            snap = self.snapshot(thread_id)
            manifest = self._manifest(thread_id)
            src = from_branch or str(manifest["current_branch"])
            visible = self._lineage(snap, src)
            if handover_version is not None:
                target = next((r for r in visible if r["type"] == "handover"
                               and r["version"] == handover_version), None)
            elif at_hash is not None:
                target = next((r for r in visible if r["hash"] == at_hash), None)
            else:
                target = visible[-1] if visible else None
            if target is None:
                raise ForkError("fork point not found on that branch")
            owner = owner_of(snap.branches, snap.chains, src, target["hash"])
            fork_point: Record = ({"kind": "handover", "version": target["version"]}
                                  if target["type"] == "handover"
                                  else {"kind": "message", "hash": target["hash"]})
            bid = new_id("br")
            while bid in snap.branches:
                bid = new_id("br")
            now = self._clock()
            doc = self._branch_doc(thread_id, bid, label or bid,
                                   {"branch_id": owner, "fork_point": fork_point}, now)
            atomic_write_json(self._branch_path(thread_id, bid), doc)
            self._chain_path(thread_id, bid).touch()
            manifest["branches"].append({"branch_id": bid, "head_hash": None})
            manifest["updated_at"] = now
            self._write_manifest(manifest)
            self._log("fork", thread_id=thread_id, detail=f"branch={bid} parent={owner}")
            return bid

    def set_current_branch(self, thread_id: str, branch_id: str) -> None:
        with self._lock:
            manifest = self._manifest(thread_id)
            if branch_id not in {b["branch_id"] for b in manifest["branches"]}:
                raise KeyError("no such branch")
            manifest["current_branch"] = branch_id
            self._write_manifest(manifest)

    # -- appending ----------------------------------------------------------------------------------
    def append(self, thread_id: str, branch_id: str, partial: Record) -> Record:
        """Append a message or handover. The vault fills in ids, numbering, links and signatures."""
        supplied = VAULT_ASSIGNED & set(partial)
        if supplied:
            raise ValueError("fields assigned by the vault were supplied: "
                             + ", ".join(sorted(supplied)))
        if partial.get("type") not in ("message", "handover"):
            raise ValueError("only message and handover records can be appended")
        return self._append(thread_id, branch_id, dict(partial))

    def _append(self, thread_id: str, branch_id: str, partial: Record) -> Record:
        with self._lock:
            manifest = self._manifest(thread_id)
            snap = self.snapshot(thread_id)
            visible = self._lineage(snap, branch_id)
            kind = partial["type"]
            if kind == "message" and manifest["mode"] != "full":
                raise ValueError("thread is handover-only; messages are not stored")

            rows = snap.chains.get(branch_id, [])
            if rows and (rows[-1] is None or not is_hash(rows[-1].get("hash"))):
                raise ValueError("the last record of this branch is unreadable; run verify")
            own = [r for r in rows if r is not None]
            if own:
                prev: str | None = own[-1]["hash"]
            else:
                branch = snap.branches[branch_id] or {}
                parent = branch.get("parent")
                prev = None
                if parent:
                    prev = visible[-1]["hash"] if visible else None
            rec: Record = {"spec_version": "1", "thread_id": thread_id, "branch_id": branch_id,
                           **copy.deepcopy(partial)}
            if kind == "message":
                rec["seq"] = 1 + max((r["seq"] for r in visible if r["type"] == "message"),
                                     default=-1)
                ids = {r.get("id") for rs in snap.chains.values() for r in rs if r}
                mid = f"msg_{branch_id}_{rec['seq']}"
                while not is_id(mid) or mid in ids:
                    mid = new_id("msg")
                rec["id"] = mid
                provenance.check(rec.get("provenance"))
                if "amends" in rec:
                    self._check_amends(visible, rec)
            elif kind == "handover":
                rec["version"] = 1 + max((r["version"] for r in visible
                                          if r["type"] == "handover"), default=0)
                provenance.check((rec.get("metadata") or {}).get("provenance"))
            self._check_file_refs(rec)
            if self._block_secrets and any(f.kind in SECRET_KINDS and f.severity == "high"
                                           for f in scan_record(rec.get("content"))):
                raise SecretBlockedError("content contains a secret; it was not stored")
            rec["prev_hash"] = prev
            rec["hash"] = record_hash(rec)
            if self._signer:
                rec["signature"] = self._signer.signature(rec)
            problems = schemas.errors(kind, rec)
            if problems:
                raise ValueError(f"invalid {kind}: " + "; ".join(problems))

            append_line(self._chain_path(thread_id, branch_id), self._encode_line(rec))
            for b in manifest["branches"]:
                if b["branch_id"] == branch_id:
                    b["head_hash"] = rec["hash"]
            manifest["updated_at"] = self._clock()
            if self._signer:
                keys = manifest.setdefault("signing_keys", [])
                if self._signer.key_id not in {k["key_id"] for k in keys}:
                    keys.append(self._signer.manifest_entry())
            self._write_manifest(manifest)
            return copy.deepcopy(rec)

    @staticmethod
    def _check_amends(visible: list[Record], rec: Record) -> None:
        target = next((r for r in visible if r["type"] == "message" and r["id"] == rec["amends"]),
                      None)
        if target is None:
            raise ValueError("amends: no such message on this branch")
        if provenance.is_upgrade(target["provenance"], rec["provenance"]):
            raise ValueError("an amendment cannot claim more trust than the original")

    def _check_file_refs(self, rec: Record) -> None:
        refs: list[str] = []
        if rec["type"] == "handover":
            refs = [f["sha256"] for f in rec.get("content", {}).get("files", [])]
        elif rec["type"] == "message":
            refs = list(rec.get("file_refs", []))
        for sha in refs:
            if not self.blobs.has(check_hash(sha)):
                raise ValueError("record references a file that is not in the vault")

    def amend_message(self, thread_id: str, branch_id: str, message_id: str, content: str, *,
                      author: Record, requested_provenance: str = "user-asserted") -> Record:
        """A signed correction: a new message with `amends` = the original's id. The original
        stays in the chain. Provenance is capped at the original's level (never upgraded)."""
        visible = self.branch_records(thread_id, branch_id)
        original = next((r for r in visible if r["type"] == "message" and r["id"] == message_id),
                        None)
        if original is None:
            raise ValueError("amends: no such message on this branch")
        return self.append(thread_id, branch_id, {
            "type": "message", "role": original["role"], "author": author,
            "created_at": self._clock(), "content": content, "amends": message_id,
            "provenance": provenance.at_most(requested_provenance, original["provenance"])})

    def edit_handover(self, thread_id: str, branch_id: str, content: Record, *,
                      author: Record) -> Record:
        """A user's edit of the latest handover becomes the next version. Its provenance is
        `user-asserted`, capped at the edited version's level."""
        visible = self.branch_records(thread_id, branch_id)
        prev = next((r for r in reversed(visible) if r["type"] == "handover"), None)
        if prev is None:
            raise ValueError("no handover to edit on this branch")
        meta = copy.deepcopy(prev["metadata"])
        meta.update(author=author, created_at=self._clock(),
                    provenance=provenance.at_most("user-asserted", meta["provenance"]))
        meta["thread_state"] = {**meta.get("thread_state", {}), "user_reviewed": True}
        return self.append(thread_id, branch_id, {"type": "handover", "content": content,
                                                  "metadata": meta})

    # -- files --------------------------------------------------------------------------------------
    def put_file(self, thread_id: str, name: str, media_type: str, data: bytes, *,
                 expires_at: str | None = None) -> Record:
        with self._lock:
            manifest = self._manifest(thread_id)
            ref: Record = {"sha256": "", "name": name, "media_type": media_type, "size": len(data)}
            if expires_at:
                parse_ts(expires_at)
                ref["expires_at"] = expires_at
            ref["sha256"] = self.blobs.put(data)
            problems = schemas.errors_at("common", "#/$defs/file_ref", ref)
            if problems:
                raise ValueError("invalid file: " + "; ".join(problems))
            existing = next((f for f in manifest["files"] if f["sha256"] == ref["sha256"]), None)
            if existing is not None:
                return dict(existing)
            manifest["files"].append(ref)
            manifest["updated_at"] = self._clock()
            self._write_manifest(manifest)
            return dict(ref)

    def forget_file(self, sha256: str, *, reason: str = "user-forget") -> None:
        """SPEC section 5: delete the blob, tombstone every branch that referenced it, drop it from
        manifest.files, log it. Handover `files` entries stay as chained history."""
        check_hash(sha256)
        with self._lock:
            touched: list[str] = []
            for info in self.list_threads():
                if self._tombstone_thread(info.thread_id, sha256, reason):
                    touched.append(info.thread_id)
            existed = self.blobs.delete(sha256)
            detail = f"file {sha256} reason={reason} blob_deleted={existed}"
            for tid in touched:
                self._log("forget", thread_id=tid, detail=detail)
            if not touched:
                self._log("forget", detail=detail)

    def _tombstone_thread(self, thread_id: str, sha256: str, reason: str) -> bool:
        manifest = self._manifest(thread_id)
        snap = self.snapshot(thread_id)
        in_manifest = any(f["sha256"] == sha256 for f in manifest["files"])
        targets: list[str] = []
        for bid in snap.branches:
            try:
                visible = self._lineage(snap, bid)
            except ForkError:
                continue
            refs = {s for r in visible for s in _record_refs(r)}
            covered = any(_is_tombstone_for(r, sha256) for r in visible)
            if (in_manifest or sha256 in refs) and not covered:
                targets.append(bid)
        # Parents first, so a fork that inherits the tombstone does not get a second one.
        order = {bid: i for i, bid in enumerate(_topo(snap))}
        done_any = in_manifest
        for bid in sorted(targets, key=lambda b: order.get(b, 0)):
            visible = self._lineage(self.snapshot(thread_id), bid)
            if any(_is_tombstone_for(r, sha256) for r in visible):
                continue
            self._append(thread_id, bid, {"type": "tombstone",
                                          "target": {"kind": "file", "sha256": sha256},
                                          "removed_at": self._clock(), "reason": reason})
            done_any = True
        if in_manifest:
            manifest = self._manifest(thread_id)
            manifest["files"] = [f for f in manifest["files"] if f["sha256"] != sha256]
            manifest["updated_at"] = self._clock()
            self._write_manifest(manifest)
        return done_any

    # -- expiry -------------------------------------------------------------------------------------
    def set_expiry(self, thread_id: str, expires_at: str | None) -> None:
        with self._lock:
            manifest = self._manifest(thread_id)
            if expires_at is None:
                manifest.pop("expires_at", None)
            else:
                parse_ts(expires_at)
                manifest["expires_at"] = expires_at
            self._write_manifest(manifest)

    def set_file_expiry(self, thread_id: str, sha256: str, expires_at: str | None) -> None:
        with self._lock:
            manifest = self._manifest(thread_id)
            entry = next((f for f in manifest["files"] if f["sha256"] == sha256), None)
            if entry is None:
                raise KeyError("file not in this thread")
            if expires_at is None:
                entry.pop("expires_at", None)
            else:
                parse_ts(expires_at)
                entry["expires_at"] = expires_at
            self._write_manifest(manifest)

    def sweep(self, now: str | None = None) -> SweepReport:
        """Delete expired threads and forget expired files (tombstone reason `expired`).

        An expired thread is removed entirely (its folder and any blobs no other thread uses).
        An expired file is forgotten everywhere, like `forget_file`.
        """
        with self._lock:
            when: datetime = parse_ts(now or self._clock())
            report = SweepReport()
            for info in self.list_threads():
                manifest = self._manifest(info.thread_id)
                if manifest.get("expires_at") and parse_ts(manifest["expires_at"]) <= when:
                    self._delete_thread(info.thread_id)
                    report.threads_deleted.append(info.thread_id)
            for info in self.list_threads():
                for f in self._manifest(info.thread_id)["files"]:
                    if f.get("expires_at") and parse_ts(f["expires_at"]) <= when \
                            and f["sha256"] not in report.files_forgotten:
                        self.forget_file(f["sha256"], reason="expired")
                        report.files_forgotten.append(f["sha256"])
            self._log("sweep", detail=f"threads_deleted={len(report.threads_deleted)} "
                                      f"files_forgotten={len(report.files_forgotten)}")
            return report

    def _delete_thread(self, thread_id: str) -> None:
        snap = self.snapshot(thread_id)
        mine = _manifest_refs(snap.manifest)
        mine |= {s for rs in snap.chains.values() for r in rs if r for s in _record_refs(r)}
        shutil.rmtree(self.thread_dir(thread_id))
        still_used: set[str] = set()
        for info in self.list_threads():
            other = self.snapshot(info.thread_id)
            still_used |= _manifest_refs(other.manifest)
            still_used |= {s for rs in other.chains.values() for r in rs if r
                           for s in _record_refs(r)}
        for sha in mine - still_used:
            self.blobs.delete(sha)
        self._log("sweep", thread_id=thread_id, detail="thread expired and deleted")

    # -- verify -------------------------------------------------------------------------------------
    def trusted_keys(self) -> dict[str, Any] | None:
        return self._keystore.trusted_keys() if self._keystore else None

    def verify(self, thread_id: str) -> VerifyReport:
        return verify_snapshot(self.snapshot(thread_id), self.blobs.check,
                               trusted_keys=self.trusted_keys(),
                               require_signatures=self._require_sigs)

    def verify_vault(self) -> VaultVerifyReport:
        """Every thread, the access log, the policy file and every blob's hash."""
        threads = [self.verify(p.name) for p in sorted((self.root / "threads").iterdir())
                   if p.is_dir() and is_id(p.name)]
        access: list[Record | None] = []
        path = self.root / "access.jsonl"
        if path.exists():
            for ln in split_jsonl(path.read_bytes()):
                try:
                    v = loads(ln)
                    access.append(v if isinstance(v, dict) else None)
                except StrictJSONError:
                    access.append(None)
        access_issues = verify_access_chain(access)
        policy_ok = True
        if (self.root / "policy.json").exists():
            try:
                policy_ok = not schemas.errors("policy", read_json(self.root / "policy.json"))
            except StrictJSONError:
                policy_ok = False
        orphans = [sha for sha in self.blobs if self.blobs.check(sha) == "blob_hash_mismatch"]
        return VaultVerifyReport(ok=all(t.ok for t in threads) and not access_issues
                                 and policy_ok and not orphans,
                                 threads=threads, access_log_issues=access_issues,
                                 policy_ok=policy_ok, orphan_blob_issues=orphans)

    # -- views --------------------------------------------------------------------------------------
    def _current(self, thread_id: str, branch_id: str | None) -> str:
        return branch_id or str(self._manifest(thread_id)["current_branch"])

    def render_text(self, thread_id: str, branch_id: str | None = None) -> str:
        bid = self._current(thread_id, branch_id)
        report = self.verify(thread_id)
        return thread_text(self._manifest(thread_id), bid, self.branch_records(thread_id, bid),
                           verified=report.ok, notices=report.notices)

    def pack_result(self, thread_id: str, max_tokens: int,
                    branch_id: str | None = None) -> PackResult:
        bid = self._current(thread_id, branch_id)
        records = self.branch_records(thread_id, bid)
        manifest = self._manifest(thread_id)
        order: list[Record] = []
        seen: set[str] = set()
        handovers = [r for r in records if r["type"] == "handover"]
        listed = {f["sha256"]: f for f in manifest["files"]}
        if handovers:
            for f in handovers[-1]["content"]["files"]:
                ref = listed.get(f["sha256"], {"sha256": f["sha256"], "name": f["name"],
                                               "media_type": ""})
                if f["sha256"] not in seen:
                    order.append(ref)
                    seen.add(f["sha256"])
        order += [f for f in manifest["files"] if f["sha256"] not in seen]
        files: list[tuple[Record, bytes | None]] = []
        for ref in order:
            try:
                files.append((ref, self.blobs.get(ref["sha256"])))
            except (FileNotFoundError, ValueError):
                files.append((ref, None))
        return build_pack(thread_id=thread_id, records=records, files=files,
                          max_tokens=max_tokens, verified=self.verify(thread_id).ok,
                          counter=self._counter,
                          counter_name="custom" if self._counter else None)

    def pack(self, thread_id: str, max_tokens: int, branch_id: str | None = None) -> str:
        return self.pack_result(thread_id, max_tokens, branch_id).text


def _record_refs(rec: Record) -> list[str]:
    """File hashes a record references. Tolerates malformed records (they come from disk and are
    not trusted): anything that is not a well-formed hash is ignored."""
    try:
        if rec.get("type") == "handover":
            refs = [f.get("sha256") for f in rec.get("content", {}).get("files", [])]
        elif rec.get("type") == "message":
            refs = list(rec.get("file_refs", []))
        else:
            return []
    except (AttributeError, TypeError):
        return []
    return [s for s in refs if is_hash(s)]


def _manifest_refs(manifest: Record | None) -> set[str]:
    files = (manifest or {}).get("files", [])
    return {str(f["sha256"]) for f in files if isinstance(f, dict) and is_hash(f.get("sha256"))}


def _is_tombstone_for(rec: Record, sha256: str) -> bool:
    target = rec.get("target")
    return (rec.get("type") == "tombstone" and isinstance(target, dict)
            and target.get("sha256") == sha256)


def _topo(snap: ThreadSnapshot) -> list[str]:
    from threadvault.core.lineage import topo_order

    return topo_order(snap.branches)
