"""Selective, signed export of a thread, and verification of an export bundle.

A bundle is a zip:
    export.json                         signed descriptor (below)
    threads/<tid>/manifest.json         manifest rewritten for the export (selected branches/files)
    threads/<tid>/branches/<bid>.json
    threads/<tid>/chains/<bid>.jsonl    plaintext records, unchanged (hashes and signatures intact)
    blobs/<hex>                         included files
    handovers.jsonl                     (mode "handovers" only) the selected handover records

Selective:
- `branches`: export only these branches. Their ancestors are included up to the fork point, so
  every chain still verifies from its first record.
- `files`: include all files, none, or a list of hashes. Left-out files are listed as `withheld`, so
  verification knows their absence is deliberate (not `missing_blob`).
- mode "handovers": only handover records (latest or all), no chains. Each record still verifies by
  its own hash and signature, but the chain links cannot be checked (`chain_complete: false`).

The descriptor lists every other file in the bundle with its SHA-256 and is signed with the
vault's Ed25519 key, so a recipient can check the bundle is complete and unaltered.

Policy: an export sends vault data off the machine. The caller (CLI / connector) must check the
`export` capability and apply the destination's redaction profile first (SPEC sections 9, 10).
As a last line of defence this module refuses to export content with high-severity secrets
unless `allow_secrets=True`.
"""

from __future__ import annotations

import io
import json
import posixpath
import zipfile
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel

from threadvault import schemas
from threadvault.core.disk import DiskVault, SecretBlockedError
from threadvault.core.hashing import record_hash, sha256_bytes
from threadvault.core.ids import check_id, is_hash
from threadvault.core.jsonio import StrictJSONError, dumps_line, loads, split_jsonl
from threadvault.core.lineage import ThreadSnapshot, fork_point_hash, lineage
from threadvault.core.signing import (
    check_signature,
    key_id_for,
    keys_from_manifest,
    load_public_key,
)
from threadvault.core.verify import verify_snapshot
from threadvault.scanners.engine import scan_record
from threadvault.types import SECRET_KINDS, Record, VerifyReport

MAX_BUNDLE_ENTRIES = 10_000
MAX_BUNDLE_BYTES = 512 * 1024 * 1024


class ExportResult(BaseModel):
    path: str
    thread_id: str
    mode: str
    branches: list[str]
    files_included: list[str]
    files_withheld: list[str]
    key_id: str


class ExportVerifyReport(BaseModel):
    ok: bool
    signature_ok: bool
    signer_trusted: bool
    key_id: str | None
    problems: list[str]
    thread: VerifyReport | None = None
    notices: list[str] = []


def _json_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, entries[name])
    return buf.getvalue()


def export_thread(vault: DiskVault, thread_id: str, out_path: Path, *,
                  branches: list[str] | None = None,
                  files: bool | list[str] = True,
                  mode: Literal["chains", "handovers"] = "chains",
                  all_handover_versions: bool = False,
                  allow_secrets: bool = False) -> ExportResult:
    signer = vault._signer
    if signer is None:
        raise ValueError("a signed export needs a vault opened with a key store")
    snap = vault.snapshot(thread_id)
    manifest = snap.manifest
    if manifest is None or schemas.errors("manifest", manifest):
        raise ValueError("thread manifest is invalid; run verify")
    report = vault.verify(thread_id)
    if not report.ok:
        raise ValueError("thread does not verify; refusing to export it")

    wanted = [check_id(b, "branch id") for b in (branches or [manifest["current_branch"]])]
    for b in wanted:
        if b not in snap.branches:
            raise KeyError("no such branch")

    # Which records go out: each branch contributes a prefix of its own chain. A selected branch
    # gives all of it; an ancestor gives records up to the fork point its child needs.
    keep: dict[str, int] = {}  # branch -> number of own records to include

    def need(bid: str, count: int) -> None:
        keep[bid] = max(keep.get(bid, 0), count)
        parent = (snap.branches[bid] or {}).get("parent")
        if parent:
            pid = parent["branch_id"]
            fp = fork_point_hash(lineage(snap.branches, snap.chains, pid), parent["fork_point"])
            own = [r for r in snap.chains.get(pid, []) if r is not None]
            idx = next((i for i, r in enumerate(own) if r["hash"] == fp), -1)
            need(pid, idx + 1)  # 0 if the fork point is further up (inherited by the parent)

    for b in wanted:
        need(b, len([r for r in snap.chains.get(b, []) if r is not None]))
    out_chains: dict[str, list[Record]] = {
        bid: [r for r in snap.chains.get(bid, []) if r is not None][:n] for bid, n in keep.items()}
    chain_view: dict[str, list[Record | None]] = {k: list(v) for k, v in out_chains.items()}

    visible = [r for b in wanted for r in lineage(snap.branches, chain_view, b)]
    handovers = [r for r in visible if r["type"] == "handover"]
    if mode == "handovers":
        if not handovers:
            raise ValueError("no handover to export")
        chosen = handovers if all_handover_versions else [max(handovers, key=lambda r: r["version"])]
        exported_records = list({r["hash"]: r for r in chosen}.values())
    else:
        exported_records = [r for rs in out_chains.values() for r in rs]

    if not allow_secrets:
        findings = [f for r in exported_records for f in scan_record(r.get("content"))]
        if any(f.kind in SECRET_KINDS and f.severity == "high" for f in findings):
            raise SecretBlockedError("thread contains secrets; redact first or pass allow_secrets")

    # Files referenced by what is exported.
    referenced: list[str] = []
    for f in manifest["files"]:
        referenced.append(f["sha256"])
    for r in exported_records:
        if r["type"] == "handover":
            referenced += [f["sha256"] for f in r["content"]["files"]]
        elif r["type"] == "message":
            referenced += list(r.get("file_refs", []))
    referenced = list(dict.fromkeys(referenced))
    tombstoned = {r["target"].get("sha256") for r in exported_records if r["type"] == "tombstone"}
    available = [s for s in referenced if s not in tombstoned and vault.blobs.has(s)]
    if files is True:
        include = available
    elif files is False:
        include = []
    else:
        include = [s for s in available if s in set(files)]
    withheld = [s for s in referenced if s not in include and s not in tombstoned]

    entries: dict[str, bytes] = {}
    base = f"threads/{thread_id}"
    if mode == "chains":
        m = dict(manifest)
        m["branches"] = [{"branch_id": bid, "head_hash": recs[-1]["hash"] if recs else None}
                         for bid, recs in sorted(out_chains.items())]
        m["files"] = [f for f in manifest["files"] if f["sha256"] in include]
        m["current_branch"] = wanted[0]
        m.pop("encryption", None)  # the bundle itself is plaintext
        entries[f"{base}/manifest.json"] = _json_bytes(m)
        for bid, recs in out_chains.items():
            entries[f"{base}/branches/{bid}.json"] = _json_bytes(snap.branches[bid])
            entries[f"{base}/chains/{bid}.jsonl"] = b"".join(dumps_line(r) for r in recs)
    else:
        entries["handovers.jsonl"] = b"".join(dumps_line(r) for r in exported_records)
    for sha in include:
        entries[f"blobs/{sha.removeprefix('sha256:')}"] = vault.blobs.get(sha)

    descriptor: Record = {
        "spec_version": "1", "type": "export", "created_at": vault._clock(),
        "thread_id": thread_id, "mode": mode, "chain_complete": mode == "chains",
        "branches": sorted(out_chains) if mode == "chains" else wanted,
        "files_included": include, "files_withheld": withheld,
        "signing_keys": manifest.get("signing_keys", []),
        "signer": signer.manifest_entry(),
        "entries": [{"path": p, "sha256": sha256_bytes(d)} for p, d in sorted(entries.items())],
    }
    descriptor["signature"] = signer.signature(descriptor)
    entries["export.json"] = _json_bytes(descriptor)
    out_path.write_bytes(_zip(entries))
    vault._log("export", thread_id=thread_id,
               detail=f"mode={mode} branches={len(descriptor['branches'])} files={len(include)} "
                      f"withheld={len(withheld)}")
    return ExportResult(path=str(out_path), thread_id=thread_id, mode=mode,
                        branches=descriptor["branches"], files_included=include,
                        files_withheld=withheld, key_id=signer.key_id)


# -- verifying a bundle -----------------------------------------------------------------------------
def _safe_name(name: str) -> bool:
    return (not name.startswith("/") and "\\" not in name and ".." not in name.split("/")
            and posixpath.normpath(name) == name)


def verify_export(path: Path,
                  trusted_keys: dict[str, Ed25519PublicKey] | None = None) -> ExportVerifyReport:
    """Check a bundle: descriptor signature, every listed file's hash, nothing extra, and then the
    thread itself (chains mode) or each handover's hash and signature (handovers mode)."""
    problems: list[str] = []

    def fail(msg: str, key_id: str | None = None) -> ExportVerifyReport:
        return ExportVerifyReport(ok=False, signature_ok=False, signer_trusted=False,
                                  key_id=key_id, problems=[*problems, msg])

    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return fail("not a zip file")
    infos = zf.infolist()
    if len(infos) > MAX_BUNDLE_ENTRIES or sum(i.file_size for i in infos) > MAX_BUNDLE_BYTES:
        return fail("bundle too large")
    names = [i.filename for i in infos if not i.is_dir()]
    if len(set(names)) != len(names) or not all(_safe_name(n) for n in names):
        return fail("bundle has duplicate or unsafe paths")
    if "export.json" not in names:
        return fail("export.json missing")
    try:
        desc = loads(zf.read("export.json"))
        signer = desc["signer"]
        key = load_public_key(signer["public_key"])
        if key_id_for(key) != signer["key_id"]:
            return fail("signer key_id does not match its key")
    except (StrictJSONError, KeyError, TypeError, ValueError):
        return fail("export.json is malformed")
    key_id = str(signer["key_id"])
    signature_ok = check_signature(desc, {key_id: key})
    trusted = trusted_keys is not None and key_id in trusted_keys
    if not signature_ok:
        problems.append("descriptor signature invalid")
    if trusted_keys is not None and not trusted:
        # Anyone can re-sign a forged bundle with a fresh key; with trusted keys given, an
        # untrusted signer is a failure, not a footnote.
        problems.append("export was signed by a key you do not trust")

    try:
        listed = {str(e["path"]): str(e["sha256"]) for e in desc.get("entries", [])}
        withheld = {str(s) for s in desc.get("files_withheld", [])}
        signing_keys = list(desc.get("signing_keys", []))
    except (TypeError, KeyError, AttributeError):
        return fail("export.json is malformed", key_id)
    # Signatures are mandatory inside a bundle whose thread declares signing keys.
    require_sigs = bool(signing_keys) or trusted_keys is not None
    data: dict[str, bytes] = {}
    for name in names:
        if name == "export.json":
            continue
        if name not in listed:
            problems.append(f"unlisted file in bundle: {name[:100]}")
            continue
        data[name] = zf.read(name)
        if sha256_bytes(data[name]) != listed[name]:
            problems.append(f"file altered: {name[:100]}")
    problems += [f"listed file missing: {p[:100]}" for p in listed if p not in data]

    notices: list[str] = []
    if withheld:
        notices.append(f"{len(withheld)} file(s) were deliberately left out of this export.")
    if not trusted:
        notices.append("The export's signing key is not in your trusted keys: the signature shows "
                       "the bundle is intact, not who made it.")
    thread_report: VerifyReport | None = None
    tid = str(desc.get("thread_id", ""))
    sig_keys = trusted_keys if trusted_keys is not None else {key_id: key}

    if desc.get("mode") == "chains":
        try:
            snap = _snapshot_from_bundle(tid, data)
        except (StrictJSONError, ValueError):
            return fail("bundle thread files are malformed", key_id)

        def blob_check(sha: str) -> str | None:
            if sha in withheld:
                return None
            name = f"blobs/{sha.removeprefix('sha256:')}"
            if not is_hash(sha) or name not in data:
                return "missing_blob"
            return None if sha256_bytes(data[name]) == sha else "blob_hash_mismatch"

        thread_report = verify_snapshot(snap, blob_check, trusted_keys=sig_keys,
                                        require_signatures=require_sigs)
        if not thread_report.ok:
            problems.append("thread does not verify")
    else:
        try:
            records = [loads(ln) for ln in split_jsonl(data.get("handovers.jsonl", b""))]
        except StrictJSONError:
            return fail("handovers.jsonl is malformed", key_id)
        manifest_keys = keys_from_manifest({"signing_keys": signing_keys})
        keys = trusted_keys if trusted_keys is not None else manifest_keys
        if not records:
            problems.append("no handover records in bundle")
        for i, r in enumerate(records):
            if not isinstance(r, dict) or schemas.errors("handover", r):
                problems.append(f"handover {i}: schema_invalid")
            elif r["hash"] != record_hash(r):
                problems.append(f"handover {i}: hash_mismatch")
            elif ("signature" in r or require_sigs) and not check_signature(r, keys):
                problems.append(f"handover {i}: signature_invalid")
            elif "signature" not in r:
                notices.append(f"handover {i} is not signed; only its hash protects it.")
        notices.append("Handover-only export: chain links to earlier records cannot be checked.")
    return ExportVerifyReport(ok=signature_ok and not problems, signature_ok=signature_ok,
                              signer_trusted=trusted, key_id=key_id, problems=problems,
                              thread=thread_report, notices=notices)


def _snapshot_from_bundle(tid: str, data: dict[str, bytes]) -> ThreadSnapshot:
    check_id(tid, "thread id")
    base = f"threads/{tid}/"
    raw_manifest = data.get(base + "manifest.json")
    manifest = loads(raw_manifest) if raw_manifest is not None else None
    branches: dict[str, Record | None] = {}
    chains: dict[str, list[Record | None]] = {}
    for name, body in data.items():
        if name.startswith(base + "branches/") and name.endswith(".json"):
            bid = name[len(base + "branches/"):-len(".json")]
            branches[check_id(bid, "branch id")] = loads(body)
        elif name.startswith(base + "chains/") and name.endswith(".jsonl"):
            bid = name[len(base + "chains/"):-len(".jsonl")]
            rows: list[Record | None] = []
            for ln in split_jsonl(body):
                try:
                    v = loads(ln)
                    rows.append(v if isinstance(v, dict) else None)
                except StrictJSONError:
                    rows.append(None)
            chains[check_id(bid, "branch id")] = rows
    return ThreadSnapshot(thread_id=tid, manifest=manifest if isinstance(manifest, dict) else None,
                          branches=branches, chains=chains)
