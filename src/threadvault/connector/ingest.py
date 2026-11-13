"""Reference logic for `POST /v1/ingest` (SPEC.md section 8), without the HTTP layer.

The real HTTP service wraps `IngestService.handle`; B's extension can be developed against it today.
Ownership: Person C (it enforces policy and scanners). HTTP-level checks (token, Host, Origin, body
limit) belong in the server wrapper, not here.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from threadvault import schemas
from threadvault.core.accesslog import AccessLog
from threadvault.core.hashing import canonical_json, sha256_bytes
from threadvault.core.vault import Vault
from threadvault.policy.engine import decide, default_profile
from threadvault.scanners.basic import scan_record
from threadvault.types import SECRET_KINDS, Finding, Record

MAX_FILE_BYTES = 50 * 1024 * 1024


class IngestService:
    def __init__(self, vault: Vault, policy: Record | None, log: AccessLog) -> None:
        self._vault, self._policy, self._log = vault, policy, log
        self._accepted: dict[str, tuple[str, Record]] = {}  # request_id -> (body hash, response)

    def handle(self, request: Any) -> Record:
        problems = schemas.errors("ingest_request", request)
        if problems:
            return self._respond(request, "rejected", error="request does not match schema")
        rid: str = request["request_id"]
        client: Record = request["client"]
        kind: str = request["payload"]["kind"]
        body_hash = sha256_bytes(canonical_json(request))

        if rid in self._accepted:
            prev_hash, prev_resp = self._accepted[rid]
            if prev_hash == body_hash:
                return prev_resp
            return self._finish(request, "rejected", error="request_id already used with different content")

        capability = "save_handover" if kind == "handover" else "append"
        if not decide(self._policy, client["client_id"], capability).allowed:
            return self._finish(request, "rejected", outcome="denied", error="not permitted by policy")
        assert self._policy is not None  # decide() allows nothing without a policy

        findings, blocked = self._scan(request["payload"], default_profile(self._policy))
        if blocked:
            return self._finish(request, "rejected", findings=findings, error="blocked by policy")
        if findings and not request.get("acknowledged_findings"):
            return self._finish(request, "needs_confirmation", findings=findings)
        if kind == "handover" and not request["user_reviewed"]:
            return self._finish(request, "rejected", error="handover must be reviewed by the user")

        try:
            thread_id, stored = self._store(request)
        except (ValueError, KeyError) as e:
            return self._finish(request, "rejected", error=str(e)[:200])
        resp = self._finish(request, "accepted", thread_id=thread_id, stored_hash=stored, findings=findings)
        self._accepted[rid] = (body_hash, resp)
        return resp

    # ----------------------------------------------------------------------------------------
    def _scan(self, payload: Record, profile: Record) -> tuple[list[Finding], bool]:
        if payload["kind"] == "file":
            try:
                text = base64.b64decode(payload["file"]["data_base64"], validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                return [], False
            findings = scan_record(text, "$.file")
        elif payload["kind"] == "handover":
            findings = scan_record(payload["content"], "$.content")
        else:
            findings = scan_record([m["content"] for m in payload["messages"]], "$.messages")
        blocked = bool(profile["block_on_secrets"]) and any(f.kind in SECRET_KINDS for f in findings)
        return findings, blocked

    def _store(self, request: Record) -> tuple[str, str]:
        target, payload = request["target"], request["payload"]
        if "new_thread" in target:
            nt = target["new_thread"]
            thread_id = self._vault.create_thread(nt["title"], nt["mode"])
        else:
            thread_id = target["thread_id"]
        data = self._vault.load_thread(thread_id)
        branch_id = str(data.manifest["current_branch"])

        if payload["kind"] == "handover":
            # The vault, not the client, decides provenance (SPEC 8.3).
            meta = {**payload["metadata"], "provenance": "ai-summary-user-saved"}
            rec = self._vault.append(thread_id, branch_id,
                                     {"type": "handover", "content": payload["content"], "metadata": meta})
            return thread_id, str(rec["hash"])
        if payload["kind"] == "messages":
            if data.manifest["mode"] != "full":
                raise ValueError("thread is handover-only; messages are not stored")
            last: Record = {}
            for m in payload["messages"]:
                last = self._vault.append(thread_id, branch_id, {
                    "type": "message", "role": m["role"], "author": m["author"],
                    "created_at": m["created_at"], "content": m["content"],
                    "provenance": "imported-unverified", **({"file_refs": m["file_refs"]} if "file_refs" in m else {})})
            return thread_id, str(last["hash"])
        f = payload["file"]
        raw = base64.b64decode(f["data_base64"], validate=True)
        if len(raw) > MAX_FILE_BYTES or len(raw) != f["size"]:
            raise ValueError("file size invalid")
        ref = self._vault.put_file(thread_id, f["name"], f["media_type"], raw)
        return thread_id, str(ref["sha256"])

    def _finish(self, request: Record, status: str, *, outcome: str | None = None, **kw: Any) -> Record:
        client = request.get("client", {}) if isinstance(request, dict) else {}
        thread_id = kw.get("thread_id") or (request.get("target", {}).get("thread_id")
                                            if isinstance(request.get("target"), dict) else None)
        self._log.record(
            client_id=str(client.get("client_id", "unknown")), kind="extension", action="ingest",
            outcome=outcome or ("allowed" if status != "rejected" else "error"), thread_id=thread_id,
            detail=f"status={status}")
        return self._respond(request, status, **kw)

    @staticmethod
    def _respond(request: Any, status: str, *, findings: list[Finding] | None = None,
                 thread_id: str | None = None, stored_hash: str | None = None,
                 error: str | None = None) -> Record:
        rid = request.get("request_id") if isinstance(request, dict) else None
        resp: Record = {
            "spec_version": "1", "type": "ingest_response",
            "request_id": rid if isinstance(rid, str) and schemas.is_valid_id(rid) else "unknown_request",
            "status": status, "findings": [f.to_schema() for f in findings or []]}
        if thread_id:
            resp["thread_id"] = thread_id
        if stored_hash:
            resp["stored_hash"] = stored_hash
        if error:
            resp["error"] = error
        return resp

