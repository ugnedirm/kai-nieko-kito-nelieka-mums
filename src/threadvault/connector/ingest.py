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
from threadvault.privacy.outbound import blocking_secrets, with_secrets
from threadvault.scanners.basic import scan_record
from threadvault.scanners.sanitize import sanitize_file
from threadvault.types import Finding, Record

MAX_FILE_BYTES = 50 * 1024 * 1024
MEDIA_BY_FORMAT = {
    "jpeg": "image/jpeg", "png": "image/png", "pdf": "application/pdf", "text": "text/plain",
}
_OOXML_BY_EXTENSION = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


def media_type_for(fmt: str, name: str) -> str:
    """The stored media type: decided by the vault from the detected format, never taken from the
    client. Office files share one container format, so the file extension picks among the three
    Office types; anything unrecognised is plain `application/octet-stream`."""
    if fmt == "ooxml":
        return _OOXML_BY_EXTENSION.get(name.rsplit(".", 1)[-1].lower(), "application/octet-stream")
    return MEDIA_BY_FORMAT.get(fmt, "application/octet-stream")


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
                raw = base64.b64decode(payload["file"]["data_base64"], validate=True)
            except binascii.Error:
                return [], False
            findings = []
            scanned: Any = []
            path = "$.file"
            try:
                scanned = raw.decode("utf-8")
                findings = scan_record(scanned, path)
            except UnicodeDecodeError:
                pass
            if profile.get("strip_file_metadata"):
                # What the cleaner could not remove is shown to the person, who decides (a file
                # they chose may keep it locally; it is never sent on, see cli/share.py).
                result = sanitize_file(raw)
                findings += [Finding(kind=f.kind, severity=f.severity, path="$.file", detail=f.detail)
                             for f in result.findings if (f.detail or "").startswith("NOT removed")]
        elif payload["kind"] == "handover":
            scanned, path = payload["content"], "$.content"
            findings = scan_record(scanned, path)
        else:
            scanned, path = [m["content"] for m in payload["messages"]], "$.messages"
            findings = scan_record(scanned, path)
        # The block decision reads the whole content with every secret rule; a secret the
        # findings above do not show yet is added, so the person sees why it was refused.
        secrets = blocking_secrets(scanned, path)
        findings = with_secrets(findings, secrets)
        blocked = bool(profile["block_on_secrets"]) and bool(secrets)
        return findings, blocked

    def _prepare_file(self, f: Record) -> tuple[bytes, str]:
        """Decode, check and clean an uploaded file BEFORE anything is created, so a refusal
        leaves nothing behind. The vault, not the client, decides the media type (SPEC 8.6)."""
        raw = base64.b64decode(f["data_base64"], validate=True)
        if len(raw) > MAX_FILE_BYTES or len(raw) != f["size"]:
            raise ValueError("file size invalid")
        result = sanitize_file(raw)
        if default_profile(self._policy)["strip_file_metadata"] if self._policy else True:
            # A file that could not be fully cleaned only gets here after the person acknowledged
            # the findings (handle() asks first), and stays local: sharing skips such files.
            raw = result.cleaned
        return raw, media_type_for(result.format, str(f["name"]))

    def _store(self, request: Record) -> tuple[str, str]:
        target, payload = request["target"], request["payload"]
        prepared = self._prepare_file(payload["file"]) if payload["kind"] == "file" else None
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
        assert prepared is not None
        raw, media_type = prepared
        ref = self._vault.put_file(thread_id, payload["file"]["name"], media_type, raw)
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

