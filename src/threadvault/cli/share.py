"""What leaves the vault when a thread is continued in another AI ("Continue here").

Text: the context pack, hidden by the destination's profile, secrets block (viewer.share_text).
Files, only if the destination's profile allows attachments:
- text files are redacted the same way and wrapped as data (so the AI that reads the upload is
  told it is information, not instructions, and the file is flagged if it looks like an order);
- pictures, PDFs and Office files go only if the cleaner confirms nothing hidden remains in the
  stored copy (anything else is skipped and said so, never sent silently).
Nothing is sent by this module: the caller decides what to do with the result.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from threadvault.cli import viewer
from threadvault.core.pack import file_context
from threadvault.core.vault import Vault
from threadvault.policy.engine import destination_profile
from threadvault.privacy.outbound import Refused, prepare_file
from threadvault.scanners.sanitize import sanitize_file
from threadvault.types import Record

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024


@dataclass
class Share:
    text: str | None = None
    hidden: dict[str, int] = field(default_factory=dict)
    files: list[dict[str, object]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # file names left out, with the reason
    problem: str | None = None


def prepare(vault: Vault, policy: Record | None, thread_id: str, dest: str) -> Share:
    text, hidden, problem = viewer.share_text(vault, policy, thread_id, dest)
    if problem or text is None:
        return Share(problem=problem or "nothing to share")
    out = Share(text=text, hidden=hidden)
    profile = destination_profile(policy, dest)
    if not profile or not profile.get("allow_attachments"):
        return out
    total = 0
    for f in vault.load_thread(thread_id).manifest.get("files", []):
        name = str(f["name"])
        try:
            data = vault.get_file(str(f["sha256"]))
        except (KeyError, OSError, ValueError):
            out.skipped.append(f"{name} (not available)")
            continue
        if len(data) > MAX_FILE_BYTES or total + len(data) > MAX_TOTAL_BYTES:
            out.skipped.append(f"{name} (too large to send)")
            continue
        try:
            prepared = prepare_file(policy, dest, data)
        except Refused:
            continue
        if prepared.reason and prepared.reason.startswith("binary"):
            result = sanitize_file(data)
            if not result.complete:
                out.skipped.append(f"{name} (may carry hidden data)")
                continue
            payload, media = result.cleaned, str(f.get("media_type", "application/octet-stream"))
        elif prepared.blocked:
            out.skipped.append(f"{name} (contains secrets)")
            continue
        else:
            wrapped = file_context(name, str(f["sha256"]), "text/plain", prepared.text)
            payload, media = wrapped.encode("utf-8"), "text/plain"
            for k, n in prepared.counts().items():
                out.hidden[k] = out.hidden.get(k, 0) + n
        total += len(payload)
        out.files.append({"name": name, "media_type": media, "size": len(payload),
                          "data_base64": base64.b64encode(payload).decode("ascii")})
    return out
