"""Span redaction for exports. Minimal stand-in until Person C's `privacy/` module lands."""

from __future__ import annotations

from threadvault.scanners.basic import scan_text
from threadvault.types import SECRET_KINDS, Record


class ExportRefused(Exception):
    """Export blocked. The message names finding kinds only, never values."""


def apply_profile(text: str, profile: Record) -> str:
    findings = [f for f in scan_text(text) if f.start is not None and f.end is not None]
    if profile["block_on_secrets"]:
        kinds = sorted({f.kind for f in findings if f.kind in SECRET_KINDS})
        if kinds:
            raise ExportRefused(f"blocked: secrets found ({', '.join(kinds)})")
    # Secret kinds are always redacted in exports, whatever the profile lists.
    redact = set(profile["redact"]) | SECRET_KINDS
    spans = sorted((f.start, f.end, f.kind) for f in findings
                   if f.kind in redact and f.start is not None and f.end is not None)
    out, pos = [], 0
    for start, end, kind in spans:
        if start < pos:  # overlapping span already covered
            pos = max(pos, end)
            continue
        out += [text[pos:start], f"[REDACTED:{kind}]"]
        pos = end
    out.append(text[pos:])
    return "".join(out)
