"""Minimal regex scanner: a FALLBACK so B and C can build gates before Person A's real scanners land.

Detects only: email, phone, api_key (AWS-style id), connection_string, private_key,
prompt_injection. It does NOT detect names or addresses and has no entropy checks. Same entry
points as the real scanner: `scan_text` and `scan_record`. Findings never contain matched values.
"""

from __future__ import annotations

import re
from typing import Any

from threadvault.types import Finding, Record, Severity

_RULES: list[tuple[str, Severity, re.Pattern[str]]] = [
    ("email", "medium", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("phone", "medium", re.compile(r"\+\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b")),
    ("api_key", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("connection_string", "high", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@]+@[^\s/]+")),
    ("private_key", "high", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("prompt_injection", "medium",
     re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.IGNORECASE)),
]


def scan_text(text: str, path: str = "$") -> list[Finding]:
    return [Finding(kind=kind, severity=sev, path=path, start=m.start(), end=m.end())
            for kind, sev, rx in _RULES for m in rx.finditer(text)]


def scan_record(obj: Any, path: str = "$") -> list[Finding]:
    """Scan every string in a JSON-like structure; `path` says where each finding is."""
    if isinstance(obj, str):
        return scan_text(obj, path)
    if isinstance(obj, dict):
        return [f for k, v in obj.items() for f in scan_record(v, f"{path}.{k}")]
    if isinstance(obj, list):
        return [f for i, v in enumerate(obj) for f in scan_record(v, f"{path}[{i}]")]
    return []


def scan_thread_records(records: list[Record]) -> list[Finding]:
    return [f for r in records for f in scan_record(r.get("content"), f"{r['type']}:{r.get('seq', r.get('version'))}")]
