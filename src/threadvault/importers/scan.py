"""Prompt-injection and hidden-content scan for imported threads (THREAT_MODEL T3, T9).

Findings carry kind, severity and a location (`message[<i>]`), never the matched text. The
importers already strip hidden characters; this scan tells the user what they contained.
Detection is heuristic: a clean result does not prove the text is safe.
"""

from __future__ import annotations

import re

from threadvault.importers.base import ImportedThread, is_hidden
from threadvault.scanners.basic import scan_text
from threadvault.types import Finding

_PATTERNS = [re.compile(p, re.IGNORECASE) for p in (
    r"disregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)",
    r"forget\s+(?:all\s+|everything\s+)?(?:previous|prior|above|your)\s+(?:instructions|rules)",
    r"you\s+are\s+now\s+(?:in\s+)?(?:dan|developer|an?\s+unrestricted)",
    r"(?:reveal|print|show|repeat)\s+(?:your|the)\s+(?:system|hidden)\s+prompt",
    r"do\s+not\s+(?:tell|inform|mention\s+(?:this\s+)?to)\s+the\s+user",
    r"</?\s*(?:historical_context|system|instructions?)\s*>",
    r"<\|(?:im_start|im_end|system|endoftext)\|>",
    r"\bnew\s+instructions?\s*:",
    r"(?:send|post|upload|exfiltrate)\s+.{0,60}\s+to\s+https?://",
)]


def scan_import(thread: ImportedThread) -> list[Finding]:
    findings: list[Finding] = []
    for i, m in enumerate(thread.messages):
        path = f"message[{i}]"
        findings += [f for f in scan_text(m.content, path)]
        for rx in _PATTERNS:
            findings += [Finding(kind="prompt_injection", severity="medium", path=path,
                                 start=x.start(), end=x.end()) for x in rx.finditer(m.content)]
        findings += [Finding(kind="hidden_content", severity="medium", path=path, start=i, end=i + 1)
                     for i, ch in enumerate(m.content) if is_hidden(ch)]  # importers strip these
    if any(w.startswith("stripped_hidden_chars:") for w in thread.warnings):
        findings.append(Finding(kind="hidden_content", severity="medium", path="import",
                                detail="hidden characters were removed during import"))
    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.kind] = out.get(f.kind, 0) + 1
    return dict(sorted(out.items()))
