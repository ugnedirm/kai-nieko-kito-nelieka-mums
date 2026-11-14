"""Prompt-injection and hidden-content scan for imported threads (THREAT_MODEL T3, T9).

Findings carry kind, severity and a location (`message[<i>]`), never the matched text. The
importers already strip hidden characters; this scan tells the user what they contained.
Detection is heuristic: a clean result does not prove the text is safe.
"""

from __future__ import annotations

from threadvault.importers.base import ImportedThread, is_hidden
from threadvault.scanners.basic import scan_text
from threadvault.types import Finding


def scan_import(thread: ImportedThread) -> list[Finding]:
    findings: list[Finding] = []
    for i, m in enumerate(thread.messages):
        path = f"message[{i}]"
        findings += [f for f in scan_text(m.content, path)]
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
