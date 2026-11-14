"""Find private data in text so it can be redacted (SPEC section 9).

Regex detectors only (no downloads, no network). Kinds match the `redact` enum in
policy.schema.json: email, phone, api_key, secret, person, address, national_id, iban.

`Span.value` holds the matched text. It exists only in memory, so the caller can replace it; it
MUST NOT be logged or returned to a client. Use `Span.finding()` for anything that leaves.

Limits of the regex fallback: `person` only finds names after a cue ("I'm", "my name is",
"Dr.", ...) or names already in the pseudonym map; `address` only finds simple street forms.
Presidio / local NER can be added later as an extra detector with the same `Span` output.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from threadvault.types import Finding, Severity

REDACT_KINDS = ("email", "phone", "api_key", "secret", "person", "address", "national_id", "iban")
_SEVERITY: dict[str, Severity] = {"api_key": "high", "secret": "high"}

_UP = "A-ZĄČĘĖĮŠŲŪŽÄÖÜÕ"  # capital letters incl. Lithuanian/Estonian/German
_NAME = rf"[{_UP}][\w'’-]+"


@dataclass(frozen=True)
class Span:
    kind: str
    start: int
    end: int
    value: str

    def finding(self, path: str) -> Finding:
        """The safe, value-free form of this span."""
        return Finding(kind=self.kind, severity=_SEVERITY.get(self.kind, "medium"), path=path,
                       start=self.start, end=self.end)


# -- checksums (cut false positives on long numbers) --------------------------------------
def iban_ok(raw: str) -> bool:
    s = re.sub(r"\s", "", raw).upper()
    if not 15 <= len(s) <= 34:
        return False
    digits = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(digits) % 97 == 1


def baltic_id_ok(code: str) -> bool:
    """Lithuanian asmens kodas / Estonian isikukood: 11 digits, first 1-6, mod-11 check digit."""
    if not re.fullmatch(r"[1-6]\d{10}", code):
        return False
    d = [int(c) for c in code]
    for weights in ((1, 2, 3, 4, 5, 6, 7, 8, 9, 1), (3, 4, 5, 6, 7, 8, 9, 1, 2, 3)):
        s = sum(a * b for a, b in zip(d[:10], weights, strict=True)) % 11
        if s != 10:
            return s == d[10]
    return d[10] == 0


def _ssn_ok(code: str) -> bool:
    area, group, serial = code.split("-")
    return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"


# -- detectors -----------------------------------------------------------------------------
# (kind, pattern, capture group holding the value, extra check)
_Rule = tuple[str, re.Pattern[str], int, Callable[[str], bool] | None]

_RULES: list[_Rule] = [
    ("secret", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?"
                          r"(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)"), 0, None),
    ("secret", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@]+@[^\s/]+[^\s]*"), 0, None),
    ("secret", re.compile(r"(?i:\b(?:password|passwd|pwd|secret|token|api[_-]?key)\b)"
                          # a value needs ":", "=", "is"/"was", or must mix letters and digits,
                          # so "password manager" or "token rotation" stays normal text
                          r"(?:\s*(?:[:=]|\bis\b|\bwas\b)\s*"
                          r"|\s+(?=[^\s,;\"']*\d)(?=[^\s,;\"']*[A-Za-z]))"
                          r"([^\s,;\"']{5,}[^\s,;\"'.])"), 1, None),
    ("api_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0, None),
    ("api_key", re.compile(r"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36}"
                           r"|xox[abpr]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})"), 0, None),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), 0, None),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), 0,
     iban_ok),
    ("national_id", re.compile(r"\b[1-6]\d{10}\b"), 0, baltic_id_ok),
    ("national_id", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0, _ssn_ok),
    ("phone", re.compile(r"\+\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3}[\s.-]?\d{2,4}\b"), 0, None),
    ("address", re.compile(rf"\b\d{{1,5}}\s+(?:{_NAME}\s+){{1,3}}"
                           r"(?:Street|St\.|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane"
                           r"|Drive)(?!\w)"), 0, None),
    ("address", re.compile(rf"\b{_NAME}\s+(?:g\.|gatvė|pr\.|prospektas)\s*\d+[A-Za-z]?"
                           r"(?:-\d+)?"), 0, None),
    ("person", re.compile(r"(?i:\b(?:I'm|I am|my name is|name is|name:|signed,?|regards,?"
                          r"|Mr\.?|Mrs\.?|Ms\.?|Dr\.?|ponas|ponia))"
                          rf"\s+({_NAME}(?:\s+{_NAME}){{0,2}})"), 1, None),
]


def detect(text: str, kinds: Iterable[str], known_people: Iterable[str] = ()) -> list[Span]:
    """Spans of the requested kinds, non-overlapping, sorted by position.

    When two matches overlap, the longer one wins (a connection string beats the email inside it).
    `known_people` are names already seen; they are found anywhere in the text.
    """
    wanted = set(kinds)
    found: list[Span] = []
    for kind, rx, group, check in _RULES:
        if kind not in wanted:
            continue
        for m in rx.finditer(text):
            value = m.group(group)
            if value and (check is None or check(value)):
                found.append(Span(kind, m.start(group), m.end(group), value))
    if "person" in wanted:
        for name in known_people:
            if len(name) >= 3:
                for m in re.finditer(rf"(?<!\w){re.escape(name)}(?!\w)", text):
                    found.append(Span("person", m.start(), m.end(), m.group()))
    found.sort(key=lambda s: (-(s.end - s.start), s.start))
    kept: list[Span] = []
    for s in found:
        if all(s.end <= k.start or s.start >= k.end for k in kept):
            kept.append(s)
    return sorted(kept, key=lambda s: s.start)


__all__ = ["REDACT_KINDS", "Span", "baltic_id_ok", "detect", "iban_ok"]
