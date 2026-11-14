"""Redaction and reversible pseudonymization (SPEC section 9).

- `redact_text` / `redact_record` apply a policy profile: every kind in `profile["redact"]` is
  replaced. With `pseudonymize`, people, emails, phones, addresses, IDs and IBANs become stable
  tokens like `[PERSON_1]` that can be turned back (`PseudonymMap.rehydrate`). Keys and secrets are
  never reversible: they become `[API_KEY]` / `[SECRET]` and are not stored anywhere.
- `PseudonymMap` holds token -> real value. It stays on this machine and is never exported.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from threadvault.privacy.detect import Span, detect
from threadvault.types import Finding, Record

REVERSIBLE = frozenset({"person", "email", "phone", "address", "national_id", "iban"})
_TOKEN = re.compile(r"\[(PERSON|EMAIL|PHONE|ADDRESS|NATIONAL_ID|IBAN)_(\d{1,6})\]")
_SKIP_KEYS = frozenset({"sha256", "hash", "prev_hash", "thread_id", "branch_id", "id"})
MAP_FORMAT = "threadvault-pseudonyms-1"


def _norm(value: str) -> str:
    return " ".join(value.split()).casefold()


class PseudonymMap:
    """token <-> real value. Same value always gets the same token."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path
        self._by_value: dict[tuple[str, str], str] = {}
        self._by_token: dict[str, str] = {}
        self._count: dict[str, int] = {}
        if path is not None and path.exists():
            self._load(path)

    def token(self, kind: str, value: str) -> str:
        if kind not in REVERSIBLE:
            raise ValueError("kind is not reversible")
        key = (kind, _norm(value))
        if key not in self._by_value:
            n = self._count.get(kind, 0) + 1
            self._count[kind] = n
            tok = f"[{kind.upper()}_{n}]"
            self._by_value[key] = tok
            self._by_token[tok] = value
            self._save()
        return self._by_value[key]

    def known_people(self) -> list[str]:
        return [self._by_token[t] for (k, _), t in self._by_value.items() if k == "person"]

    def rehydrate(self, text: str) -> str:
        """Put real values back for tokens this map knows; unknown tokens stay as they are."""
        return _TOKEN.sub(lambda m: self._by_token.get(m.group(0), m.group(0)), text)

    def rehydrate_json(self, text: str) -> str:
        """Like `rehydrate`, but values are JSON-escaped, for tokens inside a JSON string."""
        def put(m: re.Match[str]) -> str:
            value = self._by_token.get(m.group(0))
            return m.group(0) if value is None else json.dumps(value, ensure_ascii=False)[1:-1]
        return _TOKEN.sub(put, text)

    def rehydrate_record(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.rehydrate(obj)
        if isinstance(obj, dict):
            return {k: v if k in _SKIP_KEYS else self.rehydrate_record(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.rehydrate_record(v) for v in obj]
        return obj

    def __len__(self) -> int:
        return len(self._by_token)

    # -- local file ------------------------------------------------------------------------
    def _load(self, path: Path) -> None:
        doc = json.loads(path.read_text(encoding="utf-8"))
        if doc.get("format") != MAP_FORMAT:
            raise ValueError("not a pseudonym map")
        for e in doc["entries"]:
            kind, tok, value = e["kind"], e["token"], e["value"]
            m = _TOKEN.fullmatch(tok)
            if kind not in REVERSIBLE or m is None or m.group(1) != kind.upper():
                raise ValueError("bad pseudonym map entry")
            self._by_value[(kind, _norm(value))] = tok
            self._by_token[tok] = value
            self._count[kind] = max(self._count.get(kind, 0), int(m.group(2)))

    def _save(self) -> None:
        if self._path is None:
            return
        entries = [{"kind": k, "token": t, "value": self._by_token[t]}
                   for (k, _), t in self._by_value.items()]
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"format": MAP_FORMAT, "entries": entries}, indent=1,
                                  ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, self._path)


@dataclass
class Redacted:
    text: str
    findings: list[Finding] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.kind] = out.get(f.kind, 0) + 1
        return dict(sorted(out.items()))


def _replacement(span: Span, profile: Record, mapping: PseudonymMap | None) -> str:
    if profile.get("pseudonymize") and mapping is not None and span.kind in REVERSIBLE:
        return mapping.token(span.kind, span.value)
    return f"[{span.kind.upper()}]"


def redact_text(text: str, profile: Record, mapping: PseudonymMap | None = None,
                path: str = "$") -> Redacted:
    kinds = profile.get("redact", [])
    if not kinds:
        return Redacted(text)
    people = mapping.known_people() if mapping is not None and profile.get("pseudonymize") else []
    spans = detect(text, kinds, people)
    out, last = [], 0
    for s in spans:
        out += [text[last:s.start], _replacement(s, profile, mapping)]
        last = s.end
    out.append(text[last:])
    return Redacted("".join(out), [s.finding(path) for s in spans])


def redact_record(obj: Any, profile: Record, mapping: PseudonymMap | None = None,
                  path: str = "$") -> tuple[Any, list[Finding]]:
    """Redact every string in a JSON-like value. Ids and hashes are left alone."""
    if isinstance(obj, str):
        r = redact_text(obj, profile, mapping, path)
        return r.text, r.findings
    if isinstance(obj, dict):
        out_d: dict[str, Any] = {}
        found: list[Finding] = []
        for k, v in obj.items():
            if k in _SKIP_KEYS:
                out_d[k] = v
                continue
            out_d[k], f = redact_record(v, profile, mapping, f"{path}.{k}")
            found += f
        return out_d, found
    if isinstance(obj, list):
        out_l: list[Any] = []
        found = []
        for i, v in enumerate(obj):
            item, f = redact_record(v, profile, mapping, f"{path}[{i}]")
            out_l.append(item)
            found += f
        return out_l, found
    return obj, []


__all__ = ["MAP_FORMAT", "REVERSIBLE", "PseudonymMap", "Redacted", "redact_record",
           "redact_text"]
