"""Strict JSON reading and safe writing for vault files.

Reading is strict on purpose (SPEC 3.2: no floats; hashing must be unambiguous):
- floating-point numbers, NaN and Infinity are rejected,
- duplicate object keys are rejected (two parsers could otherwise see different values),
- JSONL is split on "\\n" only, so U+2028 and friends inside strings cannot split a record.

Writing: whole files are replaced atomically (temp file + rename); chain and log files are only
ever appended to, in binary mode so Windows never turns "\\n" into "\\r\\n".
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from threadvault.core.hashing import canonical_json


class StrictJSONError(ValueError):
    """The bytes are not JSON we are willing to hash. The message never contains the input."""


def _no_float(_: str) -> Any:
    raise StrictJSONError("floating-point numbers are not allowed")


def _no_constant(_: str) -> Any:
    raise StrictJSONError("NaN and Infinity are not allowed")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise StrictJSONError("duplicate object key")
        out[k] = v
    return out


def loads(text: str | bytes) -> Any:
    try:
        value = json.loads(text, parse_float=_no_float, parse_constant=_no_constant,
                           object_pairs_hook=_no_duplicates)
        # "\ud800" escapes parse into lone surrogates that cannot be encoded as UTF-8, so they
        # could never be hashed; reject them here instead of crashing later in canonical_json.
        canonical_json(value)
    except StrictJSONError:
        raise
    except (ValueError, RecursionError) as e:  # JSONDecodeError and UnicodeErrors are ValueErrors
        raise StrictJSONError(f"invalid JSON ({type(e).__name__})") from None
    return value


def read_json(path: Path) -> Any:
    return loads(path.read_bytes())


def split_jsonl(data: bytes) -> list[bytes]:
    """Lines of a JSONL file. A trailing "\\r" is tolerated (JSON whitespace, e.g. a Windows
    checkout); empty lines are skipped."""
    lines = data.split(b"\n")
    return [ln for ln in (raw.rstrip(b"\r") for raw in lines) if ln.strip()]


def dumps_line(obj: Any) -> bytes:
    """One JSONL line: canonical JSON plus "\\n". JSON escapes control characters, so the
    result never contains a raw newline."""
    line = canonical_json(obj)
    if b"\n" in line:  # cannot happen with json.dumps; a guard against future changes
        raise ValueError("record would span lines")
    return line + b"\n"


def append_line(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "ab") as fh:
        fh.write(dumps_line(obj))
        fh.flush()
        os.fsync(fh.fileno())


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def atomic_write_json(path: Path, obj: Any) -> None:
    text = json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    atomic_write_bytes(path, text.encode("utf-8"))
