"""Reference implementation of the hash rule in schemas/common.schema.json.

hash = "sha256:" + hex(SHA-256(canonical JSON of the record without `hash` and `signature`)).

Canonical JSON here is sorted keys, no whitespace, UTF-8, which equals RFC 8785 (JCS) for the
data we store because the schemas contain no floating-point numbers. Person A owns this module;
the sample-vault generator and tests rely on it, so change it only together with SPEC.md.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

HASH_PREFIX = "sha256:"
_EXCLUDED = ("hash", "signature")


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return HASH_PREFIX + hashlib.sha256(data).hexdigest()


def record_hash(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k not in _EXCLUDED}
    return sha256_bytes(canonical_json(body))
