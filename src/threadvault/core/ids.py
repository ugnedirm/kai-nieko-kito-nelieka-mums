"""Identifier and hash validation, plus the clock.

Every id or hash that becomes part of a filesystem path goes through these checks first, so a
crafted id (``../../etc``) can never escape the vault directory.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from datetime import UTC, datetime

_ID = re.compile(r"[A-Za-z0-9_-]{8,64}")
_HASH = re.compile(r"sha256:[0-9a-f]{64}")

Clock = Callable[[], str]


def utc_now() -> str:
    """Current UTC time as RFC 3339 with second precision, e.g. 2026-11-14T09:00:00Z."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: str) -> datetime:
    """Parse an RFC 3339 timestamp from a record. Naive values are rejected."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return dt


def is_id(value: object) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def is_hash(value: object) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def check_id(value: object, what: str = "id") -> str:
    if not is_id(value):
        raise ValueError(f"invalid {what}")
    assert isinstance(value, str)
    return value


def check_hash(value: object) -> str:
    if not is_hash(value):
        raise ValueError("invalid sha256 reference")
    assert isinstance(value, str)
    return value


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(6)}"
