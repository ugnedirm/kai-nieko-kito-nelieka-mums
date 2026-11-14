"""Expiry helpers shared by the CLI and the vault pages: "7d" -> an RFC 3339 time."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
CHOICES = {"never": None, "1d": "1d", "7d": "7d", "30d": "30d"}


class BadDuration(ValueError):
    pass


def expires_in(text: str, now: datetime | None = None) -> str:
    """'90m', '12h', '7d', '2w' -> the time that far from now, as 2026-11-21T09:00:00Z."""
    m = re.fullmatch(r"(\d{1,4})([mhdw])", text.strip().lower())
    if not m or int(m.group(1)) == 0:
        raise BadDuration("use a number and m, h, d or w, for example 12h or 7d")
    when = (now or datetime.now(UTC)) + timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")
