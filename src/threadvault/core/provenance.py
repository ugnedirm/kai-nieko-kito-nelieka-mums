"""Provenance levels (SPEC.md section 4) and the "never upgrade" rule.

Ordered from most to least trustworthy:

1. provider-verified       came straight from a provider API response
2. ai-summary-user-saved   written by an AI, reviewed and saved by the user
3. user-asserted           typed or pasted by the user
4. imported-unverified     from an export file or page scrape; authorship cannot be proven

A stored record's provenance never changes (records are immutable). An amendment is a new record
and may never claim more trust than the record it amends.
"""

from __future__ import annotations

from typing import Literal, get_args

Provenance = Literal["provider-verified", "ai-summary-user-saved", "user-asserted",
                     "imported-unverified"]
LEVELS: tuple[Provenance, ...] = get_args(Provenance)
_RANK = {p: i for i, p in enumerate(LEVELS)}  # lower = more trusted


def check(value: object) -> Provenance:
    for level in LEVELS:
        if value == level:
            return level
    raise ValueError("unknown provenance level")


def rank(value: str) -> int:
    return _RANK[check(value)]


def at_most(requested: str, ceiling: str) -> Provenance:
    """`requested`, lowered to `ceiling` if it claims more trust than the ceiling allows."""
    return check(requested) if rank(requested) >= rank(ceiling) else check(ceiling)


def is_upgrade(old: str, new: str) -> bool:
    return rank(new) < rank(old)
