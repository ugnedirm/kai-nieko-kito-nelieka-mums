"""Make untrusted text safe to print to a terminal (no ANSI/OSC escapes, no bidi tricks)."""

from __future__ import annotations

import unicodedata

_KEEP = {"\n", "\t"}
REPLACEMENT = chr(0xFFFD)


def terminal_safe(text: str) -> str:
    """Replace control, format (bidi, zero-width) and unassigned characters with U+FFFD."""
    return "".join(
        c if c in _KEEP or unicodedata.category(c)[0] not in {"C"} else REPLACEMENT for c in text)
