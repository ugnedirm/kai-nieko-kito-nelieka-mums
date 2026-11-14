"""Attach a file you chose yourself to a thread (vault page upload and `thread file add`).

Same cleaning as the browser path (`scanners/sanitize.py`), but you are the owner: a file the
cleaner cannot fully clean (for example a slide deck with embedded pictures) is not refused; you
are told what may remain and must confirm. Notes describe kinds of hidden data, never values.
"""

from __future__ import annotations

from dataclasses import dataclass

from threadvault.connector.ingest import MAX_FILE_BYTES, MEDIA_BY_FORMAT, media_type_for
from threadvault.scanners.sanitize import sanitize_file

__all__ = ["MAX_FILE_BYTES", "MEDIA_BY_FORMAT", "Prepared", "TooLarge", "clean_name", "prepare"]


@dataclass
class Prepared:
    cleaned: bytes
    media_type: str
    complete: bool  # False: something hidden may remain, so the person must confirm
    notes: list[str]


class TooLarge(Exception):
    pass


def prepare(raw: bytes, name: str = "") -> Prepared:
    if len(raw) > MAX_FILE_BYTES:
        raise TooLarge
    result = sanitize_file(raw)
    notes = [n for n in result.report() if n.startswith("NOT removed")] if not result.complete else []
    return Prepared(cleaned=result.cleaned, media_type=media_type_for(result.format, name), complete=result.complete, notes=notes[:10])


def clean_name(name: str) -> str:
    import re
    cleaned = re.sub(r"[^A-Za-z0-9._ -]", "_", name.split("/")[-1].split("\\")[-1])[:120]
    return cleaned.strip(" .") or "attachment"
