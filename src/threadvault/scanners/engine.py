"""The vault's scanner (SPEC.md section 9). Drop-in replacement for `scanners.basic`.

Same entry points as the fallback (`scan_text`, `scan_record`, `scan_thread_records`) plus
`scan_file` for attachments. Runs on handovers, messages and files.

What it detects:
- secrets (`scanners.secrets`): api_key, secret, connection_string, private_key, plus entropy hits;
- light PII: email, phone, iban (checksum-verified), national_id (US SSN, Baltic personal codes
  with checksum), person (self-introductions only), address (street-number patterns);
- prompt_injection phrases.

The PII rules are deliberately narrow (low false positives). Name and address detection proper
needs NER (Person C's privacy layer); do not rely on this module alone for redaction.
Findings never contain the matched value.
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import Any

from pydantic import BaseModel

from threadvault.scanners.secrets import find_secrets
from threadvault.types import Finding, Record, Severity

MAX_SCAN_CHARS = 2_000_000
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_TOTAL = 64 * 1024 * 1024  # uncompressed bytes we are willing to read from one archive
MAX_PDF_PAGES = 200

_PII: list[tuple[str, Severity, re.Pattern[str]]] = [
    ("email", "medium", re.compile(r"\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+\b")),
    ("phone", "medium", re.compile(
        r"(?<![\w+])\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}\b"
        r"|(?<!\w)\(\d{3}\)\s?\d{3}-\d{4}\b")),
    ("person", "medium", re.compile(
        r"\b(?i:my name is|i'm|i am|name:)\s+((?:[A-Z][a-zà-ž]+)(?:\s+[A-Z][a-zà-ž]+)+)")),
    ("address", "low", re.compile(
        r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St\.|Avenue|Ave\.?|Road|Rd\.|Boulevard|Blvd"
        r"|Lane|Drive|Dr\.|g\.|gatvė|al\.|pr\.)(?!\w)")),
    ("prompt_injection", "medium", re.compile(
        r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?"
        r"(?:previous|prior|above|earlier)\s+(?:instructions|prompts|messages|rules)"
        r"|\byou\s+are\s+now\s+(?:in\s+)?(?:developer|DAN|jailbreak|unrestricted)"
        r"|\breveal\s+(?:your\s+|the\s+)?system\s+prompt"
        r"|<\s*/?\s*historical_(?:context|files|messages)")),
]
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b")
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_BALTIC_ID = re.compile(r"(?<!\d)[1-6]\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}(?!\d)")


def _iban_ok(raw: str) -> bool:
    s = raw.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    digits = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(digits) % 97 == 1


def _baltic_id_ok(code: str) -> bool:
    """Lithuanian / Estonian personal code checksum (two weight passes)."""
    d = [int(c) for c in code]
    for weights in ((1, 2, 3, 4, 5, 6, 7, 8, 9, 1), (3, 4, 5, 6, 7, 8, 9, 1, 2, 3)):
        r = sum(a * b for a, b in zip(d, weights, strict=False)) % 11
        if r != 10:
            return r == d[10]
    return d[10] == 0


def scan_text(text: str, path: str = "$") -> list[Finding]:
    if len(text) > MAX_SCAN_CHARS:
        text = text[:MAX_SCAN_CHARS]
    out = [Finding(kind=h.kind, severity=h.severity, path=path, start=h.start, end=h.end,
                   detail=f"rule={h.rule_id}") for h in find_secrets(text)]
    for kind, sev, rx in _PII:
        for m in rx.finditer(text):
            g = 1 if kind == "person" else 0
            out.append(Finding(kind=kind, severity=sev, path=path, start=m.start(g), end=m.end(g)))
    out += [Finding(kind="iban", severity="medium", path=path, start=m.start(), end=m.end())
            for m in _IBAN.finditer(text) if _iban_ok(m.group())]
    out += [Finding(kind="national_id", severity="medium", path=path, start=m.start(), end=m.end())
            for rx, ok in ((_SSN, None), (_BALTIC_ID, _baltic_id_ok))
            for m in rx.finditer(text) if ok is None or ok(m.group())]
    return sorted(out, key=lambda f: (f.start or 0, f.kind))


def scan_record(obj: Any, path: str = "$") -> list[Finding]:
    """Scan every string in a JSON-like structure. Keys named `sha256`/`hash` hold our own
    content hashes and are skipped."""
    if isinstance(obj, str):
        return scan_text(obj, path[:256])
    if isinstance(obj, dict):
        return [f for k, v in obj.items() if k not in ("sha256", "hash", "prev_hash", "file_refs")
                for f in scan_record(v, f"{path}.{k}")]
    if isinstance(obj, list):
        return [f for i, v in enumerate(obj) for f in scan_record(v, f"{path}[{i}]")]
    return []


def scan_thread_records(records: list[Record]) -> list[Finding]:
    return [f for r in records
            for f in scan_record(r.get("content"), f"{r['type']}:{r.get('seq', r.get('version'))}")]


# -- files -------------------------------------------------------------------------------------------
class FileScan(BaseModel):
    findings: list[Finding]
    scanned: bool  # False: the format could not be read, so absence of findings means nothing
    note: str | None = None


_OOXML_TEXT = re.compile(r"(?:word|xl|ppt)/.+\.xml$|docProps/.+\.xml$")
_TAG = re.compile(r"<[^<>]{0,2000}>")


def decode_text(data: bytes) -> str | None:
    for bom, enc in ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")):
        if data.startswith(bom):
            try:
                return data[len(bom):].decode(enc)
            except UnicodeDecodeError:
                return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\x00" in text:
        return None
    return text


def _zip_texts(data: bytes) -> list[tuple[str, str]] | None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return None
    infos = zf.infolist()
    if "[Content_Types].xml" not in zf.namelist():
        return None  # a plain zip: we do not unpack arbitrary archives
    if len(infos) > MAX_ZIP_ENTRIES or sum(i.file_size for i in infos) > MAX_ZIP_TOTAL:
        raise ValueError("archive too large to scan")
    out: list[tuple[str, str]] = []
    for info in infos:
        if not _OOXML_TEXT.match(info.filename):
            continue
        raw = zf.read(info)
        text = decode_text(raw)
        if text is not None:
            # Cap before the tag regex: the scan itself is capped anyway, and this keeps a
            # small, highly compressible part from costing seconds of regex time.
            out.append((info.filename, _TAG.sub(" ", text[: MAX_SCAN_CHARS * 2])))
    return out


def _pdf_text(data: bytes) -> str | None:
    try:
        from pypdf import PdfReader
    except ImportError:
        return None
    try:
        reader = PdfReader(io.BytesIO(data))
        parts = [p.extract_text() or "" for p in reader.pages[:MAX_PDF_PAGES]]
        info: dict[str, Any] = dict(reader.metadata or {})
        parts += [str(v) for v in info.values()]
    except Exception:  # noqa: BLE001 - pypdf raises many types on hostile input
        return None
    return "\n".join(parts)


def scan_file(data: bytes, media_type: str = "", path: str = "$.file") -> FileScan:
    """Scan an attachment. Text is scanned directly; Office (OOXML) and PDF text is extracted."""
    if data.startswith(b"PK\x03\x04"):
        try:
            parts = _zip_texts(data)
        except ValueError:
            return FileScan(findings=[], scanned=False, note="archive too large to scan")
        if parts is None:
            return FileScan(findings=[], scanned=False,
                            note="archive not scanned (only Office files are unpacked)")
        found = [f for name, text in parts for f in scan_text(text, f"{path}/{name}"[:256])]
        if any(len(text) > MAX_SCAN_CHARS for _, text in parts):
            return FileScan(findings=found, scanned=False, note="only the first part was scanned")
        return FileScan(findings=found, scanned=True)
    if data.startswith(b"%PDF-"):
        text = _pdf_text(data)
        if text is None:
            return FileScan(findings=[], scanned=False, note="PDF text could not be extracted")
        return _text_scan(text, path)
    text = decode_text(data)
    if text is None:
        return FileScan(findings=[], scanned=False, note=f"binary file not scanned ({media_type[:60]})")
    return _text_scan(text, path)


def _text_scan(text: str, path: str) -> FileScan:
    if len(text) > MAX_SCAN_CHARS:
        return FileScan(findings=scan_text(text, path), scanned=False,
                        note="only the first part was scanned")
    return FileScan(findings=scan_text(text, path), scanned=True)
