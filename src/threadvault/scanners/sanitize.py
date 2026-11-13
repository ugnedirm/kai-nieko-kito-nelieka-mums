"""File sanitization: a cleaned copy plus a report (SPEC.md section 9, `strip_file_metadata`).

Supported:
- JPEG: drops EXIF / XMP (APP1), IPTC (APP13), comments (COM) and other APPn segments; keeps
  JFIF (APP0), ICC colour profiles (APP2 ICC_PROFILE) and Adobe (APP14), which affect rendering.
- PNG: drops tEXt, zTXt, iTXt, eXIf and tIME chunks.
- PDF (needs the optional `pypdf`): rebuilds the document from its pages, which drops the Info
  dictionary, XMP metadata, embedded files, document JavaScript and bookmarks; removes comment and
  markup annotations and page-level metadata.
- Office Open XML (docx, xlsx, pptx): blanks core properties, removes custom properties and the
  identifying app.xml fields; docx: accepts tracked changes (insertions kept, deletions dropped,
  formatting-change history removed) and removes comments and the template path; xlsx: removes
  hidden and very-hidden sheets, comments and threaded comments; pptx: removes comments and
  speaker notes.

`SanitizeResult.complete` is False whenever something risky was found but not removed: hidden text
in a docx, hidden rows or slides, hidden-sheet text left in shared strings or caches, images
embedded in Office files or PDFs (their own EXIF is not stripped), embedded objects, custom XML,
PDF form fields, a PDF without pypdf, an unknown binary format. Report entries describe *what kind*
of thing was removed, never its value. Data appended after a JPEG/PNG image end is dropped.
"""

from __future__ import annotations

import io
import posixpath
import re
import struct
import zipfile
from collections.abc import Callable

from pydantic import BaseModel

from threadvault.scanners.engine import MAX_ZIP_ENTRIES, MAX_ZIP_TOTAL, decode_text
from threadvault.types import Finding, Severity


class SanitizeResult(BaseModel):
    cleaned: bytes
    changed: bool
    complete: bool
    format: str
    findings: list[Finding]

    def report(self) -> list[str]:
        return [f.detail or f.kind for f in self.findings]


class _Report:
    def __init__(self, fmt: str) -> None:
        self.fmt = fmt
        self.findings: list[Finding] = []
        self.complete = True

    def removed(self, kind: str, what: str, severity: Severity = "low") -> None:
        self.findings.append(Finding(kind=kind, severity=severity, path=f"$.file:{self.fmt}",
                                     detail=f"removed: {what}"[:500]))

    def kept(self, kind: str, what: str, severity: Severity = "medium") -> None:
        self.complete = False
        self.findings.append(Finding(kind=kind, severity=severity, path=f"$.file:{self.fmt}",
                                     detail=f"NOT removed: {what}"[:500]))


# -- JPEG -------------------------------------------------------------------------------------------
_JPEG_KEEP_APP = {0xE0, 0xEE}  # JFIF, Adobe


def _sanitize_jpeg(data: bytes, rep: _Report) -> bytes:
    out = bytearray(data[:2])
    i = 2
    n = len(data)
    while i < n:
        if data[i] != 0xFF:
            rep.kept("file_metadata", "unparseable JPEG structure")
            return data
        while i < n and data[i] == 0xFF:  # fill bytes
            i += 1
        if i >= n:
            break
        marker = data[i]
        i += 1
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            out += bytes((0xFF, marker))
            continue
        if marker == 0xD9:
            out += b"\xff\xd9"
            break
        if i + 2 > n:
            rep.kept("file_metadata", "truncated JPEG")
            return data
        (length,) = struct.unpack(">H", data[i:i + 2])
        if length < 2 or i + length > n:
            rep.kept("file_metadata", "truncated JPEG")
            return data
        payload = data[i + 2:i + length]
        segment = bytes((0xFF, marker)) + data[i:i + length]
        i += length
        if marker == 0xDA:  # start of scan: entropy-coded data up to the end-of-image marker
            # Inside scan data 0xFF is always stuffed (FF 00) or a restart marker, so the first
            # FF D9 is the real end of image. Anything after it (motion-photo trailers, appended
            # files) is dropped.
            eoi = data.find(b"\xff\xd9", i)
            if eoi < 0:
                rep.kept("file_metadata", "JPEG has no end-of-image marker")
                return data
            out += segment + data[i:eoi + 2]
            if data[eoi + 2:].strip(b"\x00"):
                rep.removed("hidden_content", "data appended after the end of the image", "medium")
            break
        if marker == 0xFE:
            rep.removed("file_metadata", "JPEG comment")
        elif marker == 0xE1:
            what = "EXIF metadata" if payload.startswith(b"Exif") else (
                "XMP metadata" if b"adobe" in payload[:40].lower() else "APP1 metadata")
            rep.removed("file_metadata", what, "medium")
        elif marker == 0xED:
            rep.removed("file_metadata", "IPTC metadata", "medium")
        elif marker == 0xE2 and payload.startswith(b"ICC_PROFILE"):
            out += segment
        elif 0xE0 <= marker <= 0xEF and marker not in _JPEG_KEEP_APP:
            rep.removed("file_metadata", f"APP{marker - 0xE0} segment")
        else:
            out += segment
    return bytes(out)


# -- PNG --------------------------------------------------------------------------------------------
_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_PNG_DROP = {b"tEXt": "text metadata", b"zTXt": "compressed text metadata",
             b"iTXt": "international text metadata", b"eXIf": "EXIF metadata",
             b"tIME": "modification time"}


def _sanitize_png(data: bytes, rep: _Report) -> bytes:
    out = bytearray(_PNG_SIG)
    i = len(_PNG_SIG)
    while i + 8 <= len(data):
        (length,) = struct.unpack(">I", data[i:i + 4])
        ctype = data[i + 4:i + 8]
        end = i + 12 + length
        if end > len(data):
            rep.kept("file_metadata", "truncated PNG")
            return data
        if ctype in _PNG_DROP:
            rep.removed("file_metadata", f"PNG {_PNG_DROP[ctype]}",
                        "medium" if ctype in (b"eXIf", b"iTXt") else "low")
        elif ctype[:1].islower() and ctype not in _PNG_KEEP_ANCILLARY:
            # Unknown ancillary or private chunk: not needed to display the image.
            rep.removed("file_metadata", "PNG private/unknown ancillary chunk")
        else:
            out += data[i:end]
        i = end
        if ctype == b"IEND":
            if data[i:].strip(b"\x00"):
                rep.removed("hidden_content", "data appended after the end of the image", "medium")
            break
    return bytes(out)


# Ancillary chunks that only affect rendering.
_PNG_KEEP_ANCILLARY = {b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT", b"pHYs", b"bKGD",
                       b"hIST", b"sPLT", b"acTL", b"fcTL", b"fdAT", b"cICP", b"mDCv", b"cLLi"}


# -- PDF --------------------------------------------------------------------------------------------
_PDF_COMMENT_SUBTYPES = {"/Text", "/FreeText", "/Popup", "/Highlight", "/Underline", "/StrikeOut",
                         "/Squiggly", "/Caret", "/Ink", "/Stamp", "/FileAttachment", "/Sound"}


def _sanitize_pdf(data: bytes, rep: _Report) -> bytes:
    try:
        from pypdf import PdfReader, PdfWriter
        from pypdf.generic import ArrayObject, DictionaryObject, NameObject
    except ImportError:
        rep.kept("file_metadata", "PDF metadata (install the 'sanitize' extra: pypdf)", "high")
        return data
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            rep.kept("file_metadata", "encrypted PDF could not be inspected", "high")
            return data
        if reader.metadata:
            rep.removed("file_metadata", "PDF document information (author, title, tools)",
                        "medium")
        root = reader.trailer["/Root"].get_object()
        if not isinstance(root, DictionaryObject):
            raise TypeError("PDF has no document catalog")
        if "/Metadata" in root:
            rep.removed("file_metadata", "PDF XMP metadata", "medium")
        names_ref = root.get("/Names")
        names = names_ref.get_object() if names_ref is not None else None
        if isinstance(names, DictionaryObject) and "/EmbeddedFiles" in names:
            rep.removed("hidden_content", "PDF embedded files", "medium")
        if isinstance(names, DictionaryObject) and "/JavaScript" in names:
            rep.removed("hidden_content", "PDF document JavaScript", "medium")
        if "/Outlines" in root:
            rep.removed("file_metadata", "PDF bookmarks (document was rebuilt)")
        writer = PdfWriter()
        comments = 0
        for page in reader.pages:
            # Strip BEFORE copying: add_page clones every object the page references, and a
            # cloned-then-unlinked object would still be written to the file.
            for key in ("/Metadata", "/PieceInfo", "/AA"):
                if key in page:
                    del page[NameObject(key)]
                    rep.removed("file_metadata", f"PDF page {key[1:]}")
            resources = page.get("/Resources")
            res_obj = resources.get_object() if resources is not None else None
            if isinstance(res_obj, DictionaryObject) and "/XObject" in res_obj:
                rep.kept("file_metadata", "images inside the PDF may carry their own EXIF")
            annots = page.get("/Annots")
            if annots is not None:
                kept = ArrayObject()
                for a in annots.get_object():
                    obj = a.get_object()
                    if obj.get("/Subtype") in _PDF_COMMENT_SUBTYPES:
                        comments += 1
                    else:
                        if obj.get("/Subtype") == "/Widget":
                            rep.kept("hidden_content", "PDF form fields and their values")
                        kept.append(a)
                if kept:
                    page[NameObject("/Annots")] = kept
                else:
                    del page[NameObject("/Annots")]
            writer.add_page(page)
        if comments:
            rep.removed("hidden_content", f"{comments} PDF comment/markup annotation(s)", "medium")
        writer.add_metadata({"/Producer": "threadvault"})
        writer.compress_identical_objects()  # drops unreferenced objects (default in pypdf 5-7)
        buf = io.BytesIO()
        writer.write(buf)
        return buf.getvalue()
    except Exception:  # noqa: BLE001 - pypdf raises many types on hostile input
        rep.kept("file_metadata", "PDF could not be parsed", "high")
        return data


# -- Office Open XML ----------------------------------------------------------------------------------
_EMPTY_CORE = (b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
               b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
               b'metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" '
               b'xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/'
               b'dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>')
_APP_FIELDS = re.compile(rb"<(Company|Manager|Template|HyperlinkBase)>.*?</\1>|"
                         rb"<(Company|Manager|Template|HyperlinkBase)\s*/>", re.DOTALL)
_DOCX_STORY = re.compile(r"word/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$")
_DOCX_COMMENT_PARTS = re.compile(r"word/(comments|commentsExtended|commentsIds|commentsExtensible"
                                 r"|people)\.xml$")
_XLSX_COMMENT_PARTS = re.compile(r"xl/(comments\d*\.xml|threadedComments/.+\.xml|persons/.+\.xml)$")
_PPTX_HIDDEN_PARTS = re.compile(r"ppt/(comments/.+\.xml|commentAuthors\.xml|authors\.xml"
                                r"|notesSlides/.+\.xml)$")


def _sub_count(pattern: str, repl: str | Callable[[re.Match[str]], str], text: str) -> tuple[str, int]:
    return re.subn(pattern, repl, text, flags=re.DOTALL)


_CHANGE_TAGS = (r"(rPrChange|pPrChange|sectPrChange|tblPrChange|trPrChange|tcPrChange"
                r"|tblGridChange|numberingChange)")


def _accept_tracked_changes(xml: str) -> tuple[str, int]:
    """Accept all revisions: deleted text goes, inserted text stays, change history goes."""
    total = 0
    steps: list[tuple[str, str]] = [
        (r"<w:del\b[^>]*/>", ""),
        (r"<w:del\b[^>]*>.*?</w:del>", ""),
        (r"<w:moveFrom\b[^>]*>.*?</w:moveFrom>", ""),
        (r"<w:(?:moveFromRangeStart|moveFromRangeEnd|moveToRangeStart|moveToRangeEnd)\b[^>]*/>", ""),
        (r"<w:ins\b[^>]*/>", ""),
        (r"</?w:ins\b[^>]*>", ""),
        (r"</?w:moveTo\b[^>]*>", ""),
        (r"<w:" + _CHANGE_TAGS + r"\b[^>]*/>", ""),
        (r"<w:" + _CHANGE_TAGS + r"\b[^>]*>.*?</w:\1>", ""),
    ]
    for pattern, repl in steps:
        xml, n = _sub_count(pattern, repl, xml)
        total += n
    return xml, total


class _Package:
    """An OOXML zip held in memory, with helpers to delete parts and their relationships."""

    def __init__(self, data: bytes) -> None:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_ENTRIES or sum(i.file_size for i in infos) > MAX_ZIP_TOTAL:
            raise ValueError("archive too large")
        self.order = [i.filename for i in infos if not i.is_dir()]
        self.parts = {name: zf.read(name) for name in self.order}

    def text(self, name: str) -> str:
        return self.parts[name].decode("utf-8")

    def set_text(self, name: str, value: str) -> None:
        self.parts[name] = value.encode("utf-8")

    @staticmethod
    def rels_name(part: str) -> str:
        d, f = posixpath.split(part)
        return posixpath.join(d, "_rels", f + ".rels")

    @staticmethod
    def source_of(rels: str) -> str:
        d, f = posixpath.split(rels)
        return posixpath.join(posixpath.dirname(d), f.removesuffix(".rels"))

    def remove(self, doomed: set[str]) -> None:
        """Delete parts, every relationship pointing at them, references to those relationship
        ids in the source parts, and their content-type overrides."""
        doomed = {p for p in doomed if p in self.parts}
        doomed |= {self.rels_name(p) for p in doomed if self.rels_name(p) in self.parts}
        for p in doomed:
            self.parts.pop(p, None)
        for rels in [n for n in self.parts if n.endswith(".rels")]:
            src = self.source_of(rels)
            base = posixpath.dirname(src)
            xml = self.text(rels)
            dead_ids: list[str] = []

            def drop(m: re.Match[str], base: str = base, dead_ids: list[str] = dead_ids) -> str:
                tag = m.group(0)
                if 'TargetMode="External"' in tag:
                    return tag
                target = re.search(r'Target="([^"]+)"', tag)
                rid = re.search(r'Id="([^"]+)"', tag)
                if not target:
                    return tag
                t = target.group(1)
                path = t.lstrip("/") if t.startswith("/") else posixpath.normpath(
                    posixpath.join(base, t))
                if path in doomed:
                    if rid:
                        dead_ids.append(rid.group(1))
                    return ""
                return tag

            new = re.sub(r"<Relationship\b[^>]*/>", drop, xml)
            if new != xml:
                self.set_text(rels, new)
            if dead_ids and src in self.parts and src.endswith(".xml"):
                sxml = self.text(src)
                for rid in dead_ids:
                    sxml = re.sub(rf'<[\w:]+\b[^>]*\br:id="{re.escape(rid)}"[^>]*/>', "", sxml)
                self.set_text(src, sxml)
        ct = "[Content_Types].xml"
        if ct in self.parts:
            xml = self.text(ct)
            for p in doomed:
                xml = re.sub(rf'<Override\b[^>]*PartName="/{re.escape(p)}"[^>]*/>', "", xml)
            self.set_text(ct, xml)

    def build(self) -> bytes:
        buf = io.BytesIO()
        names = [n for n in self.order if n in self.parts]
        names.sort(key=lambda n: n != "[Content_Types].xml")
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
            for name in names:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                out.writestr(info, self.parts[name])
        return buf.getvalue()


def _sanitize_ooxml(data: bytes, rep: _Report) -> bytes:
    try:
        pkg = _Package(data)
    except (zipfile.BadZipFile, ValueError):
        rep.kept("file_metadata", "Office file could not be opened", "high")
        return data
    names = set(pkg.parts)
    try:
        if "docProps/core.xml" in names and pkg.parts["docProps/core.xml"] != _EMPTY_CORE:
            pkg.parts["docProps/core.xml"] = _EMPTY_CORE
            rep.removed("file_metadata", "document properties (author, title, dates, revision)",
                        "medium")
        if "docProps/app.xml" in names:
            new, n = _APP_FIELDS.subn(b"", pkg.parts["docProps/app.xml"])
            if n:
                pkg.parts["docProps/app.xml"] = new
                rep.removed("file_metadata", "company/manager/template fields")
        doomed: set[str] = set()
        if "docProps/custom.xml" in names:
            doomed.add("docProps/custom.xml")
            rep.removed("file_metadata", "custom document properties", "medium")

        # Word
        for name in sorted(n for n in names if _DOCX_STORY.match(n)):
            xml = pkg.text(name)
            xml, changes = _accept_tracked_changes(xml)
            if changes:
                rep.removed("hidden_content", f"tracked changes in {name} (accepted)", "medium")
            xml, _ = _sub_count(r"<w:(?:commentRangeStart|commentRangeEnd|commentReference)\b[^>]*/>",
                                "", xml)
            if "<w:vanish/>" in xml or "<w:vanish " in xml:
                rep.kept("hidden_content", f"hidden text in {name}")
            pkg.set_text(name, xml)
        comment_parts = {n for n in names if _DOCX_COMMENT_PARTS.match(n)}
        if comment_parts:
            doomed |= comment_parts
            rep.removed("hidden_content", "Word comments", "medium")
        if "word/settings.xml" in names:
            xml = pkg.text("word/settings.xml")
            xml, _ = _sub_count(r"<w:trackRevisions\b[^>]*/>", "", xml)
            xml, n2 = _sub_count(r"<w:attachedTemplate\b[^>]*/>", "", xml)
            if n2:
                rep.removed("file_metadata", "attached template path")
            pkg.set_text("word/settings.xml", xml)

        # Excel
        if "xl/workbook.xml" in names:
            wb = pkg.text("xl/workbook.xml")
            hidden = re.findall(r'<sheet\b[^>]*\bstate="(?:hidden|veryHidden)"[^>]*/>', wb)
            if hidden:
                rels = pkg.text("xl/_rels/workbook.xml.rels")
                for tag in hidden:
                    rid = re.search(r'\br:id="([^"]+)"', tag)
                    if rid:
                        rel = re.search(rf'<Relationship\b[^>]*Id="{re.escape(rid.group(1))}"[^>]*/>',
                                        rels)
                        target = re.search(r'Target="([^"]+)"', rel.group(0)) if rel else None
                        if target:
                            t = target.group(1)
                            doomed.add(t.lstrip("/") if t.startswith("/")
                                       else posixpath.normpath(posixpath.join("xl", t)))
                    wb = wb.replace(tag, "")
                wb, _ = _sub_count(r"<definedNames>.*?</definedNames>", "", wb)
                pkg.set_text("xl/workbook.xml", wb)
                if "xl/calcChain.xml" in names:
                    doomed.add("xl/calcChain.xml")
                rep.removed("hidden_content", f"{len(hidden)} hidden sheet part(s) (and defined "
                            "names)", "high")
                # Cell text lives in a workbook-wide shared-strings table (and may be copied into
                # pivot caches, chart caches and external links), so it can outlive the sheet.
                if any(n == "xl/sharedStrings.xml" or n.startswith(
                        ("xl/pivotCache", "xl/charts/", "xl/externalLinks/")) for n in names):
                    rep.kept("hidden_content", "text from hidden sheets may remain in shared "
                             "strings, pivot or chart caches", "high")
            for name in sorted(n for n in names if n.startswith("xl/worksheets/sheet")):
                sx = pkg.text(name)
                if re.search(r'<(?:row|col)\b[^>]*\bhidden="(?:1|true)"', sx):
                    rep.kept("hidden_content", f"hidden rows or columns in {name}")
        xl_comments = {n for n in names if _XLSX_COMMENT_PARTS.match(n)}
        if xl_comments:
            doomed |= xl_comments
            rep.removed("hidden_content", "Excel comments", "medium")

        # PowerPoint
        ppt_hidden = {n for n in names if _PPTX_HIDDEN_PARTS.match(n)}
        if any("notesSlides/" in n for n in ppt_hidden):
            rep.removed("hidden_content", "speaker notes", "medium")
        if any("notesSlides/" not in n for n in ppt_hidden):
            rep.removed("hidden_content", "PowerPoint comments", "medium")
        doomed |= ppt_hidden
        if any(re.match(r"ppt/slides/slide\d+\.xml$", n) and ' show="0"' in pkg.text(n)[:2000]
               for n in names):
            rep.kept("hidden_content", "hidden slides")

        # Parts this sanitizer does not clean: say so rather than claim a clean file.
        if any(re.match(r"(word|xl|ppt)/media/", n) for n in names):
            rep.kept("file_metadata", "embedded images may carry their own EXIF/GPS metadata")
        if any(re.match(r"(word|xl|ppt)/embeddings/", n) for n in names):
            rep.kept("hidden_content", "embedded objects (other files inside this one)")
        if any(n.startswith("customXml/") for n in names):
            rep.kept("hidden_content", "custom XML data parts")
        thumbs = {n for n in names if n.startswith("docProps/thumbnail")}
        if thumbs:
            doomed |= thumbs
            rep.removed("hidden_content", "document thumbnail image")

        if doomed:
            pkg.remove(doomed)
        return pkg.build()
    except (UnicodeDecodeError, KeyError):
        rep.kept("file_metadata", "Office file has unexpected structure", "high")
        return data


# -- entry point ------------------------------------------------------------------------------------
def detect_format(data: bytes) -> str:
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(_PNG_SIG):
        return "png"
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                if "[Content_Types].xml" in zf.namelist():
                    return "ooxml"
        except zipfile.BadZipFile:
            pass
        return "zip"
    if decode_text(data) is not None:
        return "text"
    return "unknown"


def sanitize_file(data: bytes) -> SanitizeResult:
    fmt = detect_format(data)
    rep = _Report(fmt)
    if fmt == "jpeg":
        cleaned = _sanitize_jpeg(data, rep)
    elif fmt == "png":
        cleaned = _sanitize_png(data, rep)
    elif fmt == "pdf":
        cleaned = _sanitize_pdf(data, rep)
    elif fmt == "ooxml":
        cleaned = _sanitize_ooxml(data, rep)
    elif fmt == "text":
        cleaned = data
    else:
        cleaned = data
        rep.kept("file_metadata", f"{fmt} format is not supported by the sanitizer", "medium")
    return SanitizeResult(cleaned=cleaned, changed=cleaned != data, complete=rep.complete,
                          format=fmt, findings=rep.findings)
