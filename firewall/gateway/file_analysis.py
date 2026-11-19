"""Document scanner: find prompt injections hidden in files *before* an AI reads them.

Indirect prompt injection usually arrives inside documents: an HTML comment,
white or zero-size text, a hidden Word run, an encoded block. The scanner
extracts all text (including the hidden parts), lists the hiding tricks it found
and runs the firewall detectors on each passage so it can point at the
suspicious one.

It also reports a few classic *malware* indicators (executable headers, macros,
the EICAR test string) as a secondary courtesy check; it is **not** an antivirus.

Uploaded bytes are inspected in memory only: never written, loaded or executed.
"""

from __future__ import annotations

import hashlib
import html.parser
import io
import re
import zipfile
from pathlib import PurePath
from typing import Any
from xml.etree import ElementTree

from firewall import Firewall
from firewall.layers.normalizer import normalize_report

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_EXTRACTED_CHARS = 120_000
MAX_ZIP_ENTRIES = 300
MAX_ZIP_EXPANDED_BYTES = 12 * 1024 * 1024
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d]*[1-9])|"
    r"opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|color\s*:\s*(?:#fff(?:fff)?|white)\b",
    re.IGNORECASE,
)
VOID_TAGS = {"br", "img", "hr", "meta", "link", "input", "source", "wbr", "area", "base", "col"}
TEXT_SUFFIXES = {
    ".txt", ".md", ".csv", ".json", ".xml", ".eml", ".log", ".py", ".js", ".ps1", ".vbs",
    ".bat", ".sh", ".rtf", ".yaml", ".yml",
}  # fmt: skip


class _HTMLText(html.parser.HTMLParser):
    """Collect visible text, visually hidden text and comments separately."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden: list[str] = []
        self.comments: list[str] = []
        self._stack: list[bool] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in VOID_TAGS:
            return
        values = dict(attrs)
        hidden = bool(HIDDEN_STYLE.search(values.get("style") or "")) or "hidden" in values
        self._stack.append(hidden or (bool(self._stack) and self._stack[-1]))

    def handle_endtag(self, tag: str) -> None:
        if tag not in VOID_TAGS and self._stack:
            self._stack.pop()

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self.comments.append(data.strip())

    def handle_data(self, data: str) -> None:
        if not data.strip():
            return
        if self._stack and self._stack[-1]:
            self.hidden.append(data.strip())
        else:
            self.parts.append(data.strip())


def _parse_html(data: bytes) -> _HTMLText:
    parser = _HTMLText()
    parser.feed(data.decode("utf-8", errors="replace"))
    return parser


def _extract_docx(data: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ZIP_ENTRIES:
                raise ValueError("Office document contains too many archive entries")
            if sum(entry.file_size for entry in entries) > MAX_ZIP_EXPANDED_BYTES:
                raise ValueError("Office document expands beyond the analysis limit")
            xml_names = [
                name
                for name in archive.namelist()
                if name.startswith("word/")
                and name.endswith(".xml")
                and any(part in name for part in ("document", "comments", "header", "footer"))
            ]
            content = []
            for name in xml_names:
                root = ElementTree.fromstring(archive.read(name))
                content.extend(node.text or "" for node in root.iter() if node.tag.endswith("}t"))
            return "\n".join(content)
    except (zipfile.BadZipFile, ElementTree.ParseError, KeyError, OSError) as error:
        raise ValueError("Office document could not be parsed") from error


def _extract_pdf(data: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as error:
        raise ValueError("PDF extraction is unavailable; install pypdf") from error
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if len(reader.pages) > 100:
            raise ValueError("PDF exceeds the 100-page analysis limit")
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except ValueError:
        raise
    except Exception as error:
        raise ValueError("PDF could not be parsed") from error


def _extract_text(filename: str, content_type: str, data: bytes) -> tuple[str, str]:
    suffix = PurePath(filename).suffix.lower()
    if suffix in {".docx", ".docm"}:
        return _extract_docx(data), "office-document"
    if suffix == ".pdf" or content_type == "application/pdf":
        return _extract_pdf(data), "pdf"
    if suffix in {".html", ".htm"} or content_type == "text/html":
        parser = _parse_html(data)
        return "\n".join(parser.parts + parser.hidden + parser.comments), "html"
    if suffix in TEXT_SUFFIXES or content_type.startswith("text/") or suffix in {".doc", ".xls", ".ppt"}:
        return data.decode("utf-8", errors="replace"), "text"
    if data.startswith(b"PK\x03\x04"):
        try:
            return _extract_docx(data), "office-document"
        except ValueError:
            return "", "archive"
    return "", "binary"


def _malware_indicators(filename: str, data: bytes, extracted_text: str) -> list[dict[str, str]]:
    indicators: list[dict[str, str]] = []
    suffix = PurePath(filename).suffix.lower()
    lowered = extracted_text.casefold()

    def add(name: str, severity: str, detail: str) -> None:
        indicators.append({"name": name, "severity": severity, "detail": detail})

    if EICAR in data:
        add("eicar-test-signature", "high", "Known antivirus test signature detected.")
    if data.startswith(b"MZ"):
        add("windows-executable-header", "review", "File begins with a Windows PE executable header.")
    if data.startswith(b"\x7fELF"):
        add("elf-executable-header", "review", "File begins with an ELF executable header.")
    if suffix in {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}:
        add("macro-enabled-office-format", "review", "Macro-capable Office format; macros are not executed.")
    if suffix in {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"} and b"vbaProject.bin" in data:
        add("office-vba-project", "high", "Embedded VBA project marker detected.")
    script_rules = (
        (r"powershell(?:\.exe)?\s+[^\r\n]{0,80}(?:-enc(?:odedcommand)?\b|frombase64string)",
         "encoded-powershell", "high"),
        (r"\b(?:invoke-expression|iex)\s*\(", "dynamic-powershell-execution", "review"),
        (r"\bdownloadstring\s*\(", "remote-script-download", "high"),
        (r"\b(?:autoopen|document_open)\b", "office-auto-run-macro", "review"),
        (r"/javascript\b|/openaction\b|/launch\b", "pdf-active-content-marker", "review"),
    )  # fmt: skip
    for pattern, name, severity in script_rules:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            add(name, severity, "Suspicious static content pattern detected.")
    return indicators


def _hiding_tricks(file_kind: str, data: bytes, text: str) -> list[str]:
    """Ways the document hides content from a human reader."""
    tricks: list[str] = []
    if file_kind == "html":
        parser = _parse_html(data)
        if parser.comments:
            tricks.append(f"{len(parser.comments)} HTML comment(s), invisible when the page is rendered")
        if parser.hidden:
            tricks.append(
                f"{len(parser.hidden)} visually hidden text block(s) (display:none, white or 0-size text)"
            )
    if file_kind == "office-document" and b"w:vanish" in data:
        tricks.append("Word text formatted as hidden")
    _, notes = normalize_report(text)
    tricks.extend(note for note in notes if "HTML" not in note)
    return list(dict.fromkeys(tricks))


def _passages(text: str, size: int = 500) -> list[str]:
    chunks, current = [], ""
    for paragraph in re.split(r"\n", text):
        paragraph = paragraph.strip()
        if not paragraph:
            continue
        if current and len(current) + len(paragraph) > size:
            chunks.append(current)
            current = ""
        current = (current + "\n" + paragraph).strip()
    if current:
        chunks.append(current)
    return chunks[:200]


def analyze_bytes(filename: str, content_type: str, data: bytes) -> dict[str, Any]:
    """Inspect one upload without persisting or executing it."""
    safe_name = PurePath(filename.replace("\\", "/")).name[:180] or "uploaded-file"
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"File exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB limit")
    text, file_kind = _extract_text(safe_name, content_type.lower(), data)
    text = text[:MAX_EXTRACTED_CHARS]
    indicators = _malware_indicators(safe_name, data, text)
    firewall = Firewall()
    passages = _passages(text)
    findings = []
    for passage in passages:
        check = firewall.inspect_input(passage, stage="document")
        if check.verdict == "block":
            # Point at the line that triggered the detector when one does on its own.
            lines = [line for line in passage.split("\n") if line.strip()]
            culprit = next(
                (line for line in lines if firewall.inspect_input(line, stage="document").verdict == "block"),
                passage,
            )
            findings.append(
                {"excerpt": culprit[:300], "layer": check.layer, "score": round(check.score, 3),
                 "reason": check.reason}  # fmt: skip
            )
    whole = firewall.inspect_input(text, stage="document") if text.strip() else None
    if whole is not None and whole.verdict == "block" and not findings:
        findings.append(
            {"excerpt": text[:300], "layer": whole.layer, "score": round(whole.score, 3),
             "reason": whole.reason}  # fmt: skip
        )
    has_high = any(item["severity"] == "high" for item in indicators)
    malware_status = "suspicious" if has_high else "review" if indicators else "no-known-indicator"
    first = findings[0] if findings else None
    if not text.strip():
        status, reason = "not-scanned", "No extractable text found."
    elif first:
        status, reason = "block", first["reason"]
    else:
        status, reason = "allow", "no detector flagged any passage"
    return {
        "filename": safe_name,
        "file_kind": file_kind,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "stored": False,
        "executed": False,
        "malware": {"status": malware_status, "indicators": indicators},
        "prompt_injection": {
            "status": status,
            "layer": first["layer"] if first else None,
            "score": first["score"] if first else (round(whole.score, 3) if whole else None),
            "reason": reason,
            "findings": findings,
            "hiding_tricks": _hiding_tricks(file_kind, data, text) if text.strip() else [],
            "passages_scanned": len(passages),
        },
        "extracted_text": text,
        "preview": text[:600],
        "disclaimer": (
            "Detectors can miss new attacks and the malware check is not an antivirus: "
            "a clean result does not prove the file is safe."
        ),
    }
