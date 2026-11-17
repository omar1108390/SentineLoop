"""In-memory static file triage for prompt injection and common malware indicators.

Uploaded bytes are inspected only. This module never writes, loads, or executes them.
"""

import hashlib
import html.parser
import io
import re
import zipfile
from pathlib import PurePath
from typing import Any
from xml.etree import ElementTree

from firewall import Firewall

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_EXTRACTED_CHARS = 120_000
MAX_ZIP_ENTRIES = 300
MAX_ZIP_EXPANDED_BYTES = 12 * 1024 * 1024
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class _HTMLText(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data)


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
        raise ValueError("PDF extraction is unavailable; install the files extra") from error
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
    if suffix == ".docx" or suffix == ".docm":
        return _extract_docx(data), "office-document"
    if suffix == ".pdf" or content_type == "application/pdf":
        return _extract_pdf(data), "pdf"
    if suffix in {".html", ".htm"} or content_type == "text/html":
        parser = _HTMLText()
        parser.feed(data.decode("utf-8", errors="replace"))
        return "\n".join(parser.parts), "html"
    text_types = {
        ".txt",
        ".md",
        ".csv",
        ".json",
        ".xml",
        ".eml",
        ".log",
        ".py",
        ".js",
        ".ps1",
        ".vbs",
        ".bat",
        ".sh",
        ".rtf",
        ".yaml",
        ".yml",
    }
    if (
        suffix in text_types
        or content_type.startswith("text/")
        or suffix in {".doc", ".xls", ".ppt"}
    ):
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
    if EICAR in data:
        indicators.append(
            {
                "name": "eicar-test-signature",
                "severity": "high",
                "detail": "Known antivirus test signature detected.",
            }
        )
    if data.startswith(b"MZ"):
        indicators.append(
            {
                "name": "windows-executable-header",
                "severity": "review",
                "detail": "File begins with a Windows PE executable header.",
            }
        )
    if data.startswith(b"\x7fELF"):
        indicators.append(
            {
                "name": "elf-executable-header",
                "severity": "review",
                "detail": "File begins with an ELF executable header.",
            }
        )
    if suffix in {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}:
        indicators.append(
            {
                "name": "macro-enabled-office-format",
                "severity": "review",
                "detail": "Macro-capable Office format; macros are not executed.",
            }
        )
    if (
        suffix in {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
        and b"vbaProject.bin" in data
    ):
        indicators.append(
            {
                "name": "office-vba-project",
                "severity": "high",
                "detail": "Embedded VBA project marker detected.",
            }
        )
    script_rules = (
        (
            r"powershell(?:\.exe)?\s+[^\r\n]{0,80}(?:-enc(?:odedcommand)?\b|frombase64string)",
            "encoded-powershell",
            "high",
        ),
        (r"\b(?:invoke-expression|iex)\s*\(", "dynamic-powershell-execution", "review"),
        (r"\bdownloadstring\s*\(", "remote-script-download", "high"),
        (r"\b(?:autoopen|document_open)\b", "office-auto-run-macro", "review"),
        (r"/javascript\b|/openaction\b|/launch\b", "pdf-active-content-marker", "review"),
    )
    for pattern, name, severity in script_rules:
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            indicators.append(
                {
                    "name": name,
                    "severity": severity,
                    "detail": "Suspicious static content pattern detected.",
                }
            )
    return indicators


def analyze_bytes(filename: str, content_type: str, data: bytes) -> dict[str, Any]:
    """Inspect one upload without persisting or executing it."""
    safe_name = PurePath(filename.replace("\\", "/")).name[:180] or "uploaded-file"
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"File exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MB limit")
    text, file_kind = _extract_text(safe_name, content_type.lower(), data)
    text = text[:MAX_EXTRACTED_CHARS]
    indicators = _malware_indicators(safe_name, data, text)
    prompt_check = Firewall().inspect_input(text) if text.strip() else None
    has_high = any(item["severity"] == "high" for item in indicators)
    malware_status = "suspicious" if has_high else "review" if indicators else "no-known-indicator"
    return {
        "filename": safe_name,
        "file_kind": file_kind,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "stored": False,
        "executed": False,
        "malware": {"status": malware_status, "indicators": indicators},
        "prompt_injection": {
            "status": prompt_check.verdict if prompt_check else "not-scanned",
            "layer": prompt_check.layer if prompt_check else None,
            "score": prompt_check.score if prompt_check else None,
            "reason": prompt_check.reason if prompt_check else "No extractable text found.",
        },
        "extracted_text": text,
        "preview": text[:600],
        "disclaimer": "Static indicators only; no known indicator does not prove a file is safe.",
    }
