"""Parser for the "ECU Software Version Report" exported by OceanLink Pro (OLP).

The format (verified against a real report, 2026-08-28):

    OceanLink Pro
    ECU Software Version Report
    Date: 2026-08-28 18:15:16.564271
    VIN: VCF1ZBE21PG0xxxxx
    BODY                                  <- section (BODY/INFOTAINMENT/POWERTRAIN/CHASSIS/ADAS)
    GW - Gateway                          <- ECU block: CODE - Full name
    Software Version: FM298034S100K
    Hardware Version: FM298034H100C
    Supplier SW Version: GW500002         <- the field used in the Marlin comparison
    Bootloader Version: HIRAIN1.0.8
    ...

The parser accepts both PDF (text extracted with pdfplumber) and plain text
with the same line structure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

VIN_RE = re.compile(r"^VIN:\s*([A-HJ-NPR-Z0-9]{17})\s*$", re.MULTILINE)
def parse_report_date(text: str) -> datetime | None:
    """The OLP "Date:" line as an aware datetime, or None when it is missing
    or not a date. OLP writes the laptop's local time without a zone; it is
    taken as UTC, which is close enough for ages in days and for ordering."""
    try:
        parsed = datetime.fromisoformat(str(text).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


DATE_RE = re.compile(r"^Date:\s*(.+)$", re.MULTILINE)
# Section headings are short all-uppercase lines (BODY, ADAS, ...)
SECTION_RE = re.compile(r"^[A-Z][A-Z ]{2,24}$")
# ECU block: "CODE - Full name", e.g. "MCU_F - Motor Control Unit Front"
ECU_HEADER_RE = re.compile(r"^([A-Z][A-Z0-9_]{0,11}) - (.+)$")
# Older OLP builds (mid-2025) label the field "Supplier Software Version";
# newer ones "Supplier SW Version". Both carry the value the check uses.
FIELD_RE = re.compile(
    r"^(Software|Hardware|Supplier SW|Supplier Software|Bootloader) Version:\s*(.*)$"
)
# pdfplumber renders undefined glyphs (padding in the OLP PDFs) as "(cid:0)"
_CID_JUNK_RE = re.compile(r"\(cid:\d+\)")


def clean_value(value: str) -> str:
    """Strips pdfplumber's (cid:N) padding glyphs and surrounding whitespace.
    OLP writes NA when the module gave no answer; that is an empty field."""
    value = _CID_JUNK_RE.sub("", value).strip()
    if value.upper() in ("NA", "N/A") or not re.search(r"[A-Za-z0-9]", value):
        return ""  # NA, or only punctuation such as ")))" (a module that gave no answer)
    return value

MAX_REPORT_BYTES = 15 * 1024 * 1024
# A real OLP report is a handful of pages. Text extraction is CPU-bound and
# linear in the amount of text, so a page cap keeps a hostile PDF from tying up
# a worker thread for minutes.
MAX_REPORT_PAGES = 20


class ReportParseError(Exception):
    """The file could not be interpreted as a valid OLP report.

    `key` is an i18n key (locales: "parse_<key>") so the reason can be shown in
    the user's language; `detail` is optional technical extra info (untranslated).
    """

    def __init__(self, key: str, detail: str = ""):
        self.key = key
        self.detail = detail
        super().__init__(key if not detail else f"{key}: {detail}")


@dataclass
class ModuleReading:
    code: str            # e.g. "VCU", "MCU_F"
    name: str            # e.g. "Vehicle Control Unit"
    section: str         # e.g. "POWERTRAIN"
    supplier_sw: str     # "Supplier SW Version" — used in the comparison
    software: str = ""
    hardware: str = ""
    bootloader: str = ""

    @property
    def raw_name(self) -> str:
        return f"{self.code} - {self.name}"

    @property
    def version(self) -> str:
        return self.supplier_sw


@dataclass
class ParsedReport:
    vin: str
    modules: list[ModuleReading] = field(default_factory=list)
    meta: dict = field(default_factory=dict)


def _extract_text(data: bytes, filename: str) -> str:
    if data[:5] == b"%PDF-":
        try:
            import io

            import pdfplumber

            with pdfplumber.open(io.BytesIO(data)) as pdf:
                page_count = len(pdf.pages)
                if page_count > MAX_REPORT_PAGES:
                    raise ReportParseError(
                        "too_many_pages", f"{page_count} pages, max {MAX_REPORT_PAGES}"
                    )
                pages = [page.extract_text() or "" for page in pdf.pages]
            return "\n".join(pages)
        except ReportParseError:
            raise
        except Exception as exc:  # corrupt/encrypted PDF etc.
            raise ReportParseError("bad_pdf", str(exc)) from exc
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReportParseError("unreadable") from exc


_FIELD_ATTR = {
    "Software": "software",
    "Hardware": "hardware",
    "Supplier SW": "supplier_sw",
    "Supplier Software": "supplier_sw",
    "Bootloader": "bootloader",
}


def parse_report(data: bytes, filename: str = "") -> ParsedReport:
    if len(data) > MAX_REPORT_BYTES:
        raise ReportParseError("too_large")
    if not data:
        raise ReportParseError("empty")

    text = _extract_text(data, filename)

    if "ECU Software Version Report" not in text:
        raise ReportParseError("no_header")

    vin_match = VIN_RE.search(text)
    if not vin_match:
        raise ReportParseError("no_vin")
    vin = vin_match.group(1)

    date_match = DATE_RE.search(text)

    modules: list[ModuleReading] = []
    section = ""
    current: dict | None = None

    def _flush() -> None:
        nonlocal current
        if current is not None:
            modules.append(ModuleReading(**current))
            current = None

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        header = ECU_HEADER_RE.match(line)
        if header:
            _flush()
            current = {
                "code": header.group(1),
                "name": header.group(2).strip(),
                "section": section,
                "supplier_sw": "",
            }
            continue
        fld = FIELD_RE.match(line)
        if fld and current is not None:
            current[_FIELD_ATTR[fld.group(1)]] = clean_value(fld.group(2))
            continue
        if SECTION_RE.match(line) and " - " not in line:
            _flush()
            section = line
            continue

    _flush()

    if not modules:
        raise ReportParseError("no_modules")

    return ParsedReport(
        vin=vin,
        modules=modules,
        meta={
            "filename": filename,
            "report_date": date_match.group(1).strip() if date_match else "",
        },
    )
