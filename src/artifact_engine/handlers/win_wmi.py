"""Handlers: WMI repository (OBJECTS.DATA) carving.

EZ Tools do not touch the WMI repository, which most responders skip. Two
artifacts are carved straight out of OBJECTS.DATA by keyword search (no full
CIM parse needed):

* ``persistence`` -> wmi_persistence.csv
      FilterToConsumerBindings (EventConsumer / __EventFilter), the classic WMI
      persistence mechanism, with the consumer command line and the filter WQL.

* ``ccm_rua`` -> wmi_ccm_rua.csv
      SCCM software-metering RecentlyUsedApplication records = execution
      evidence (full path, last user, last run time, launch count).

Both are Python-3 reimplementations of David Pany's (Mandiant) PyWMIPersistenceFinder
and CCM_RUA_Finder, which are Python-2 only:
    https://github.com/davidpany/WMI_Forensics

Carving operates on the raw bytes decoded as latin-1 (1 byte -> 1 codepoint) so
NUL-delimited fields survive intact and re-encode losslessly for struct parsing.
"""

from __future__ import annotations

import csv
import re
import string
import struct
from datetime import datetime, timedelta
from pathlib import Path

_REPO = "Windows/System32/wbem/Repository"
_PRINTABLE = set(string.printable)


def _objects_data(evidence: Path) -> Path | None:
    """OBJECTS.DATA is at Repository/ (modern) or Repository/FS/ (legacy)."""
    repo = evidence / _REPO
    direct = repo / "OBJECTS.DATA"
    if direct.is_file():
        return direct
    return next(repo.rglob("OBJECTS.DATA"), None) if repo.is_dir() else None


def _write(path: Path, header: list[str], rows: list) -> None:
    if not rows:
        return                       # nothing found -> no CSV
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


# --------------------------------------------------------------------------- #
# WMI persistence: FilterToConsumerBindings
# --------------------------------------------------------------------------- #
# Bindings whose names match these are usually shipped by Windows itself.
_COMMON_BINDINGS = {
    "BVTConsumer-BVTFilter",
    "SCM Event Log Consumer-SCM Event Log Filter",
}
_CONSUMER_NAME = re.compile(r'([\w_]*EventConsumer)\.Name="([\w\s]*)"')
_FILTER_NAME = re.compile(r'(_EventFilter)\.Name="([\w\s]*)"')


# A consumer record is far smaller than this; the name is looked up in a bounded
# window after each marker instead of a lazy ".*?(...).*?<name>" scan across the
# whole blob. That scan backtracks catastrophically on some real repositories
# (multi-MB OBJECTS.DATA where the name isn't near a marker), pinning the GIL
# for hours and freezing the entire run -- bars dead, Ctrl+C unresponsive.
_DETAIL_WINDOW = 8192


def _consumer_detail(blob: str, name: str) -> tuple[str, str]:
    """(consumer_type, command/arguments) for a consumer name."""
    for m in re.finditer(r"CommandLineEventConsumer\x00\x00", blob):
        win = blob[m.end(): m.end() + _DETAIL_WINDOW]
        idx = win.find(name)
        if idx >= 0:
            # First NUL-delimited field after the marker = the command line.
            args = win[:idx].split("\x00", 1)[0]
            return "CommandLineEventConsumer", (
                "".join(ch for ch in args if ch in _PRINTABLE).strip())
    for m in re.finditer(r"\w*EventConsumer", blob):
        win = blob[m.end(): m.end() + _DETAIL_WINDOW]
        idx = win.find(name)
        if idx < 0:
            continue
        dm = re.match(r"\x00\x00([^\x00]*)\x00\x00([^\x00]*)", win[idx + len(name):])
        if dm:
            detail = " ~ ".join(p for p in (dm.group(1), dm.group(2)) if p)
            return m.group(0), "".join(ch for ch in detail if ch in _PRINTABLE).strip()
    return "", ""


def _filter_query(blob: str, name: str) -> str:
    m = re.search(re.escape(name) + r"\x00\x00([^\x00]*)\x00\x00", blob, re.DOTALL)
    if not m:
        return ""
    return "".join(ch for ch in m.group(1) if ch in _PRINTABLE).strip()


def persistence(ctx) -> None:
    out = ctx.out / "wmi_persistence.csv"
    header = ["binding", "consumer_name", "consumer_type", "consumer_detail",
              "filter_name", "filter_query", "note"]
    objects = _objects_data(ctx.evidence)
    if objects is None:
        _write(out, header, [])
        return

    blob = objects.read_bytes().decode("latin-1")

    # A binding ties an EventConsumer to an __EventFilter. Their names co-occur
    # near the "_FilterToConsumerBinding" marker; a window keeps the pairing.
    bindings: dict[tuple[str, str], None] = {}
    for m in re.finditer(r"_FilterToConsumerBinding", blob):
        window = blob[max(0, m.start() - 2048): m.end() + 2048]
        cm = _CONSUMER_NAME.search(window)
        fm = _FILTER_NAME.search(window)
        if cm and fm:
            bindings.setdefault((cm.group(2), fm.group(2)), None)

    rows = []
    for cname, fname in bindings:
        ctype, detail = _consumer_detail(blob, cname)
        query = _filter_query(blob, fname)
        binding = f"{cname}-{fname}"
        note = "common (likely legitimate)" if binding in _COMMON_BINDINGS else ""
        rows.append([binding, cname, ctype, detail, fname, query, note])

    _write(out, header, rows)


# --------------------------------------------------------------------------- #
# SCCM RecentlyUsedApplication (CCM_RUA)
# --------------------------------------------------------------------------- #
# Class-instance GUID headers, as they appear in the file (utf-16le bytes seen
# through a latin-1 decode).
_GUID_VISTA = ("7C261551B264D35E30A7FA29C75283DAE04BBA71DBE8F5E553F7AD381B406DD8"
               .encode("utf-16le").decode("latin-1"))
_GUID_XP = ("6FA62F462BEF740F820D72D9250D743C"
            .encode("utf-16le").decode("latin-1"))

_RUA_FIELDS = (
    "additional_product_codes company_name explorer_file_name file_description "
    "file_properties_hash file_version folder_path last_used_time last_user_name "
    "msi_display_name msi_publisher msi_version original_file_name product_language "
    "product_name product_version software_properties_hash"
).split()

_NULLDEL = re.compile(
    r"CCM_RecentlyUsedApps\x00\x00" + r"\x00\x00".join(
        rf"(?P<{f}>[^\x00]*)" for f in _RUA_FIELDS
    )
)
_NULLDEL_FULL = re.compile(
    rf"(?P<GUID>{re.escape(_GUID_VISTA)}|{re.escape(_GUID_XP)})"
    r"(?P<rua_header>[\x00-\xff]{20,250})" + _NULLDEL.pattern
)
_HEADER = re.compile(
    rf"(?P<GUID>{re.escape(_GUID_VISTA)}|{re.escape(_GUID_XP)})"
    r"(?P<ts1>[\x00-\xff]{8})(?P<ts2>[\x00-\xff]{8})[\x00-\xff]{34}"
    r"(?P<file_size>[\x00-\xff]{4})[\x00-\xff]{20}(?P<launch_count>[\x00-\xff]{4})"
)
_XML = re.compile(
    r"<CCM_RecentlyUsedApps>.*?<ExplorerFileName>(?P<explorer_file_name>.*?)</ExplorerFileName>"
    r".*?<FolderPath>(?P<folder_path>.*?)</FolderPath>"
    r".*?<LastUsedTime>(?P<last_used_time>.*?)</LastUsedTime>"
    r".*?<LastUserName>(?P<last_user_name>.*?)</LastUserName>",
    re.DOTALL,
)


def _filetime(raw8: str) -> str:
    """8-byte FILETIME (100-ns intervals since 1601) -> ISO string."""
    try:
        nano = struct.unpack("<Q", raw8.encode("latin-1"))[0]
        if not nano:
            return ""
        return (datetime(1601, 1, 1) + timedelta(microseconds=nano / 10)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except (struct.error, OverflowError, OSError, ValueError):
        return ""


def _wmi_used_time(raw: str) -> str:
    """CCM LastUsedTime 'YYYYMMDDHHMMSS....' -> 'YYYY-MM-DD HH:MM:SS'."""
    if len(raw) < 14 or not raw[:14].isdigit():
        return raw
    return f"{raw[:4]}-{raw[4:6]}-{raw[6:8]} {raw[8:10]}:{raw[10:12]}:{raw[12:14]}"


def _clean(value: str) -> str:
    return "".join(ch for ch in value if ch == " " or ch in _PRINTABLE).strip()


def ccm_rua(ctx) -> None:
    out = ctx.out / "wmi_ccm_rua.csv"
    header = ["format", "folder_path", "explorer_file_name", "file_size",
              "last_user_name", "last_used_time", "launch_count",
              "timestamp1", "timestamp2", "original_file_name", "file_description",
              "company_name", "product_name", "product_version", "file_version"]
    objects = _objects_data(ctx.evidence)
    if objects is None:
        _write(out, header, [])
        return

    data = objects.read_bytes()
    rows = []
    seen: set[tuple] = set()
    for hit in re.finditer(rb"CCM_RecentlyUsedApps", data):
        window = data[max(0, hit.start() - 300): hit.start() + 2100].decode("latin-1")
        row = _parse_ccm_record(window)
        if row is None:
            continue
        key = (row[1], row[2], row[5])  # folder, exe, last_used_time
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)

    _write(out, header, rows)


def _parse_ccm_record(window: str) -> list | None:
    full = _NULLDEL_FULL.search(window)
    if full:
        return _row_from_nulldel(full, header=True)
    carve = _NULLDEL.search(window)
    if carve:
        return _row_from_nulldel(carve, header=False)
    xml = _XML.search(window)
    if xml:
        g = xml.groupdict()
        return ["XML", _clean(g.get("folder_path", "")), _clean(g.get("explorer_file_name", "")),
                "", _clean(g.get("last_user_name", "")), _wmi_used_time(g.get("last_used_time", "")),
                "", "", "", "", "", "", "", "", ""]
    return None


def _row_from_nulldel(m: re.Match, header: bool) -> list:
    g = m.groupdict()
    fmt, fsize, launch, ts1, ts2 = "Carved_NullDelim", "", "", "", ""
    if header and "GUID" in g:
        fmt = "Vista+_Full" if g["GUID"] == _GUID_VISTA else "XP_Full"
        hm = _HEADER.search(g["GUID"] + g.get("rua_header", ""))
        if hm:
            ts1 = _filetime(hm.group("ts1"))
            ts2 = _filetime(hm.group("ts2"))
            try:
                fsize = str(struct.unpack("<L", hm.group("file_size").encode("latin-1"))[0])
                launch = str(struct.unpack("<L", hm.group("launch_count").encode("latin-1"))[0])
            except (struct.error, ValueError):
                pass
    return [
        fmt, _clean(g["folder_path"]), _clean(g["explorer_file_name"]), fsize,
        _clean(g["last_user_name"]), _wmi_used_time(g["last_used_time"]), launch,
        ts1, ts2, _clean(g["original_file_name"]), _clean(g["file_description"]),
        _clean(g["company_name"]), _clean(g["product_name"]),
        _clean(g["product_version"]), _clean(g["file_version"]),
    ]
