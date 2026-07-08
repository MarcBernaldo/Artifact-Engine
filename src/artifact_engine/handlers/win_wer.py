"""Handler: Windows Error Reporting (WER) report files.

Each crash/hang leaves an INI-like ``.wer`` file (UTF-16) under
    ProgramData/Microsoft/Windows/WER/{ReportArchive,ReportQueue}/**/Report.wer

It records the full path of the binary that crashed, the faulting module and the
EventTime (FILETIME) = proof of execution that survives deletion of the binary.

Output: wer.csv
"""

from __future__ import annotations

import csv
from datetime import datetime, timedelta
from pathlib import Path

_WER = "ProgramData/Microsoft/Windows/WER"


def _read_text(path: Path) -> str:
    """Decode by BOM (.wer files are UTF-16 w/ BOM); never guess UTF-16 endianness."""
    raw = path.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            pass
    if raw[:3] == b"\xef\xbb\xbf":
        return raw.decode("utf-8-sig", errors="replace")
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def _filetime(value: str) -> str:
    """EventTime is a decimal FILETIME (100-ns intervals since 1601)."""
    try:
        ft = int(value)
    except (TypeError, ValueError):
        return value
    if ft <= 0:
        return ""
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=ft / 10)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except (OverflowError, OSError):
        return ""


def _parse(path: Path) -> dict[str, str]:
    """Flatten the key=value lines, pairing Sig[n].Name with Sig[n].Value."""
    flat: dict[str, str] = {}
    sig_name: dict[str, str] = {}
    sig_value: dict[str, str] = {}
    for line in _read_text(path).splitlines():
        key, sep, val = line.partition("=")
        if not sep:
            continue
        key, val = key.strip(), val.strip()
        if key.startswith("Sig[") and key.endswith("].Name"):
            sig_name[key[4:-6]] = val
        elif key.startswith("Sig[") and key.endswith("].Value"):
            sig_value[key[4:-7]] = val
        else:
            flat[key] = val
    # name -> value for the signature fields (e.g. "Fault Module Name" -> ntdll.dll)
    sigs = {sig_name[i]: sig_value.get(i, "") for i in sig_name}
    flat["_sigs"] = sigs  # type: ignore[assignment]
    return flat


def run(ctx) -> None:
    base = ctx.evidence / _WER
    header = ["report", "event_type", "event_time", "app_name", "app_path",
              "fault_module", "exception_code"]
    rows = []
    if base.is_dir():
        for wer in sorted(base.rglob("*.wer")):
            try:
                f = _parse(wer)
            except OSError:
                continue
            sigs = f.get("_sigs", {})  # type: ignore[assignment]
            rows.append([
                wer.parent.name,
                f.get("EventType", ""),
                _filetime(f.get("EventTime", "")),
                sigs.get("Application Name", "") or f.get("AppName", ""),
                f.get("AppPath", "") or f.get("TargetAppId", ""),
                sigs.get("Fault Module Name", "") or sigs.get("Faulting Module Name", ""),
                sigs.get("Exception Code", ""),
            ])

    if not rows:
        return                       # no WER reports -> no CSV
    ctx.out.mkdir(parents=True, exist_ok=True)
    with open(ctx.out / "wer.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
