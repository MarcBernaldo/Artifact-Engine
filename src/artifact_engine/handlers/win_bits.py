"""Handler: BITS transfer jobs (qmgr.db / qmgr*.dat). Output: bits_jobs.csv

The Background Intelligent Transfer Service queues file downloads/uploads and
persists them in ``ProgramData\\Microsoft\\Network\\Downloader\\`` — ``qmgr.db``
(ESE, Win10 1709+) or ``qmgr0.dat``/``qmgr1.dat`` (legacy). BITS is a common
malware channel: it survives reboots, runs as SYSTEM, and download traffic looks
like Windows Update. A job stores the remote URL next to the local destination.

Rather than parse the ESE/legacy container (no dependency for either format),
each job's remote URL and local path are carved out: both are stored as
consecutive UTF-16LE strings, the destination a few bytes after the URL. This is
format-agnostic (works on .db and .dat alike) and needs no schema. Identical
(url, dest) records are collapsed with a count. ``suspicious`` = a raw-IP host
(CDNs use names), an ftp URL, or a script/executable dropped somewhere other than
the browser/OS update temp — the shapes a benign auto-update never takes.
"""

from __future__ import annotations

import re
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv

_DOWNLOADER = "ProgramData/Microsoft/Network/Downloader"

# UTF-16LE printable run; a BITS job stores the URL then, a few bytes later, the
# local destination path in the same encoding.
_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
_URL = re.compile(r"(?i)^(?:https?|ftp)://")
_PATH = re.compile(r"^(?:[A-Za-z]:\\|\\\\)")
_HOST = re.compile(r"(?i)^[a-z]+://([^/:]+)")
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_USER = re.compile(r"(?i)\\Users\\([^\\]+)\\")
_EXEC_EXT = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".vbe",
             ".js", ".jse", ".hta", ".scr", ".msi")


def _host(url: str) -> str:
    m = _HOST.match(url)
    return m.group(1) if m else ""


def _owner(dest: str) -> str:
    m = _USER.search(dest)
    return m.group(1) if m else ""


def _suspicious(url: str, dest: str) -> str:
    host = _host(url)
    if _IP.match(host):                              # raw-IP host: CDNs use names
        return "yes"
    if url.lower().startswith("ftp://"):
        return "yes"
    low = dest.lower()
    if low.endswith(_EXEC_EXT):
        # BITS delivering a runnable file is only normal into the browser/OS
        # update temp; anywhere else (or with no dest at all) is worth a look.
        if "\\temp\\" not in low and "\\windowsapps\\" not in low:
            return "yes"
    return ""


def _carve(data: bytes) -> dict[tuple[str, str], int]:
    runs = [(m.start(), m.end(), m.group().decode("utf-16le", "replace"))
            for m in _RUN.finditer(data)]
    jobs: dict[tuple[str, str], int] = {}
    for i, (_s, e, text) in enumerate(runs):
        if not _URL.match(text):
            continue
        dest = ""
        for oo, _ee, ss in runs[i + 1:i + 4]:        # destination sits just after
            if 0 < oo - e < 40 and _PATH.match(ss):
                dest = ss
                break
        key = (text, dest)
        jobs[key] = jobs.get(key, 0) + 1
    return jobs


def run(ctx) -> None:
    root = Path(ctx.evidence) / _DOWNLOADER
    files = [p for p in root.glob("qmgr*") if p.is_file()] if root.is_dir() else []
    if not files:
        raise HandlerSkip("no BITS qmgr store")

    jobs: dict[tuple[str, str], int] = {}
    for f in files:
        try:
            data = f.read_bytes()
        except OSError:
            continue
        for key, n in _carve(data).items():
            jobs[key] = jobs.get(key, 0) + n

    rows = []
    for (url, dest), count in jobs.items():
        susp = _suspicious(url, dest)
        rows.append([_owner(dest), _host(url), url, dest, count, susp])
    rows.sort(key=lambda r: (r[5] != "yes", -r[4], r[2]))
    write_csv(ctx.out, "bits_jobs.csv",
              ["user", "host", "url", "dest", "count", "suspicious"], rows)
