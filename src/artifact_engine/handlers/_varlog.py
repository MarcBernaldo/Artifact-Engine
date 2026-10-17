"""Which text logs under /var/log are syslog files, and which are other text.

`syslog` takes the files written in syslog format (messages, syslog, secure,
warn, mail*, cron, kern.log, daemon.log, ...), whatever they are called, and
`other_logs` every other text file. Left out of both kinds: the directories
that hold a format of their own, read by other parsers (the journal, auditd,
the web servers, container logs) -- a text log another parser also reads, like
the package logs, is still taken -- what is not a log (binary records such as
wtmp, lastlog and sysstat files; archives that bundle a tool's output) and the
folders support tools drop there.

A file's kind is decided on its first lines, decompressed, so a rotation is
judged like its live file and a name proves nothing either way.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import re
from collections.abc import Iterator
from pathlib import Path

from artifact_engine.handlers._lincommon import _ROTATION, root, sort_rotations

# Read by other parsers (auditd_events, the web parsers) or in a format of their
# own (the systemd journal, Kubernetes/Docker container logs).
_OWNED_DIRS = {"journal", "audit", "apache2", "httpd", "nginx", "lighttpd", "pods", "containers"}
# Bundles, not logs: archives of a tool's output (supportconfig, leapp, YaST).
_ARCHIVES = (".tar", ".tgz", ".txz", ".tbz2", ".tar.gz", ".tar.xz", ".tar.bz2", ".zip", ".7z",
             ".rpm", ".deb")
# Output folders support tools write under /var/log: SUSE supportconfig
# (`scc_<host>_<date>`) and zypper's solver test cases.
_TOOL_DIRS = re.compile(r"^(?:scc_|updateTestcase-)")
_OPENERS = {".gz": gzip.open, ".xz": lzma.open, ".bz2": bz2.open}
_HEAD = 65536
_PROBE_LINES = 20

# "<ts> <host> <program>[pid]: <message>"; ts RFC 3339 or the classic "Aug  9 14:03:11".
SYSLOG_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\dT[\d:.+\-]+Z?|[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+(?P<program>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$")


def _head(f: Path) -> bytes | None:
    try:
        with (_OPENERS.get(f.suffix.lower()) or open)(f, "rb") as fh:
            return fh.read(_HEAD)
    except (OSError, EOFError, ValueError, lzma.LZMAError):
        return None


def kind(f: Path) -> str:
    """'syslog', 'text' or '' (binary, unreadable or empty)."""
    head = _head(f)
    if not head or b"\x00" in head:
        return ""
    lines = [ln for ln in head.decode("utf-8", "replace").splitlines() if ln.strip()][:_PROBE_LINES]
    if not lines:
        return ""
    hits = sum(1 for ln in lines if SYSLOG_LINE.match(ln))
    return "syslog" if hits * 2 >= len(lines) else "text"


def family(f: Path) -> str:
    """The live file a rotation belongs to: `messages-20260519.xz` -> `messages`."""
    return _ROTATION.sub("", f.name)


def log_files(evidence: Path, want: str) -> Iterator[Path]:
    """Every /var/log file of kind `want`, family by family, oldest rotation first."""
    base = root(evidence) / "var" / "log"
    if not base.is_dir():
        return
    groups: dict[tuple[Path, str], list[Path]] = {}
    for f in sorted(base.rglob("*")):
        rel = f.relative_to(base).parts
        if rel[0] in _OWNED_DIRS or any(_TOOL_DIRS.match(p) for p in rel[:-1]):
            continue
        name = f.name.lower()
        if name.endswith(_ARCHIVES) or not f.is_file():
            continue
        groups.setdefault((f.parent, family(f)), []).append(f)
    for _key, files in sorted(groups.items(), key=lambda kv: (str(kv[0][0]), kv[0][1])):
        for f in sort_rotations(files):
            if kind(f) == want:
                yield f
