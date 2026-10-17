"""Handler: filesystem anomalies pre-collected by UAC (Linux). Aggregates the
hint files UAC produces into one triage table. Output: file_anomalies.csv

Note: many entries are benign (e.g. .cache, .htaccess); this surfaces them for
the analyst to triage, it does not assert maliciousness.

NOT THIS HOST'S FILES (v0.7.143). Container storage -- image layers and each
container's rootfs under /run/containerd, /var/lib/docker, a k3s/rke2 node's
/var/lib/rancher, ... -- is full of files owned by uids this host has never
heard of, and its /run, /tmp and dot-files are the image's. On six real hosts it
was 434,632 of 437,000 rows and nearly every flag. The collector's own output
tree (a `uac` directory on the host) is the same: a copy, not the host. Neither
is listed; each excluded tree is one `excluded` row saying how many entries it
held, so the table never stops without saying so.
"""

from __future__ import annotations

import re
from collections import Counter

from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv
from artifact_engine.handlers.lin_collection import looks_like_tool
from artifact_engine.handlers.lin_storage import _RUNTIME_ROOTS

# file in system/ -> indicator label; the line is split into (path, detail).
_SIMPLE = {
    "hidden_files.txt": "hidden_file",
    "hidden_directories.txt": "hidden_dir",
    "group_name_unknown_files.txt": "unknown_group_owner",
    "user_name_unknown_files.txt": "unknown_user_owner",
}

# World-writable / transient / web locations where a hidden file or extra
# capability is far more likely to be attacker-dropped than benign.
_SUSPICIOUS_PREFIXES = (
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/var/run/",
    "/var/www/", "/srv/www/", "/usr/share/nginx/", "/var/spool/",
)


def _suspicious(path: str) -> str:
    return "yes" if path.startswith(_SUSPICIOUS_PREFIXES) else ""


# btrfs/zfs read-only snapshot copies (duplicate the live tree).
_SNAPSHOT = re.compile(r"/\.snapshots/\d+/snapshot/|/\.zfs/snapshot/")

# Sticky/temp/runtime dirs where world-writable is normal -> skipped.
_WW_EXPECTED = (
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/var/run/", "/var/lock/",
    "/var/spool/", "/dev/mqueue/",
)
# System locations where a world-writable DIRECTORY is a strong tamper signal
# (writable webroot/upload/home dirs are expected-sloppy on shared web hosts).
_WW_SYSTEM = (
    "/etc/", "/usr/", "/bin/", "/sbin/", "/lib", "/lib64", "/boot/", "/opt/",
    "/root/", "/var/log/",
)
# Inert data files: world-writable here is sloppy webapp perms, not a drop
# vector. Writable scripts/binaries/configs (everything else) stay flagged.
_INERT_EXT = {
    "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico", "webp", "tiff", "tif", "heic",
    "mp4", "mp3", "wav", "avi", "mov", "mkv", "flac", "ogg", "m4a", "webm",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "ppsx", "pps", "odt", "ods", "odp", "rtf",
    "csv", "tsv", "txt", "log", "md", "css", "js", "map", "less", "scss",
    "woff", "woff2", "ttf", "eot", "otf", "zip", "gz", "tar", "bz2", "xz", "7z", "rar",
    "json", "xml", "yaml", "yml", "po", "mo", "sql", "dat", "html", "htm",
}


def _ext(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _world_writable(sysd, rows: list[list]) -> None:
    # Files: flag writable scripts/binaries/configs; skip snapshots, temp churn
    # and inert data files (images/docs) that are merely sloppy webapp perms.
    for ln in read_lines(sysd / "world_writable_files.txt"):
        s = ln.strip()
        if not s or _SNAPSHOT.search(s) or s.startswith(_WW_EXPECTED) or _ext(s) in _INERT_EXT:
            continue
        rows.append(["world_writable_file", s, "", "yes"])
    # Dirs: only system-path writable dirs are a real signal; webroot/upload
    # dirs are expected-sloppy and would otherwise flood the table.
    for ln in read_lines(sysd / "world_writable_directories.txt"):
        s = ln.strip()
        if s and not _SNAPSHOT.search(s) and s.startswith(_WW_SYSTEM):
            rows.append(["world_writable_dir", s, "", "yes"])


def _not_the_host(path: str) -> str:
    """The excluded tree `path` sits in -- container storage or the collector's
    own output -- or '' when it is this host's file."""
    for r in _RUNTIME_ROOTS:
        if path.startswith(r):
            return r.rstrip("/")
    parts = path.split("/")
    for i, part in enumerate(parts[:-1]):
        if part and looks_like_tool(part):
            return "/".join(parts[:i + 1])
    return ""


def _exclude(rows: list[list]) -> list[list]:
    """`rows` without the excluded trees, plus one `excluded` row for each."""
    kept, gone = [], Counter()
    for r in rows:
        tree = _not_the_host(r[1])
        if tree:
            gone[tree] += 1
        else:
            kept.append(r)
    for tree, n in sorted(gone.items()):
        note = (f"{n:,} entries in container storage or the collector's output, "
                f"not this host's files: not listed")
        kept.append(["excluded", tree, note, ""])
    return kept


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    rows: list[list] = []
    if lr:
        sysd = lr / "system"
        for fname, label in _SIMPLE.items():
            for ln in read_lines(sysd / fname):
                s = ln.strip()
                if s:
                    rows.append([label, s, "", _suspicious(s)])
        # getcap: "<path> <capabilities>" - file capabilities are a privesc vector.
        for ln in read_lines(sysd / "getcap_-r.txt"):
            s = ln.strip()
            if not s:
                continue
            path, _, caps = s.partition(" ")
            rows.append(["file_capability", path, caps.strip(), _suspicious(path)])
        _world_writable(sysd, rows)
    rows = _exclude(rows)
    # surface the suspicious ones first
    rows.sort(key=lambda r: (r[3] != "yes", r[0]))
    write_csv(ctx.out, "file_anomalies.csv", ["indicator", "path", "detail", "suspicious"], rows)
