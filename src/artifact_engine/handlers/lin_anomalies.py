"""Handler: filesystem anomalies pre-collected by UAC (Linux). Aggregates the
hint files UAC produces into one triage table. Output: anomalies.csv

Note: many entries are benign (e.g. .cache, .htaccess); this surfaces them for
the analyst to triage, it does not assert maliciousness.
"""

from __future__ import annotations

import re

from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv

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
    # surface the suspicious ones first
    rows.sort(key=lambda r: (r[3] != "yes", r[0]))
    write_csv(ctx.out, "anomalies.csv", ["indicator", "path", "detail", "suspicious"], rows)
