"""Handler: all cron locations centralised. Output: cron.csv

Covers the crontab-style files (/etc/crontab, /etc/cron.d, /etc/anacrontab,
per-user spools) line by line, the periodic script directories
(/etc/cron.{hourly,daily,weekly,monthly}) as one row per script, and the
cron.allow/cron.deny access lists.
"""

from __future__ import annotations

from artifact_engine.handlers._lincommon import read_lines, root, write_csv


def _rel(base, f):
    try:
        # POSIX separators: this is a Linux artifact path, not a host path.
        return f.relative_to(base).as_posix()
    except ValueError:
        return f.name


def run(ctx) -> None:
    base = root(ctx.evidence)
    rows: list[list] = []

    # 1) crontab-style files: emit each active (non-comment) line.
    tab_files = [base / "etc" / "crontab", base / "etc" / "anacrontab"]
    for d in (base / "etc" / "cron.d", base / "var" / "spool" / "cron",
              base / "var" / "spool" / "cron" / "crontabs"):
        if d.is_dir():
            tab_files += [f for f in sorted(d.iterdir()) if f.is_file()]
    for f in tab_files:
        if not f.is_file():
            continue
        src = _rel(base, f)
        for line in read_lines(f):
            s = line.strip()
            if s and not s.startswith("#"):
                rows.append([src, s])

    # 2) periodic script dirs: presence is the signal (content is a full script).
    for name in ("cron.hourly", "cron.daily", "cron.weekly", "cron.monthly"):
        d = base / "etc" / name
        if d.is_dir():
            for f in sorted(d.iterdir()):
                if f.is_file():
                    rows.append([_rel(base, f), "(periodic script)"])

    # 3) cron access control lists.
    for name in ("cron.allow", "cron.deny"):
        f = base / "etc" / name
        if f.is_file():
            for line in read_lines(f):
                s = line.strip()
                if s and not s.startswith("#"):
                    rows.append([_rel(base, f), s])

    write_csv(ctx.out, "cron.csv", ["source", "entry"], rows)
