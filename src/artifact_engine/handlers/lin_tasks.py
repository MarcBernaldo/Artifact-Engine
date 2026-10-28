"""Handler: everything a Linux host runs on a schedule, in one table. Output: art_tasks.csv

The Linux counterpart of Windows' `art_tasks`. Until v0.7.168 the answer was spread over
three tables in three shapes: `cron_jobs` held each crontab line as one string
(schedule, user and command unsplit, environment lines mixed in), the systemd
timers sat in `persistence` as one row per directive and again in `services` as
the runtime list, and `at` jobs in `persistence`. Nobody could read "what runs,
as whom, when, and when did it last run" off any of them.

One row per scheduled thing, whatever the mechanism:

  cron             /etc/crontab, /etc/cron.d, the user spools: schedule, user
                   (the sixth field, or the spool file's owner) and command apart
  cron environment a `NAME=value` line of a crontab: applies to every job below
                   it, so LD_* and a PATH reaching a writable directory are flagged
  anacron          /etc/anacrontab: period, delay, job id, command
  periodic script  /etc/cron.{hourly,daily,weekly,monthly}: one row per script,
                   flagged on the first suspicious line INSIDE it
  at               a queued `at` job: when it runs (decoded from the file name)
                   and the commands after the environment preamble `at` writes
  systemd timer    a .timer unit: its schedule, and the command of the unit it
                   starts; with the runtime next/last run when the acquisition
                   holds `systemctl list-timers`
  cron access      cron.allow / cron.deny entries

`modified_utc` is the file's mtime from the bodyfile -- when the schedule was
last written, which is the moment persistence was installed -- and `runs` /
`last_run_utc` count the matching executions in `art_log_cron`, so a crontab line
that never ran reads differently from one that ran every five minutes.
"""

from __future__ import annotations

import csv
import re
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.handlers._lincommon import live_response, read_lines, root, write_csv
from artifact_engine.handlers.lin_persistence import _SUSP, _homes

_BODYFILE = Path("CSVs") / "Filesystem" / "art_bodyfile.csv"
_CRON_LOG = Path("CSVs") / "EventLogs" / "art_log_cron.csv"

COLUMNS = ["mechanism", "file", "user", "schedule", "command", "modified_utc",
           "runs", "last_run_utc", "state", "suspicious", "reason"]

_PERIODIC = ("cron.hourly", "cron.daily", "cron.weekly", "cron.monthly")
_ENV = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
_WRITABLE = ("/tmp", "/var/tmp", "/dev/shm", "/home/", "/run/user")

# `at` names a job file `<queue><job:5 hex><minutes since the epoch:8 hex>`.
_AT_NAME = re.compile(r"^[a-zA-Z=]([0-9a-f]{5})([0-9a-f]{8})$")

_TIMER_KEYS = ("OnCalendar", "OnBootSec", "OnStartupSec", "OnUnitActiveSec",
               "OnUnitInactiveSec", "OnActiveSec")
_UNIT_DIRS = ("etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system")
_STAMP = re.compile(r"[A-Z][a-z]{2} \d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?: \S+)?")


def _rel(base: Path, f: Path) -> str:
    try:
        return f.relative_to(base).as_posix()
    except ValueError:
        return f.name


def _flag(text: str) -> str:
    """The reason a command is worth a look, or ''."""
    m = _SUSP.search(text or "")
    return f"command has `{m.group(0).strip()}`" if m else ""


def _env_flag(name: str, value: str) -> str:
    if name.upper().startswith("LD_"):
        return f"{name} set for every job in this file"
    if name.upper() == "PATH":
        parts = value.strip().strip("\"'").split(":")
        bad = [p for p in parts if p in ("", ".") or p.startswith(_WRITABLE)]
        if bad:
            return f"PATH reaches {bad[0] or 'the current directory'} before the system dirs"
    return ""


def _row(mechanism, file, user="", schedule="", command="", state="", reason=""):
    return {"mechanism": mechanism, "file": file, "user": user, "schedule": schedule,
            "command": command, "state": state, "reason": reason}


def _crontab(rows: list[dict], base: Path, f: Path, owner: str | None) -> None:
    """One crontab file. `owner` is the spool's user; None means a system file,
    whose sixth field names the user."""
    rel = _rel(base, f)
    for line in read_lines(f):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        env = _ENV.match(s)
        if env and not s.startswith("@"):
            rows.append(_row("cron environment", rel, owner or "", "", s,
                             reason=_env_flag(env.group(1), env.group(2))))
            continue
        parts = s.split()
        n = 1 if s.startswith("@") else 5
        user_at = n if owner is None else None
        if len(parts) <= n + (1 if user_at is not None else 0):
            rows.append(_row("cron", rel, owner or "", "", s, reason=_flag(s)))
            continue
        schedule = " ".join(parts[:n])
        user = parts[user_at] if user_at is not None else owner
        command = s.split(None, n + (1 if user_at is not None else 0))[-1]
        rows.append(_row("cron", rel, user, schedule, command, reason=_flag(command)))


def _anacron(rows: list[dict], base: Path) -> None:
    f = base / "etc" / "anacrontab"
    for line in read_lines(f):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        env = _ENV.match(s)
        if env:
            rows.append(_row("cron environment", _rel(base, f), "root", "", s,
                             reason=_env_flag(env.group(1), env.group(2))))
            continue
        parts = s.split(None, 3)
        if len(parts) == 4:
            period, delay, job, command = parts
            rows.append(_row("anacron", _rel(base, f), "root",
                             f"every {period} (delay {delay} min, job {job})", command,
                             reason=_flag(command)))


def _periodic(rows: list[dict], base: Path) -> None:
    for name in _PERIODIC:
        d = base / "etc" / name
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if not f.is_file() or f.name.startswith("."):
                continue
            reason = ""
            for line in read_lines(f):
                s = line.strip()
                if s and not s.startswith("#") and (r := _flag(s)):
                    reason = f"{r} in: {s[:120]}"
                    break
            rows.append(_row("periodic script", _rel(base, f), "root",
                             name.removeprefix("cron."), "/" + _rel(base, f), reason=reason))


def _at_commands(f: Path) -> list[str]:
    """The lines of an `at` job after its preamble. `at` writes the environment
    (`X=...; export X`), then `cd <dir> || {` ... `}`, then the user's commands."""
    lines = [ln.rstrip() for ln in read_lines(f)]
    end = max((i for i, ln in enumerate(lines) if ln.strip() == "}"), default=-1)
    if end < 0:
        end = max((i for i, ln in enumerate(lines) if ln.strip().startswith("cd ")), default=-1)
    return [ln.strip() for ln in lines[end + 1:]
            if ln.strip() and not ln.strip().startswith("#")]


def _at(rows: list[dict], base: Path) -> None:
    for d in (base / "var/spool/at", base / "var/spool/cron/atjobs"):
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if not f.is_file() or f.name.startswith("."):
                continue
            when = ""
            m = _AT_NAME.match(f.name)
            if m:
                at = datetime.fromtimestamp(int(m.group(2), 16) * 60, tz=timezone.utc)
                when = f"once at {at:%Y-%m-%d %H:%M} UTC"
            cmds = _at_commands(f)
            command = "; ".join(cmds)
            rows.append(_row("at", _rel(base, f), "", when, command[:500],
                             reason=_flag(command)))


def _unit_keys(f: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in read_lines(f):
        s = line.strip()
        if "=" in s and not s.startswith(("#", ";")):
            k, v = s.split("=", 1)
            out.setdefault(k.strip(), v.strip())
    return out


def _timers(rows: list[dict], base: Path) -> dict[str, dict]:
    """Timer unit files: system dirs first (the first copy of a name wins, as
    systemd resolves it), then each account's ~/.config/systemd/user."""
    found: dict[str, dict] = {}
    dirs = [(base / d, "root") for d in _UNIT_DIRS]
    for home in _homes(base):
        dirs.append((home / ".config/systemd/user", home.name))
    for d, user in dirs:
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.timer")):
            if not f.is_file() or f.name in found:
                continue
            keys = _unit_keys(f)
            schedule = "; ".join(f"{k}={keys[k]}" for k in _TIMER_KEYS if k in keys)
            unit = keys.get("Unit") or f.name.removesuffix(".timer") + ".service"
            svc = next((x / unit for x, _ in dirs if (x / unit).is_file()), None)
            sk = _unit_keys(svc) if svc else {}
            command = sk.get("ExecStart", "").lstrip("-@:+!")
            row = _row("systemd timer", _rel(base, f), sk.get("User", user), schedule,
                       command or f"(starts {unit})", reason=_flag(command))
            found[f.name] = row
            rows.append(row)
    return found


def _runtime_timers(rows: list[dict], found: dict[str, dict], evidence: Path) -> None:
    """`systemctl list-timers --all`: next and last run of each timer. A timer
    loaded at acquisition with no unit file in the collection is a row too."""
    lr = live_response(evidence)
    if not lr:
        return
    for raw in read_lines(lr / "system" / "systemctl_list-timers_--all.txt")[1:]:
        toks = raw.split()
        idx = next((i for i, t in enumerate(toks) if t.endswith(".timer")), -1)
        if idx < 0:
            continue
        unit, activates = toks[idx], " ".join(toks[idx + 1:])
        head = raw[:raw.find(unit)]
        stamps = _STAMP.findall(head)
        if head.strip().lower().startswith("n/a"):
            nxt, last = "n/a", (stamps[0] if stamps else "n/a")
        else:
            nxt = stamps[0] if stamps else "n/a"
            last = stamps[1] if len(stamps) > 1 else "n/a"
        state = f"next {nxt}; last {last}"
        if unit in found:
            found[unit]["state"] = state
        else:
            rows.append(_row("systemd timer", "", "", "", f"(starts {activates})",
                             state=f"{state}; no unit file in the collection"))


def _access(rows: list[dict], base: Path) -> None:
    for name in ("cron.allow", "cron.deny"):
        f = base / "etc" / name
        for line in read_lines(f):
            s = line.strip()
            if s and not s.startswith("#"):
                rows.append(_row("cron access", _rel(base, f), s))


def _bodyfile(evidence: Path, wanted: set[str]) -> dict[str, tuple[str, str]]:
    """{absolute path: (mtime_utc, uid)} for the files named, from the bodyfile.

    The lines are tested on their first characters before the CSV is parsed: a
    container node's bodyfile is millions of rows, and only a handful are ours."""
    src = evidence / _BODYFILE
    out: dict[str, tuple[str, str]] = {}
    if not wanted or not src.is_file():
        return out
    heads = tuple({"/" + w.split("/")[1] for w in wanted} | {'"/' + w.split("/")[1] for w in wanted})
    try:
        with src.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            header = next(csv.reader([fh.readline()]), [])
            try:
                ni, mi, ui = (header.index(c) for c in ("name", "mtime_utc", "uid"))
            except ValueError:
                return out
            for line in fh:
                if not line.startswith(heads):
                    continue
                r = next(csv.reader([line]), [])
                if len(r) > max(ni, mi, ui) and r[ni] in wanted:
                    out[r[ni]] = (r[mi], r[ui])
    except OSError:
        return out
    return out


def _cron_runs(evidence: Path) -> dict[tuple[str, str], tuple[int, str]]:
    """{(user, command): (executions, last time_utc)} from art_log_cron."""
    src = evidence / _CRON_LOG
    out: dict[tuple[str, str], tuple[int, str]] = {}
    if not src.is_file():
        return out
    try:
        with src.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            for r in csv.DictReader(fh):
                if r.get("kind") != "exec":
                    continue
                key = (r.get("user", ""), (r.get("detail") or "").strip())
                n, last = out.get(key, (0, ""))
                out[key] = (n + 1, max(last, r.get("time_utc") or ""))
    except (OSError, csv.Error):
        return out
    return out


def _passwd(base: Path) -> dict[str, str]:
    out = {}
    for line in read_lines(base / "etc" / "passwd"):
        p = line.split(":")
        if len(p) > 2:
            out[p[2]] = p[0]
    return out


def run(ctx) -> None:
    evidence = Path(ctx.evidence)
    base = root(evidence)
    rows: list[dict] = []

    for f in (base / "etc" / "crontab",):
        if f.is_file():
            _crontab(rows, base, f, None)
    d = base / "etc" / "cron.d"
    if d.is_dir():
        for f in sorted(d.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                _crontab(rows, base, f, None)
    for d in (base / "var/spool/cron", base / "var/spool/cron/crontabs"):
        if d.is_dir():
            for f in sorted(d.iterdir()):
                if f.is_file() and not f.name.startswith("."):
                    _crontab(rows, base, f, f.name)
    _anacron(rows, base)
    _periodic(rows, base)
    _at(rows, base)
    found = _timers(rows, base)
    _runtime_timers(rows, found, evidence)
    _access(rows, base)

    files = {"/" + r["file"] for r in rows if r["file"]}
    meta = _bodyfile(evidence, files)
    users = _passwd(base)
    runs = _cron_runs(evidence)
    out = []
    for r in rows:
        mtime, uid = meta.get("/" + r["file"], ("", "")) if r["file"] else ("", "")
        if not r["user"] and r["mechanism"] == "at" and uid:
            r["user"] = users.get(uid, f"uid {uid}")
        n, last = runs.get((r["user"], r["command"]), (0, "")) \
            if r["mechanism"] == "cron" else (0, "")
        out.append([r["mechanism"], r["file"], r["user"], r["schedule"], r["command"],
                    mtime, n or "", last, r["state"], "yes" if r["reason"] else "",
                    r["reason"]])
    out.sort(key=lambda x: (x[9] != "yes", x[0], x[1]))
    write_csv(ctx.out, "art_tasks.csv", COLUMNS, out)
