r"""Handler: scheduled tasks registered, what they ran, and the ones removed after.
Output: task_installs.csv

Three tables in this engine already carry scheduled tasks -- `tasks_disk` (the
System32\Tasks XML store), `reg_scheduledtasks` (TaskCache) and `evtx_tasks` (the
Task Scheduler channel) -- and every one of them answers "what is registered
now". None of them was ever asked what happened to a task, which is the question
the event log alone can answer.

WHAT ONLY THE LOG KNOWS. A task deleted after it ran leaves NOTHING on disk and
nothing in the registry. Event 106 records that it was registered and BY WHOM,
141 that it was removed and by whom, and 200/201 carry `ActionName` -- the binary
the task actually executed. So for a task that no longer exists anywhere, the
channel still holds the account that planted it, the command it ran, and the
minute it was cleaned up. That is the service-install signature of
`service_installs`, on the other classic mechanism.

ORDER IS THE WHOLE DIFFERENCE, and getting it wrong turns this into noise. A task
UPDATE is implemented as a delete followed by a re-registration, so 141 before 106
is Windows updating OneDrive and 106 before 141 is somebody removing what they
installed. Only the second is counted -- and even then a create/delete pair on its
own is NOT flagged, because vendors do exactly that every update cycle. What is
flagged is the pair that closes quickly around an execution: registered, ran, gone
inside the hour.

DISK ROWS ARE A SECOND, NARROWER SOURCE. A task still on disk is already fully
reported by `tasks_disk`, so re-listing it here would be duplication. It earns a
row only when the community task list names the tooling behind it, because that
attribution has nowhere else to live -- and the `source` column says which
provenance each row came from, since "was registered at 14:02 by this account" and
"is sitting on disk" are not the same claim.

The list is enrichment, as everywhere else: it arrives with `aeng update`, and
without it this handler loses tool names, never the lifecycle findings.
"""

from __future__ import annotations

import csv
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _awesome, _evtx
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_liveresponse_velociraptor import _in_staging, _is_lolbin
from artifact_engine.handlers.win_service_installs import image_binary
from artifact_engine.logging_setup import get_logger

log = get_logger()

_TSCH_CSV = Path("CSVs") / "EventLogs" / "evtx_tsch.csv"
_TASKS_DISK_CSV = Path("CSVs") / "Persistence" / "tasks_disk.csv"

_TASKS_LIST = "suspicious_windows_tasks_list.csv"

_REGISTERED, _UPDATED, _DELETED = "106", "140", "141"
_RAN = ("200", "201")

# A task registered and destroyed inside this window was not a task, it was a way
# to run something. An hour is generous on purpose: the technique closes in
# seconds, and an installer that legitimately removes a task it registered does it
# across a reboot or an upgrade, not within the same lunch break.
_SHORT_LIFE_MIN = 60

# Interpreters an action has no business being. Shares `image_binary` with the
# service handler so both mechanisms answer this identically -- an ImagePath and a
# task ActionName are the same kind of string, and a substring match on either
# would put every `cmdmon.exe` on the estate at the top of the table.
_SHELL_NAMES = {"cmd", "%comspec%", "comspec", "powershell", "pwsh", "wscript",
                "cscript", "mshta", "rundll32", "regsvr32", "curl", "bitsadmin",
                "certutil", "msiexec"}

# A hostile or corrupt channel must not become a memory problem in a worker.
_MAX_TASKS = 100_000

_COLUMNS = ["registered_utc", "task", "registered_by", "deleted_utc", "deleted_by",
            "lifespan_minutes", "runs", "last_run_utc", "action", "on_disk",
            "disk_command", "source", "indicators", "tool", "tool_category",
            "list_severity", "reference", "suspicious"]


class _Task:
    """Every Task Scheduler event that named one task, in the order they arrived."""

    __slots__ = ("deleted", "registered", "runs")

    def __init__(self) -> None:
        self.registered: list[tuple[str, str]] = []      # (time, user)
        self.deleted: list[tuple[str, str]] = []
        self.runs: list[tuple[str, str]] = []            # (time, action)


def lifecycle(task: _Task) -> tuple[str, str, str, str, int | None]:
    """(registered, by, deleted, by, minutes alive) for the first registration
    that was FOLLOWED by a deletion, else just the first registration.

    A 141 that precedes every 106 is an update -- Windows re-registers a task by
    removing it first -- and reading that as a removal would report every vendor
    updater on the machine.
    """
    first = task.registered[0] if task.registered else ("", "")
    for when, user in task.registered:
        start = _evtx.when(when)
        for d_when, d_user in task.deleted:
            end = _evtx.when(d_when)
            if start is None or end is None:
                # Unparseable stamps: the pair is real, its duration is not.
                return when, user, d_when, d_user, None
            if end >= start:
                return when, user, d_when, d_user, int((end - start).total_seconds() // 60)
    return first[0], first[1], "", "", None


def ran_between(task: _Task, start: str, end: str) -> bool:
    """Whether the task executed between its registration and its removal."""
    a, b = _evtx.when(start), _evtx.when(end)
    if a is None or b is None:
        return bool(task.runs)
    return any(a <= r <= b for r in (_evtx.when(t) for t, _ in task.runs) if r)


def action_is_a_shell(action: str) -> bool:
    return image_binary(action) in _SHELL_NAMES


def _events(path: Path):
    """(event id, task name, user, action, time) for every task-scheduler row."""
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(line.replace("\x00", "") for line in fh):
            eid = (row.get("EventId") or "").strip()
            payload = row.get("Payload") or ""
            name = (_evtx.after(row.get("PayloadData1") or "", "Task")
                    or _evtx.payload_field(payload, "TaskName"))
            if not name:
                continue
            user = ((row.get("UserName") or "").strip()
                    or _evtx.payload_field(payload, "UserContext")
                    or _evtx.payload_field(payload, "UserName"))
            action = ((row.get("ExecutableInfo") or "").strip()
                      or _evtx.payload_field(payload, "ActionName"))
            yield eid, name.strip(), user, action, (row.get("TimeCreated") or "").strip()


def _collect(path: Path) -> dict[str, _Task]:
    """Every task the channel names, keyed by lower-cased task path."""
    tasks: dict[str, _Task] = {}
    for eid, name, user, action, when in _events(path):
        if eid not in (_REGISTERED, _UPDATED, _DELETED) and eid not in _RAN:
            continue
        key = name.lower()
        rec = tasks.get(key)
        if rec is None:
            if len(tasks) >= _MAX_TASKS:
                log.warning(f"[!] task_installs: stopped at {_MAX_TASKS} task names")
                break
            rec = tasks[key] = _Task()
        if eid == _REGISTERED:
            rec.registered.append((when, user))
        elif eid == _DELETED:
            rec.deleted.append((when, user))
        elif eid in _RAN and action:
            rec.runs.append((when, action))
    return tasks


def _on_disk(base: Path) -> dict[str, str]:
    """{task name (lower): command} from tasks_disk.csv, {} when it did not run."""
    path = base / _TASKS_DISK_CSV
    if not path.is_file():
        return {}
    out: dict[str, str] = {}
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            for row in csv.DictReader(fh):
                name = (row.get("task") or "").strip()
                if name:
                    out[name.lower()] = (row.get("command") or "").strip()
    except (OSError, csv.Error):
        return out
    return out


def _hit(listed: list[_awesome.Entry], name: str, action: str):
    """The list entry covering this task, by name first and by action after."""
    found = _awesome.match(listed, name)
    if found is None and action:
        found = _awesome.match(listed, action)
    return found


def _row(task: str, reg: tuple[str, str], dele: tuple[str, str], span: int | None,
         runs: list[tuple[str, str]], action: str, disk: str | None,
         source: str, found: list[str], hit, flagged: bool) -> list:
    return [
        reg[0], task, reg[1], dele[0], dele[1],
        "" if span is None else span, len(runs) or "",
        runs[-1][0] if runs else "", action,
        # tasks_disk may not have run, and "unknown" is not "gone": writing `no`
        # for the first would invent the strongest half of the signature on every
        # case with no Tasks folder collected. Three-valued, and not `suspicious`:
        "" if disk is None else ("yes" if disk else "no"),
        disk or "", source, " ".join(found),
        hit.tool if hit else "", hit.category if hit else "",
        hit.severity if hit else "", hit.reference if hit else "",
        "yes" if flagged else "",
    ]


def _indicators(rec: _Task, action: str, present: str | None,
                reg_when: str, del_when: str, span: int | None) -> list[str]:
    found: list[str] = []
    if reg_when and del_when:
        found.append("registered_then_deleted")
        if span is not None and span <= _SHORT_LIFE_MIN:
            found.append("short_lived")
        if ran_between(rec, reg_when, del_when):
            found.append("ran_before_deletion")
    if present == "" and reg_when:
        found.append("gone_from_disk")
    if action_is_a_shell(action):
        found.append("action_is_a_shell")
    if _is_lolbin(action):
        found.append("download_or_encoded_command")
    if _in_staging(action):
        found.append("action_in_staging")
    return found


def run(ctx) -> None:
    base = Path(ctx.evidence)
    src = base / _TSCH_CSV
    disk = _on_disk(base)
    if not src.is_file() and not disk:
        raise HandlerSkip("no evtx_tsch.csv and no tasks_disk.csv to read")

    listed = _awesome.load(Path(ctx.assets), _TASKS_LIST,
                           key="TaskName", extra_key="TaskCommand")

    tasks: dict[str, _Task] = {}
    if src.is_file():
        try:
            tasks = _collect(src)
        except (OSError, csv.Error) as e:
            raise HandlerSkip(f"evtx_tsch.csv unreadable: {e}") from e

    rows: list[list] = []
    seen: set[str] = set()
    for name, rec in tasks.items():
        reg_when, reg_by, del_when, del_by, span = lifecycle(rec)
        action = rec.runs[-1][1] if rec.runs else ""
        present = disk.get(name) if disk else None
        if disk and name not in disk:
            present = ""                       # it ran, and it is not there now

        found = _indicators(rec, action, present, reg_when, del_when, span)
        hit = _hit(listed, name, action)
        if hit is not None:
            found.append("on_threat_list" if hit.offensive else "known_greyware")
        if not found:
            continue

        flagged = (
            (hit is not None and hit.offensive)
            or ("short_lived" in found and "ran_before_deletion" in found)
            or "download_or_encoded_command" in found
            or ("action_is_a_shell" in found
                and ("gone_from_disk" in found or "registered_then_deleted" in found))
            or len(found) >= 3
        )
        seen.add(name)
        rows.append(_row(name, (reg_when, reg_by), (del_when, del_by), span,
                         rec.runs, action, present,
                         "both" if disk and name in disk else "eventlog",
                         found, hit, flagged))

    # A task still on disk is already fully reported by tasks_disk; it earns a row
    # here only when the list names the tooling behind it, which has nowhere else
    # to live.
    for name, command in disk.items():
        if name in seen:
            continue
        hit = _hit(listed, name, command)
        if hit is None:
            continue
        label = ["on_threat_list" if hit.offensive else "known_greyware"]
        rows.append(_row(name, ("", ""), ("", ""), None, [], command, command,
                         "disk", label, hit, hit.offensive))

    # Flagged first, then in time order, with the disk-only rows (which have no
    # registration time to sort by) after the dated ones rather than above them.
    rows.sort(key=lambda r: (r[-1] != "yes", not r[0], r[0], r[1]))
    write_csv(ctx.out, "task_installs.csv", _COLUMNS, rows)
