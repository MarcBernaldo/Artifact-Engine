"""Handler: scheduled tasks from the on-disk XML (System32/Tasks). Output: tasks_disk.csv

Every task the box has registered, straight from the Task Scheduler XML store -
independent of the TaskCache registry (reg_scheduledtasks) and of the event log
(evtx_tasks), so it works when the SOFTWARE hive is damaged or the log rolled,
and it exposes fields the other two summarise: author, exact command+arguments,
run-as principal and run level, trigger types, and the Hidden setting.

One row per task file; the full set is surfaced (the analyst filters the
Microsoft\\Windows\\* bulk), with `suspicious` doing the triage: command out of
a staging dir, a LOLBin action, or a task marked Hidden.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_liveresponse_velociraptor import _in_staging, _is_lolbin

_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


def _text(node, *path) -> str:
    cur = node
    for tag in path:
        if cur is None:
            return ""
        cur = cur.find(_NS + tag)
    return (cur.text or "").strip() if cur is not None and cur.text else ""


def _parse_task(data: bytes) -> dict | None:
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None
    reg = root.find(_NS + "RegistrationInfo")
    principal = root.find(f"{_NS}Principals/{_NS}Principal")
    settings = root.find(_NS + "Settings")
    actions = root.find(_NS + "Actions")

    cmds: list[str] = []
    if actions is not None:
        for ex in actions.findall(_NS + "Exec"):
            cmd = _text(ex, "Command")
            args = _text(ex, "Arguments")
            cmds.append((cmd + " " + args).strip())
        for ch in actions.findall(_NS + "ComHandler"):
            clsid = _text(ch, "ClassId")
            if clsid:
                cmds.append(f"COM:{clsid}")

    triggers = root.find(_NS + "Triggers")
    trig = ";".join(sorted({t.tag[len(_NS):] for t in triggers}
                           )) if triggers is not None else ""

    return {
        "author": _text(reg, "Author") if reg is not None else "",
        "created": _text(reg, "Date") if reg is not None else "",
        "runas": _text(principal, "UserId") if principal is not None else "",
        "runlevel": _text(principal, "RunLevel") if principal is not None else "",
        "hidden": "yes" if _text(settings, "Hidden").lower() == "true" else "",
        "disabled": "yes" if _text(settings, "Enabled").lower() == "false" else "",
        "trigger": trig,
        "command": " | ".join(c for c in cmds if c),
    }


# Vendor folders whose tasks are Hidden BY DESIGN (NGEN, Forefront, Google
# Updater, ...): dozens per machine, so Hidden only signals outside of them.
# The staging/LOLBin checks still apply inside - an attacker task planted under
# \Microsoft\Windows\ flags on its command, not on the Hidden bit.
_HIDDEN_OK = ("\\microsoft\\", "\\googlesystem\\")


def _susp(name: str, t: dict) -> str:
    if t["hidden"] and not name.lower().startswith(_HIDDEN_OK):
        return "yes"
    for cmd in t["command"].split(" | "):
        if cmd and not cmd.startswith("COM:") and (_in_staging(cmd) or _is_lolbin(cmd)):
            return "yes"
    return ""


def run(ctx) -> None:
    tasks_dir = Path(ctx.evidence) / "Windows" / "System32" / "Tasks"
    if not tasks_dir.is_dir():
        raise HandlerSkip("no System32/Tasks store")

    rows: list[list] = []
    for f in sorted(tasks_dir.rglob("*")):
        if not f.is_file():
            continue
        try:
            t = _parse_task(f.read_bytes())
        except OSError:
            continue
        if t is None:
            continue
        name = "\\" + str(f.relative_to(tasks_dir)).replace("/", "\\")
        rows.append([name, t["author"], t["created"], t["runas"], t["runlevel"],
                     t["hidden"], t["disabled"], t["trigger"], t["command"],
                     _susp(name, t)])

    rows.sort(key=lambda r: (r[9] != "yes", r[0].lower()))
    write_csv(ctx.out, "tasks_disk.csv",
              ["task", "author", "created", "runas", "runlevel", "hidden",
               "disabled", "trigger", "command", "suspicious"], rows)
