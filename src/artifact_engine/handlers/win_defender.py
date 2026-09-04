r"""Handler: what Defender saw, and whether it did anything about it.
Output: defender_detections.csv

On a host with no Sysmon and no process-creation auditing, the Defender
Operational channel is often the ONLY surviving record of process execution. Its
1116/1117 events carry the offending command line in the detection path, prefixed
`CmdLine:_`, next to the account, the process and the action taken. An entire
intrusion chain -- connectivity check, download, credential access -- has been
recovered from nothing else, by decoding payload JSON by hand.

Until now this engine dumped the channel with EvtxECmd and stopped there, which
left three things out of reach.

THE COMMAND LINE. Defender's detection path is a list of RESOURCES, each with a
scheme: `file:_C:\...`, `process:_pid:...`, `amsi:_...`, `CmdLine:_...`. Read as a
path -- which is what a bare dump invites -- a script-block detection looks like a
file with a very strange name. Split on the scheme, and the same field is
execution evidence.

WHETHER IT WAS CLEANED. "Detected" and "removed" are different incidents, and the
event that says which is not the event that says what. Defender retries: the same
`detection_id` appears several times with different actions, and action 9 (no
action) beside action 2 or 3 (quarantine, remove) says which attempt in that
sequence actually cleaned it -- and, by omission, which one got through. So the
outcome is computed per detection_id and written on every row of it, and a
detection that was NEVER acted on is what gets flagged. That is the row worth
reading: Defender saw it and it ran anyway.

TAMPERING. 5001 and 5007 -- real-time protection off, settings changed -- are
first-class rows in the same table rather than a separate question, because they
are read together: a detection that stops at 5001 is not a quiet host.

The map fills some fields and not others (the action, the error code and the
remediation user are in the event and in none of the map's properties), so every
column is read from the mapped column first and from the raw payload after.
"""

from __future__ import annotations

import csv
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _evtx
from artifact_engine.handlers._lincommon import write_csv

_DEFENDER_CSV = Path("CSVs") / "EventLogs" / "evtx_defender.csv"

# Detections. 1116 = found, 1117 = action attempted, 1006/1007 their older twins,
# 1015 = suspicious behaviour, 1119/1120 = remediation failed outright.
_DETECTION = {"1116", "1117", "1006", "1007", "1015", "1119", "1120"}

# The protection itself changing state. Kept in the same table because they are
# read together with the detections around them.
_TAMPER = {
    "5001": "real-time protection DISABLED",
    "5004": "real-time protection configuration changed",
    "5007": "Defender configuration changed",
    "5010": "malware scanning DISABLED",
    "5012": "virus scanning DISABLED",
    "5101": "expired malware definitions",
    "1002": "scan stopped before it finished",
}

# Defender's action ids. 1/2/3/10 removed the threat; 6/9 left it in place.
_ACTIONS = {"1": "clean", "2": "quarantine", "3": "remove", "6": "allow",
            "8": "user defined", "9": "no action", "10": "block"}
_REMEDIATED = {"1", "2", "3", "10"}

_SEVERITY = {"1": "Low", "2": "Moderate", "4": "High", "5": "Severe"}

# Resource schemes in a detection path. Everything before `:_` names what the
# rest of the value IS, and reading the whole field as a path loses exactly the
# thing worth having.
_CMDLINE_SCHEMES = {"cmdline", "amsi", "script"}
_FILE_SCHEMES = {"file", "webfile", "containerfile", "internet"}

_COLUMNS = ["time_utc", "event_id", "kind", "detection_id", "threat_name",
            "severity", "category", "path", "command_line", "other_resources",
            "process_name", "detection_user", "detection_source", "action",
            "remediation_user", "error_code", "outcome", "suspicious"]


def split_resources(detection_path: str) -> tuple[str, str, str]:
    r"""(files, command lines, everything else) out of a Defender detection path.

    The field is `scheme:_value` joined by `;`, and a value can itself contain
    both -- `file:_C:\x.ps1; CmdLine:_powershell -enc ...`. A part with no scheme
    is treated as a path, which is what it was before Defender had schemes.
    """
    files, cmds, other = [], [], []
    for part in (detection_path or "").split(";"):
        piece = part.strip()
        if not piece:
            continue
        scheme, sep, value = piece.partition(":_")
        if not sep:
            files.append(piece)
            continue
        low, value = scheme.strip().lower(), value.strip()
        if low in _CMDLINE_SCHEMES:
            cmds.append(value)
        elif low in _FILE_SCHEMES:
            files.append(value)
        else:
            other.append(piece)
    return "; ".join(files), "; ".join(cmds), "; ".join(other)


def _describe(value: str) -> tuple[str, str]:
    """`"Description: Trojan:Win32/X (Severe)"` -> ("Trojan:Win32/X", "Severe")."""
    text = _evtx.after(value or "", "Description")
    if text.endswith(")") and "(" in text:
        head, _, tail = text.rpartition("(")
        return head.strip(), tail[:-1].strip()
    return text.strip(), ""


def action_of(row: dict, payload: str) -> str:
    """The action Defender took, as `<id> <name>` -- id and name each from
    wherever they exist, because a dump may carry one without the other."""
    aid = _evtx.payload_field(payload, "Action ID").strip()
    name = _evtx.payload_field(payload, "Action Name").strip()
    if not name and aid in _ACTIONS:
        name = _ACTIONS[aid]
    if not aid and name:
        aid = next((k for k, v in _ACTIONS.items() if v == name.lower()), "")
    return f"{aid} {name}".strip()


def _acted(action: str) -> bool:
    """Whether this action actually removed the threat rather than noting it."""
    head = (action or "").split(None, 1)[0] if action else ""
    if head in _REMEDIATED:
        return True
    return any(w in (action or "").lower() for w in ("quarantine", "remove", "clean", "block"))


def _rows_from(src: Path):
    """Every Defender row this handler has something to say about."""
    with src.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(line.replace("\x00", "") for line in fh):
            eid = (row.get("EventId") or "").strip()
            if eid in _DETECTION or eid in _TAMPER:
                yield eid, row


def _detection_row(eid: str, row: dict) -> list:
    payload = row.get("Payload") or ""
    detection_id = (_evtx.after(row.get("PayloadData5") or "", "Detection ID")
                    or _evtx.payload_field(payload, "Detection ID"))
    threat = (_evtx.after(row.get("PayloadData1") or "", "Malware name")
              or _evtx.payload_field(payload, "Threat Name"))
    category, severity = _describe(row.get("PayloadData2") or "")
    if not category:
        category = _evtx.payload_field(payload, "Category Name")
    if not severity:
        severity = (_evtx.payload_field(payload, "Severity Name")
                    or _SEVERITY.get(_evtx.payload_field(payload, "Severity ID"), ""))
    detection_path = ((row.get("ExecutableInfo") or "").strip()
                      or _evtx.payload_field(payload, "Path"))
    files, cmds, other = split_resources(detection_path)
    process = (_evtx.after(row.get("PayloadData4") or "",
                           "Process (if real-time detection)")
               or _evtx.payload_field(payload, "Process Name"))
    user = (_evtx.after(row.get("UserName") or "", "Detection User")
            or _evtx.payload_field(payload, "Detection User"))
    error = _evtx.payload_field(payload, "Error Code")
    return [(row.get("TimeCreated") or "").strip(), eid, "detection", detection_id,
            threat, severity, category, files, cmds, other, process, user,
            _evtx.payload_field(payload, "Source Name"), action_of(row, payload),
            _evtx.payload_field(payload, "Remediation User"), error, "", ""]


def _tamper_row(eid: str, row: dict) -> list:
    payload = row.get("Payload") or ""
    old = _evtx.after(row.get("PayloadData1") or "", "Old Value")
    new = _evtx.after(row.get("PayloadData2") or "", "New Value")
    detail = " -> ".join(x for x in (old, new) if x)
    return [(row.get("TimeCreated") or "").strip(), eid, "tamper", "",
            _TAMPER[eid], "", "", "", "", detail,
            _evtx.payload_field(payload, "Process Name"),
            _evtx.payload_field(payload, "User"), "", "", "", "", "", "yes"]


def run(ctx) -> None:
    src = Path(ctx.evidence) / _DEFENDER_CSV
    if not src.is_file():
        raise HandlerSkip("no evtx_defender.csv to read")

    rows: list[list] = []
    try:
        for eid, row in _rows_from(src):
            rows.append(_tamper_row(eid, row) if eid in _TAMPER
                        else _detection_row(eid, row))
    except (OSError, csv.Error) as e:
        raise HandlerSkip(f"evtx_defender.csv unreadable: {e}") from e
    if not rows:
        return                                # the channel exists and is quiet

    # Defender retries: the same detection_id appears several times with
    # different actions. The outcome is a property of the ATTEMPT, not of any one
    # event, so it is computed across the group and written on every row of it.
    acted: dict[str, bool] = {}
    for r in rows:
        did = r[3]
        if did and r[2] == "detection":
            acted[did] = acted.get(did, False) or _acted(r[13])

    for r in rows:
        if r[2] != "detection":
            continue
        did = r[3]
        if not did:
            r[16] = "remediated" if _acted(r[13]) else "unknown"
        else:
            r[16] = "remediated" if acted.get(did) else "NOT remediated"
        # The flag is the detection that was never acted on: Defender saw it and
        # it ran anyway. A quarantined threat is an incident that ended.
        if r[16] == "NOT remediated":
            r[17] = "yes"

    rows.sort(key=lambda r: (r[17] != "yes", r[0]))
    write_csv(ctx.out, "defender_detections.csv", _COLUMNS, rows)
