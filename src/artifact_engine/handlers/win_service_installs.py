r"""Handler: services installed, and the ones that were a remote shell.
Output: service_installs.csv

Event 7045 records every service installed on the host, and the Service Control
Manager writes it whether the service was a printer driver or a beachhead. Nothing
in this engine read it: `evtx_system.csv` carried the events and `reg_services.csv`
carried what survived, and neither was ever asked the question that joins them.

THE SIGNATURE THIS EXISTS FOR. Remote execution over SMB -- PsExec, and every
impacket-derived tool after it -- works by installing a service whose image is a
command shell, running it, and deleting it. What lands in 7045 is a burst of
services with random names running

    cmd.exe /c <temp>\<random>.bat > <temp>\<same>.txt 2>&1

under LocalSystem, none of which exist in the registry afterwards. Each half of
that is ordinary on its own; together they are the mechanism, and it took reading
event dumps by hand to find nine days of presence that the first pass missed.

FOUR THINGS ARE ASKED OF EVERY SERVICE, and they are independent:

- IS THE IMAGE A SHELL? A service whose ImagePath starts with cmd, powershell or
  %COMSPEC% is not a service, it is a way to run a command as SYSTEM. This is the
  strongest single indicator here and it needs no list.
- DOES IT REDIRECT ITS OUTPUT? `> \\...\\pipe` or `> %TEMP%\\x.txt 2>&1` is how the
  caller reads the result back. Legitimate services do not.
- DOES THE NAME LOOK GENERATED? Eight random uppercase letters, or a bare hex
  string, is what a tool picks when it has to pick something.
- DID IT SURVIVE? A service installed and then absent from the registry ran and
  was removed. On its own that is also what an uninstall looks like; next to any
  of the above it is the deletion at the end of the technique.

Then, only if `aeng update` has fetched them, the awesome-lists service names are
matched too -- which adds the tool's NAME to a row the structural checks already
found, and catches the named tools that use a fixed service name. The list is
enrichment: without it this handler loses attribution, not detections.

`greyware` matches (PDQ, the RMM agents) are reported and NOT flagged. On a
managed estate they fire constantly, and a detector that flags the deployment
tool is a detector that gets turned off.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _awesome, _evtx
from artifact_engine.handlers._lincommon import write_csv

_SYSTEM_CSV = Path("CSVs") / "EventLogs" / "evtx_system.csv"
_SERVICES_CSV = Path("CSVs") / "Registry" / "reg_services.csv"

_SERVICES_LIST = "suspicious_windows_services_names_list.csv"

_EVENT_ID = "7045"

# Interpreters. A service whose image is one of these is not a service, it is a
# way to run a command as SYSTEM. Compared against the BASENAME of the executable
# rather than searched for in the path: `\Program Files\Vendor\cmdmon.exe` is a
# real product, and a substring match would put it at the top of the table on
# every host that runs one.
_SHELL_NAMES = {"cmd", "%comspec%", "comspec", "powershell", "pwsh", "wscript",
                "cscript", "mshta", "rundll32", "regsvr32"}

# Output handed back to whoever asked -- a temp file or a named pipe.
_REDIRECT = re.compile(r"(?:\d?>{1,2}\s*\S|2>&1|\\\\\.\\pipe\\)", re.IGNORECASE)

# What a tool picks when it has to pick a name: impacket's eight random uppercase
# letters, or a bare hex blob.
_GENERATED = (
    ("random_uppercase", re.compile(r"^[A-Z]{6,12}$")),
    ("hex_name", re.compile(r"^[0-9a-fA-F]{8,}$")),
    ("guid_name", re.compile(r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-")),
)

# Writable locations an image path has no business being in.
_WRITABLE = ("\\temp\\", "\\tmp\\", "\\windows\\temp\\", "\\users\\public\\",
             "\\downloads\\", "\\appdata\\", "\\programdata\\", "\\perflogs\\",
             "\\$recycle.bin\\", "\\admin$\\", "\\c$\\")

# Service accounts that give the image SYSTEM rights.
_SYSTEM_ACCOUNTS = {"localsystem", "nt authority\\system", "system", ""}

_COLUMNS = ["time_utc", "service_name", "image_path", "account", "start_type",
            "in_registry", "indicators", "tool", "tool_category", "list_severity",
            "reference", "suspicious"]


def image_binary(image: str) -> str:
    """The executable an ImagePath runs: lower-cased basename, no extension.

    An ImagePath is a command line, so the executable is its first token -- in
    quotes when the path has spaces, and sometimes an environment variable that
    IS the interpreter (`%COMSPEC% /Q /c ...`) with no path at all.
    """
    text = (image or "").strip()
    if not text:
        return ""
    head = text[1:].split('"', 1)[0] if text.startswith('"') else text.split(None, 1)[0]
    name = head.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]
    return name[:-4].lower() if name.lower().endswith(".exe") else name.lower()


def is_shell(image: str) -> bool:
    return image_binary(image) in _SHELL_NAMES


def name_shape(name: str) -> str:
    """What a service NAME looks like, or "" when it looks like a product."""
    stripped = (name or "").strip()
    for label, pattern in _GENERATED:
        if pattern.match(stripped):
            return label
    return ""


def in_writable(image: str) -> bool:
    low = (image or "").lower().replace("/", "\\")
    return any(tok in low for tok in _WRITABLE)


def indicators_for(name: str, image: str, account: str) -> list[str]:
    """Every structural reason this service is worth a second look."""
    found = []
    if is_shell(image):
        found.append("image_is_a_shell")
    if _REDIRECT.search(image or ""):
        found.append("output_redirected")
    shape = name_shape(name)
    if shape:
        found.append(shape)
    if in_writable(image):
        found.append("image_in_writable_dir")
    if found and (account or "").strip().lower() in _SYSTEM_ACCOUNTS:
        found.append("runs_as_system")
    return found


def _registry_services(base: Path) -> set[str]:
    """Service names present in the SYSTEM hive, lower-cased.

    RECmd's batch output is one row per VALUE, so the service name is the last
    component of `ControlSet00N\\Services\\<name>` and appears many times over.
    """
    path = base / _SERVICES_CSV
    if not path.is_file():
        return set()
    out: set[str] = set()
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            for row in csv.DictReader(fh):
                key = (row.get("KeyPath") or "").replace("/", "\\").strip("\\")
                if "\\services\\" not in key.lower():
                    continue
                tail = key.split("\\")
                idx = [i for i, p in enumerate(tail) if p.lower() == "services"]
                if idx and idx[-1] + 1 < len(tail):
                    out.add(tail[idx[-1] + 1].lower())
    except (OSError, csv.Error):
        return out
    return out


def _installs(path: Path):
    """Yield (time, name, image, account, start_type) for every 7045."""
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        reader = csv.DictReader(line.replace("\x00", "") for line in fh)
        for row in reader:
            if (row.get("EventId") or "").strip() != _EVENT_ID:
                continue
            payload = row.get("Payload") or ""
            name = (_evtx.after(row.get("PayloadData1") or "", "Name")
                    or _evtx.payload_field(payload, "ServiceName"))
            image = ((row.get("ExecutableInfo") or "").strip()
                     or _evtx.payload_field(payload, "ImagePath"))
            start = (_evtx.after(row.get("PayloadData2") or "", "StartType")
                     or _evtx.payload_field(payload, "StartType"))
            account = (_evtx.after(row.get("PayloadData3") or "", "Account")
                       or _evtx.payload_field(payload, "AccountName"))
            yield (row.get("TimeCreated") or "").strip(), name, image, account, start


def run(ctx) -> None:
    base = Path(ctx.evidence)
    src = base / _SYSTEM_CSV
    if not src.is_file():
        raise HandlerSkip("no evtx_system.csv to read")

    known = _registry_services(base)
    listed = _awesome.load(Path(ctx.assets), _SERVICES_LIST,
                           key="service_name", extra_key="service_path")

    rows: list[list] = []
    try:
        stream = _installs(src)
        for when, name, image, account, start in stream:
            if not name and not image:
                continue
            found = indicators_for(name, image, account)
            # `in_registry` is only interesting next to something else: an
            # ordinary uninstall removes a service too, and saying "gone" about
            # every retired printer driver would bury the burst that matters.
            survived = (name or "").strip().lower() in known if known else None
            if found and survived is False:
                found.append("not_in_registry")

            hit = _awesome.match(listed, name)
            if hit is None and image:
                hit = _awesome.match(listed, image)
            if hit is not None:
                found.append("on_threat_list" if hit.offensive else "known_greyware")

            if not found:
                continue
            flagged = ("image_is_a_shell" in found
                       or (hit is not None and hit.offensive)
                       or len(found) >= 3)
            rows.append([
                when, name, image, account, start,
                # "Unknown" and "gone" are different answers, and writing `no`
                # for the first would invent the strongest half of the signature
                # on every host with no hive. Three-valued, and not `suspicious`:
                "" if survived is None else ("yes" if survived else "no"),
                " ".join(found),
                hit.tool if hit else "", hit.category if hit else "",
                hit.severity if hit else "", hit.reference if hit else "",
                "yes" if flagged else "",
            ])
    except (OSError, csv.Error) as e:
        raise HandlerSkip(f"evtx_system.csv unreadable: {e}") from e

    rows.sort(key=lambda r: (r[-1] != "yes", r[0]))
    write_csv(ctx.out, "service_installs.csv", _COLUMNS, rows)
