r"""Handler: third-party endpoint-security logs. Outputs: av_detections.csv, av_products.csv

On a managed estate the endpoint product is often the only thing that saw the
first stage, and it saw it AT THE TIME, with a name and a path. A detection at
T on file F is the cheapest pivot a case has. Until now every byte of it was
discarded: two dozen products' log directories arrive in the acquisition and
nothing read one.

TWO TABLES, BECAUSE THERE ARE TWO ANSWERS. `av_detections.csv` holds what was
read. `av_products.csv` holds what is THERE -- every product directory found,
its file count and its date window, whether a reader exists and how much of it
was read. The second table is the point of this parser as much as the first:
most of the products the acquisition collects have no reader here, and a run
that reported only the ones that do would read as a clean machine on a host
running any of the others. `report.txt` prints the gap, and distinguishes the
two ways a product can produce nothing -- no reader at all, and a reader that
ran and found nothing, which is a lead and not a gap.

WHY SO FEW READERS, DELIBERATELY. A half-parsed vendor log is worse than an
honest gap, because it looks like an answer. Each format here is read only as
far as it can be read without guessing. The list lives in
`assets/av_products.txt` and is the analyst's to extend -- a rebranded or OEM
product whose format matches an existing reader is one line, no code. A path on
that list is relative to the volume and stays inside it: an absolute path, which
is the natural shape to paste in from a vendor's documentation, would read the
ANALYST's own machine and file it under the subject's name.

WHAT A READER MAY NOT DO. It may not invent a column. Every row carries the raw
line in `detail`, and a line the layout check does not confirm degrades to its
timestamp plus that line, with the unresolved columns EMPTY -- never a guess at
which field was the threat name. `av_products.csv` counts those rows
(`raw_only`) per path, so a reader meeting a layout it does not know shows up as
a number instead of as wrong facts -- and the count is the READER's verdict on
the layout, not the emptiness of a cell: a format that confirmed its layout and
left the threat name blank because the log did is not a line this engine failed
to read.

A row must identify SOMETHING: a file, or a threat name the format itself
labelled as one. This is a detections table and not a log dump, so a line with
neither is dropped -- in McAfee's and Symantec's logs nothing labels a threat
name, so there a record naming no file is no row at all. The on-demand scanners
do label theirs, and `Backdoor:Win32/Example found, could not be removed` with
no path is still the most useful sentence in the acquisition.

TIME. These products write the HOST's local time with no offset in it, so the
column is `time_local` (ARCHITECTURE §5), never `time_utc`. McAfee's date is
carried VERBATIM: `10/12/2021` is October or December depending on the machine's
locale and nothing in the file says which, so normalising it would invent a
day/month order. Symantec's hex timestamp is unambiguous and is rendered ISO.
`time_kind` says what the time IS -- `event` for a per-detection time, and
`scan_start` where the product logs only when the scan began (the on-demand
scanners), because a scan start placed on a timeline as an event time is a
wrong timeline.

FLAG. `suspicious` is not "a detection happened" -- that is every row, and a
column that fires on every row separates nothing. It marks the rows where the
PRODUCT ITSELF said the file is still there: left alone, access denied, delete
failed, would have been blocked, pending restart. It is read from the action
field only, never from the raw line, where those words mean nothing. Symantec's
numeric action codes are left as `code:<n>` and never translated, so no row of
its is flagged -- the engine does not know that vocabulary and does not pretend
to.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.handlers._lincommon import write_csv

ASSET = "av_products.txt"

DETECTION_HEADER = ["product", "time_local", "time_kind", "threat_name", "path",
                    "action", "user", "source_file", "detail", "suspicious"]
PRODUCT_HEADER = ["product", "path", "files", "bytes", "first_modified_utc",
                  "last_modified_utc", "reader", "files_read", "rows", "raw_only"]

# A Windows path, and a DOMAIN\user that is not one.
_PATHISH = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")
_USERISH = re.compile(r"^[^\\/:*?\"<>|]{1,64}\\[^\\/:*?\"<>|]{1,64}$")

# What a product says when the file is STILL THERE.
_NOT_REMOVED = re.compile(
    r"left\s+alone|no\s+action|not\s+(?:removed|cleaned|deleted|quarantined|repaired)"
    r"|could\s+not\s+(?:be\s+)?(?:remove|clean|delete|quarantine|repair)"
    r"|(?:remove|clean|delete|quarantine|repair)\s+(?:has\s+)?fail"
    r"|fail(?:ed|ure)\s+to\s+(?:remove|clean|delete|quarantine|repair)"
    r"|access\s+denied|would\s+(?:have\s+been|be)\s|pending\s+(?:reboot|restart)"
    r"|\ballowed\b|\bpermitted\b|\bskipped\b|\bignored\b", re.IGNORECASE)

_BOMS = ((b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"), (b"\xef\xbb\xbf", "utf-8-sig"))


def _flat(text: str) -> str:
    """One line and one space between things: `detail` is a CSV cell, and these
    logs carry tabs and runs of padding that would make it unreadable."""
    return re.sub(r"\s+", " ", text.replace("\r", " ").replace("\n", " ")).strip()


def _text(path: Path) -> str:
    """Decode a vendor log. Several are UTF-16 -- McAfee's scan logs are -- so the
    encoding comes from the BOM, and from the NUL density when there is no BOM,
    rather than being assumed. Read as UTF-8, a UTF-16 log yields text nothing
    matches, which is a silent empty table."""
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    for bom, enc in _BOMS:
        if raw.startswith(bom):
            return raw.decode(enc, errors="replace")
    if raw[:64].count(0) > 8:
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _flag(action: str) -> str:
    return "yes" if action and _NOT_REMOVED.search(action) else ""


def _fields(rest: str) -> list[str]:
    """Split a log line's body. Tabs where there are tabs; runs of two or more
    spaces otherwise, never a single space -- a threat name and a command line
    both hold single spaces, and splitting on one would shred both."""
    parts = rest.split("\t") if "\t" in rest else re.split(r"\s{2,}", rest)
    return [p.strip() for p in parts if p.strip()]


# --- McAfee ---------------------------------------------------------------
# The host's own date and time, in the host's locale order, then the body.
_MC_LINE = re.compile(
    r"^\s*(\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4})\s+"
    r"(\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s*[AaPp]\.?[Mm]\.?)?)\s+(\S.*)$")


def _mcafee(text: str):
    """VirusScan Enterprise and Endpoint Security activity logs. The documented
    VSE body is <action> <user> <path> <threat> [<type>]; it is trusted only
    where the field AFTER the located path is not itself a path, which is the
    check on the whole layout. Endpoint Security's body is a different shape and
    degrades to its action and its raw line, as intended."""
    for raw in text.splitlines():
        m = _MC_LINE.match(raw)
        if not m:
            continue
        date, clock, rest = m.group(1), m.group(2), m.group(3)
        fields = _fields(rest)
        path = next((f for f in fields if _PATHISH.match(f)), "")
        if not path:
            continue                       # names no file: not a detection row
        user = next((f for f in fields
                     if _USERISH.match(f) and not _PATHISH.match(f)), "")
        threat = ""
        i = fields.index(path)
        if i + 1 < len(fields) and not _PATHISH.match(fields[i + 1]):
            cand = fields[i + 1]
            if cand != user:
                threat = cand
        action = fields[0] if fields[0] not in (path, user) else ""
        # The layout verdict is this reader's, not an inference from an empty
        # cell: VSE puts the threat name after the path, so not finding one
        # there means this is a layout the reader does not know.
        yield [f"{date} {clock}", "event", threat, path, action, user,
               _flat(raw), _flag(action), "ok" if threat else "raw"]


# --- Symantec Endpoint Protection ----------------------------------------
_SEP_TIME = re.compile(r"^[0-9A-Fa-f]{12}$")
# time, event, category, logger, computer, user, virus, file, wanted1, wanted2,
# real action, ... -- the first eleven are stable across versions; later ones
# were appended, which is why nothing past index 10 is read.
_SEP_USER, _SEP_VIRUS, _SEP_FILE, _SEP_ACTION = 5, 6, 7, 10


def _sep_time(hex12: str) -> str:
    """Six hex bytes: year-1970, month (0-11), day, hour, minute, second, in the
    client's local time. Returns "" when any field is out of range, which is
    this row's layout check -- a wrong theory about the format shows up as rows
    that are skipped, not as wrong timestamps."""
    b = [int(hex12[i:i + 2], 16) for i in range(0, 12, 2)]
    try:
        # Naive on purpose: the product wrote a wall clock with no offset in it,
        # and attaching a timezone here would be this engine inventing one.
        return datetime(b[0] + 1970, b[1] + 1, b[2], b[3], b[4],      # noqa: DTZ001
                        b[5]).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ""


def _symantec(text: str):
    """The client's AV logs. A row is trusted field-by-field only when the file
    column holds something path-shaped; otherwise the path is located by shape
    and the threat name is left empty rather than taken from a column that may
    not be the one."""
    for raw in text.splitlines():
        parts = [p.strip() for p in raw.split(",")]
        if len(parts) < 8 or not _SEP_TIME.match(parts[0]):
            continue
        when = _sep_time(parts[0])
        if not when:
            continue
        if _PATHISH.match(parts[_SEP_FILE]):
            path, threat = parts[_SEP_FILE], parts[_SEP_VIRUS]
            user = parts[_SEP_USER] if not _PATHISH.match(parts[_SEP_USER]) else ""
            act = parts[_SEP_ACTION] if len(parts) > _SEP_ACTION else ""
            # Never translated: the engine does not know this vocabulary, and a
            # guessed word in `action` would be read as the product's own.
            action = f"code:{act}" if act.isdigit() else act
            # The layout IS confirmed here, whatever the virus column holds: an
            # empty one is the log's own blank, not a line this reader failed on.
            layout = "ok"
        else:
            path = next((p for p in parts if _PATHISH.match(p)), "")
            if not path:
                continue
            threat, user, action, layout = "", "", "", "raw"
        yield [when, "event", threat, path, action, user, _flat(raw),
               _flag(action), layout]


# --- Microsoft Safety Scanner --------------------------------------------
# An operator-run on-demand scanner: whoever touched the host before the
# acquisition may have left its log behind, and it names what it found.
_MS_START = re.compile(r"^\s*start(?:ed)?\s+on\s+(\S.*?)\s*$", re.IGNORECASE)
_MS_THREAT = re.compile(r"^\s*threat(?:\s+detected)?\s*[:=]\s*(\S.*?)\s*$", re.IGNORECASE)
#   `file://` FIRST: `file\s*[:=]` matches the `file:` of `file://C:\...` too,
#   and the wrong order leaves the two slashes on the front of every path.
_MS_FILE = re.compile(r"^\s*(?:file://|file\s*[:=]\s*)(\S.*?)\s*$", re.IGNORECASE)
#   The summary line names the threat in Microsoft's own nomenclature
#   (`Type:Platform/Name`), and the shape is required: without it `Found no
#   infections` is a threat called `no` and `Found 2 threats.` one called `2`.
_MS_FOUND = re.compile(
    r"^\s*found\s+([A-Za-z][\w.\-]*:[\w.\-]+/[^\s,]+)\s+(\S.*?)\s*$",
    re.IGNORECASE)


def _msert(text: str):
    """`msert.log`. The file logs one start time for the whole scan and no
    per-detection time, so every row says `scan_start` -- that is what the
    timestamp is, and calling it an event time would put the scanner's clock on
    the attacker's timeline."""
    started, pending = "", ""
    order: list[str] = []
    # Every file per threat, not one: a single threat name across three files is
    # the ordinary mass-infection case, and keying by the name alone kept the
    # last path and dropped the other two with nothing counting them.
    files: dict[str, list[str]] = {}
    verdict: dict[str, tuple[str, str]] = {}

    def seen(name: str) -> None:
        if name not in files:
            files[name] = []
            order.append(name)

    for raw in text.splitlines():
        m = _MS_START.match(raw)
        if m and not started:
            started = m.group(1)
            continue
        m = _MS_THREAT.match(raw)
        if m:
            pending = m.group(1)
            seen(pending)
            continue
        m = _MS_FILE.match(raw)
        if m and pending:
            if m.group(1) not in files[pending]:
                files[pending].append(m.group(1))
            continue
        m = _MS_FOUND.match(raw)
        if m:
            seen(m.group(1))
            verdict[m.group(1)] = (m.group(2), _flat(raw))
    for name in order:
        action, line = verdict.get(name, ("", f"Threat: {name}"))
        # `or [""]`: a summary entry with no file is still a threat the scanner
        # named and said it could not remove, which is a row (see the module
        # docstring on what a row must identify).
        for path in files[name] or [""]:
            yield [started, "scan_start", name, path, action, "",
                   line, _flag(action), "ok"]


# (filename filter, reader). The filter is why a quarantine directory's files
# are counted and not opened: they are samples, not logs.
_READERS = {
    "mcafee": (re.compile(r"\.(?:txt|log)$", re.IGNORECASE), _mcafee),
    "symantec": (re.compile(r"\.log$", re.IGNORECASE), _symantec),
    "msert": (re.compile(r"\.log$", re.IGNORECASE), _msert),
}


def contained(pattern: str) -> bool:
    """Does this pattern stay inside the volume it is matched against?

    A drive letter or a leading slash makes `evidence / pattern` the absolute
    path itself, which exists on the EXAMINER's machine and would be read, and
    reported, as the subject's. `..` walks out of the volume into another
    machine's output. Both are rejected rather than sanitised: a line the
    analyst meant as a path on this volume is one they can write correctly, and
    silently rewriting it would read something they did not ask for."""
    pat = pattern.replace("\\", "/")
    if pat.startswith("/") or re.match(r"^[A-Za-z]:", pat):
        return False
    return ".." not in pat.split("/")


def load_products(path: Path,
                  log=None) -> list[tuple[str, str, list[str]]]:
    """(product, reader, paths) per line of `av_products.txt` ([] if absent).

    A path that would leave the volume is dropped and named in the log -- never
    silently, because the analyst added it to be read."""
    out: list[tuple[str, str, list[str]]] = []
    if not path.is_file():
        return out
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        parts = [p.strip() for p in s.split("|")]
        if len(parts) < 3 or not parts[0]:
            continue
        reader = parts[1] if parts[1] in _READERS else ""
        paths = []
        for p in parts[2:]:
            if not p:
                continue
            if not contained(p):
                if log is not None:
                    log.warning(f"[!] {path.name}: {parts[0]}: path leaves the "
                                f"volume, not read: {p}")
                continue
            paths.append(p)
        if paths:
            out.append((parts[0], reader, paths))
    return out


def _expand(evidence: Path, pattern: str) -> list[Path]:
    """Existing paths matching one asset-file pattern. `%user%` is every profile.

    Checked again here, after `load_products`: this is the function that turns a
    string into a read, so the check belongs where the read happens as well as
    where the list is parsed. It has to come BEFORE the glob -- `glob` raises
    `NotImplementedError`, not an OSError, on an absolute pattern, and catching
    that afterwards would mean the read off the wrong machine was attempted. The
    exception is caught too, as insurance for a caller that skips `contained`."""
    if not contained(pattern):
        return []
    pat = pattern.replace("%user%", "*")
    if any(ch in pat for ch in "*?["):
        try:
            return sorted(evidence.glob(pat))
        except (OSError, ValueError, NotImplementedError):
            return []
    p = evidence / pat
    return [p] if p.exists() else []


def _files(base: Path) -> list[Path]:
    if base.is_file():
        return [base]
    try:
        return sorted(p for p in base.rglob("*") if p.is_file())
    except OSError:
        return []


def _utc(stamp: float) -> str:
    return datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def survey(evidence: Path, products: list[tuple[str, str, list[str]]]):
    """Yield (product, reader, base, files) for every product path on this volume."""
    for name, reader, patterns in products:
        for pattern in patterns:
            for base in _expand(evidence, pattern):
                yield name, reader, base, _files(base)


def run(ctx) -> None:
    evidence = Path(ctx.evidence)
    products = load_products(Path(ctx.assets) / ASSET, ctx.log)
    detections: list[list] = []
    inventory: list[list] = []
    for name, reader, base, files in survey(evidence, products):
        stamps, size = [], 0
        for f in files:
            try:
                st = f.stat()
            except OSError:
                continue
            stamps.append(st.st_mtime)
            size += st.st_size
        read = rows = raw_only = 0
        if reader:
            pattern, parse = _READERS[reader]
            for f in files:
                if not pattern.search(f.name):
                    continue
                read += 1
                for row in parse(_text(f)):
                    # row: time_local, time_kind, threat, path, action, user,
                    #      detail, suspicious, and the reader's layout verdict,
                    #      which is counted and not written to the CSV
                    detections.append([name, *row[:6], f.name, *row[6:8]])
                    rows += 1
                    if row[8] == "raw":
                        raw_only += 1
        inventory.append([
            name, base.relative_to(evidence).as_posix(), len(files), size,
            _utc(min(stamps)) if stamps else "", _utc(max(stamps)) if stamps else "",
            reader, read, rows, raw_only])
    write_csv(ctx.out, "av_detections.csv", DETECTION_HEADER, detections)
    write_csv(ctx.out, "av_products.csv", PRODUCT_HEADER, inventory)
