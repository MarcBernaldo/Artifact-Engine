"""Phase 0 - Integrity: SHA256 of the original files before extraction.

Generates the chain of custody (human-readable traces.txt + machine traces.csv).
Runs BEFORE touching anything and is idempotent (not regenerated if it exists).
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine import __version__
from artifact_engine.core.extractor import DROP_DIR, FAILED_NOTE, MARKER
from artifact_engine.core.memory import POINTER as MEMORY_POINTER
from artifact_engine.logging_setup import get_logger

log = get_logger()

TRACES_TXT = "traces.txt"
TRACES_CSV = "traces.csv"

# Files/folders produced by the tool itself: never "originals"
_OUTPUT_NAMES = {TRACES_TXT, TRACES_CSV, "aeng-run.log", FAILED_NOTE}
_UNIT_OUTPUT_EXTS = {"db", "xlsx", "db-journal", "db-wal", "db-shm"}
# Written by the engine at the CASE ROOT after phase 0 (report.build_run_summary,
# consolidate.STALE_LIST, lateral.build, casedb.build), so the next run used to
# record them as "new originals" (v0.7.124). Only at the root: an evidence file of
# the same name anywhere below it is still hashed. case.db and the temporary file
# it is written through (a run killed while writing it leaves one), and case.html
# (casepage.write) the same way, since v0.7.200.
_ROOT_OUTPUT_NAMES = {"run-summary.json", "run-summary.txt", "stale-outputs.txt",
                      "lateral_movement.csv", "lateral_movement.html",
                      "case.db", "case.db.tmp", "case.html", "case.html.tmp"}
_OUTPUT_DIRS = {"CSVs", "JSONs", "TXTs"}


def _run_json_machine(path: Path) -> str | None:
    """The machine an engine `run.json` names; None for anything else."""
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    name = d.get("machine") if isinstance(d, dict) and "runs" in d else None
    if not isinstance(name, str) or not name or "/" in name or "\\" in name:
        return None
    return name


_VSS_SUFFIX = re.compile(r"_VSS\d+$", re.IGNORECASE)     # as consolidate's


def root_machine_outputs(root: Path) -> set[str]:
    """What the engine writes AT the case root for a unit rooted there, by name,
    lower-cased (v0.7.132). Two layouts put a unit's outputs at the root:

    - a machine detected AT the root (`-p` pointed at one collection, a
      LiveResponse-only root): its `run.json` is at the root;
    - a live volume merged with its snapshots (`merge_vss`) whose folders sit
      directly under the root (`<root>/C`, `<root>/VSS1`): the unit lives in
      their parent, named after the live machine, and each volume's `run.json`
      is one level down.

    Read from those `run.json` files -- the first thing the engine writes for a
    machine, at the end of parsing -- so it holds on the first run after an
    upgrade and after a run that died before consolidating. A root with neither
    excludes nothing: the names are derived, never guessed.

    Two limits, said rather than hidden. An evidence file delivered at such a
    root under one of these names is skipped too: that root is the unit's output
    folder, where the engine writes and overwrites these names. And the outputs
    a unit wrote under an EARLIER name (the case folder renamed, a drop renamed
    after a new majority host) are recorded once, as they were before."""
    units: set[str] = set()
    name = _run_json_machine(root / "run.json")
    if name:
        units.add(name)
    by_host: dict[str, list[str]] = {}
    try:
        subs = [d for d in root.iterdir() if d.is_dir()]
    except OSError:
        subs = []
    for d in subs:
        n = _run_json_machine(d / "run.json")
        if n:
            by_host.setdefault(_VSS_SUFFIX.sub("", n).lower(), []).append(n)
    for members in by_host.values():
        live = [n for n in members if not _VSS_SUFFIX.search(n)]
        if live and len(members) > len(live):          # a live volume and a snapshot
            units.update(live)
    if not units:
        return set()
    # report.build, findings.FINDINGS_CSV, scheduler._write_manifest,
    # consolidate.Unit.output / _marker / the merge's scratch .db, and the side
    # files SQLite and Excel keep beside an open .db/.xlsx
    out = {"run.json", "report.txt", "findings.csv"}
    # lin_web_metrics writes its panel in the MACHINE's folder, which is the root
    # only for a machine detected there -- not for a merged unit, whose volumes
    # keep theirs one level down (v0.7.189).
    if name:
        out.add("web_metrics.html")
    for n in units:
        out |= {f".{n}.consolidated", f".{n}.aeng-merge.db", f"~${n}.xlsx",
                *(f"{n}.{ext}" for ext in _UNIT_OUTPUT_EXTS)}
    return {x.lower() for x in out}


_BUF = 1024 * 1024  # 1 MiB


@dataclass
class TraceEntry:
    rel_path: str
    size: int
    sha256: str
    mtime: str
    # Why this original was NOT hashed (AE-104): a file that could not be read, or
    # a directory that could not be listed. Written into traces.txt and not into
    # traces.csv, so the next run tries it again; it makes the run incomplete.
    error: str = ""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_BUF), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_original_files(root: Path, include_drops: bool = True,
                         unlisted: list[OSError] | None = None):
    """Every file whose custody this case has to record.

    WHAT IS NOT ONE, and was. On the first run this phase happens before phase 1,
    so the case root holds the acquisitions and nothing else -- which is the whole
    premise in the module docstring above. On the SECOND run the extracted trees
    are sitting there too, and a plain walk called every one of their files an
    original: measured on a real case, 21 recorded acquisitions became 120,029
    "new originals" on the next run, ~50 GB re-hashed, and a custody record whose
    21 meaningful rows were buried under a hundred thousand derived ones.

    They are not originals by any reading: every one of them came out of an
    archive that IS recorded here, byte for byte, under a hash that covers them
    all. So an extraction destination is pruned, identified by the marker phase 1
    writes into it, or by the note it writes before the first member and removes
    only once the marker is there (AE-103) -- which also means nothing is pruned on
    the first run, when neither exists yet and the premise holds on its own.
    """
    def excluded(path) -> bool:
        # A drop folder's contents, when the configuration keeps them out of
        # custody: one that cannot be listed is not a gap in the record either
        # (found by review).
        try:
            first = Path(path).relative_to(root).parts[:1]
        except (TypeError, ValueError):
            return False
        return not include_drops and bool(first) and bool(DROP_DIR.fullmatch(first[0]))

    def not_listed(e: OSError) -> None:
        if unlisted is not None and not excluded(e.filename):
            unlisted.append(e)

    def engines(d: Path) -> bool:
        try:
            return ((d / MARKER).is_file()
                    # a FAILED extraction never gets the marker; what it left
                    # came out of the recorded archive all the same (v0.7.128)
                    or (d / FAILED_NOTE).is_file()
                    # a memory unit holds a pointer and outputs; the image it
                    # points at is beside it and recorded there (v0.7.88)
                    or (d / MEMORY_POINTER).is_file())
        except OSError as e:
            # A folder that cannot be listed can still answer for a name that is
            # there by raising: said like any other, not raised (found by review).
            not_listed(OSError(e.errno, e.strerror, str(d)))
            return True

    # A directory that cannot be listed was skipped by `os.walk` without a line
    # (AE-104): its files were neither hashed nor said to be missing.
    for dirpath, dirnames, filenames in os.walk(root, onerror=not_listed):
        here = Path(dirpath)
        rel = here.relative_to(root).parts
        # Pruned rather than filtered per file: an extracted acquisition is
        # millions of paths, and not descending into it is the point.
        dirnames[:] = [d for d in dirnames
                       if d not in _OUTPUT_DIRS and not engines(here / d)]
        for name in filenames:
            if name in _OUTPUT_NAMES or (not rel and name in _ROOT_OUTPUT_NAMES):
                continue
            # A memory unit's .db/.xlsx lie beside its folder, named after it
            # (v0.7.89): rebuilt by every run, they are never an original.
            # Excel's owner file (`~$X.xlsx`) and SQLite's journals are the same
            # outputs' side files, present only while one is open.
            stem, dot, ext = name.removeprefix("~$").rpartition(".")
            if (dot and ext.lower() in _UNIT_OUTPUT_EXTS
                    and (here / stem / MEMORY_POINTER).is_file()):
                continue
            # Optionally skip the contents of a loose-drop folder
            # (weblogs*/fortigate*/evtx*) at the case root: often thousands of
            # rotated logs whose custody is not always required. Only the FIRST
            # path component is checked, so a real acquisition that merely
            # contains a var/log/... path is never affected.
            if not include_drops and DROP_DIR.fullmatch(rel[0] if rel else name):
                continue
            p = here / name
            if p.is_file():
                yield p


def fmt_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == units[-1]:
            return f"{f:.1f} {u}" if u != "B" else f"{int(f)} B"
        f /= 1024
    return f"{n} B"


class CustodyError(Exception):
    """The custody record is there and its index cannot be used: nothing is written,
    and the run does not start (v0.7.201, AE-100)."""


def _recorded_paths(csv_path: Path) -> set[str]:
    """rel_paths already in traces.csv -- the machine-readable custody index.

    An index that is there and cannot be read is an error, not an empty set. Read
    as empty, it made the run hash every original again and open both files with
    "w", so the record of every earlier delivery was gone (AE-100). That is what a
    spreadsheet re-saving the csv with another separator did, with no exception at
    all: the header no longer held `rel_path`. A BOM in front of it is accepted."""
    if not csv_path.is_file():
        return set()
    try:
        with open(csv_path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                raise CustodyError(f"{TRACES_CSV} is empty or has no header")
            if "rel_path" not in reader.fieldnames:
                raise CustodyError(f"{TRACES_CSV} has no rel_path column (header: "
                                   f"{','.join(reader.fieldnames)[:80]!r})")
            return {row["rel_path"] for row in reader if row.get("rel_path")}
    except (OSError, ValueError, csv.Error) as e:
        raise CustodyError(f"{TRACES_CSV} cannot be read: {type(e).__name__}: {e}") from e


def generate_traces(root: Path, max_workers: int = 4, operator: str = "",
                    include_drops: bool = True,
                    hold: set[Path] | frozenset[Path] = frozenset(),
                    hashed: dict[Path, str] | None = None) -> list[TraceEntry]:
    """Hash originals under `root` that are not recorded yet; append them.

    Append-only, never regenerate. The earlier behaviour skipped the whole phase
    once traces.txt existed, which is right for evidence already recorded and
    wrong for everything that arrives later: a second delivery got extracted and
    parsed while the custody record kept claiming to describe the case. An
    incomplete record that does not say it is incomplete is worse than none.

    So each run hashes only what is new and appends it as its OWN dated section,
    because those files were received and hashed at a different moment and the
    record should show that. Lines already written are never touched -- rewriting
    a chain-of-custody document is exactly what the original guard was protecting
    against, and that protection is kept.

    `include_drops=False` skips the files inside loose-drop folders
    (weblogs*/fortigate*/evtx*); the containers delivered at the case root are still
    hashed either way (Phase 0 runs before extraction, so a dropped `.zip` is
    hashed as the one delivered artifact regardless of this flag).

    `hold` is what has not finished arriving (`core/arrival.py`) and is not recorded
    this run: append-only means a file hashed mid-copy would stay here under the
    hash of a truncated file. `hashed` carries SHA-256s already computed this run --
    a sealed archive is read whole to check its seal -- so it is not read twice."""
    txt_path = root / TRACES_TXT
    csv_path = root / TRACES_CSV
    # The record and its index stand or fall together: a record whose index is
    # gone, or unusable, is never started again over the top of it.
    how = ("Nothing was written. Restore it from a copy, or move traces.txt and "
           "traces.csv out of the case root to start a new record on purpose.")
    try:
        known = _recorded_paths(csv_path)
    except CustodyError as e:
        raise CustodyError(f"{e}. {how}") from None
    if not csv_path.is_file() and txt_path.is_file() and txt_path.stat().st_size > 0:
        raise CustodyError(f"{TRACES_TXT} is there but {TRACES_CSV}, its index, is not. {how}")
    ours = root_machine_outputs(root)         # the engine's own, at the root only
    held = {str(Path(p).relative_to(root)) for p in hold if Path(p).is_relative_to(root)}
    pre = {str(Path(p).relative_to(root)): h for p, h in (hashed or {}).items()
           if Path(p).is_relative_to(root)}

    unlisted: list[OSError] = []
    files = list(_iter_original_files(root, include_drops=include_drops, unlisted=unlisted))
    not_listed = [TraceEntry(rel_path=_rel_of(e.filename, root), size=0, sha256="", mtime="",
                             error=f"directory not listed: {type(e).__name__}: "
                                   f"{e.strerror or e}")
                  for e in unlisted]
    if not files and not not_listed:
        log.warning("[!] No files found to hash")
        return []

    arriving = sum(1 for p in files if str(p.relative_to(root)) in held)
    if arriving:
        log.info(f"[~] integrity: {arriving} file(s) not recorded yet, still arriving")
    new = [p for p in files
           if str(p.relative_to(root)) not in known and str(p.relative_to(root)) not in held
           and not (p.parent == root and p.name.lower() in ours)]
    if not new and not not_listed:
        log.info(f"[=] integrity: {len(known)} original(s) already recorded, none new")
        return []
    if known:
        log.info(f"[+] integrity: {len(new)} new original(s) "
                 f"({len(known)} already recorded)")

    def _hash(p: Path) -> TraceEntry:
        rel = str(p.relative_to(root))
        try:
            return _hash_one(p, rel)
        except OSError as e:
            # One locked file raised out of the pool and the phase ended with
            # nothing written for the files that DID hash (AE-104).
            return TraceEntry(rel_path=rel, size=_size(p), sha256="", mtime="",
                              error=f"{type(e).__name__}: {e.strerror or e}")

    def _hash_one(p: Path, rel: str) -> TraceEntry:
        st = p.stat()
        return TraceEntry(
            rel_path=rel,
            size=st.st_size,
            sha256=pre.get(rel) or sha256_file(p),
            mtime=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        )

    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
        entries = sorted(ex.map(_hash, new), key=lambda e: e.rel_path) + not_listed
    for e in entries:
        if e.error:
            log.warning(f"[!] integrity: NOT hashed {e.rel_path}: {e.error}")

    # Appended whenever the file is there -- not when the index gave rows: an
    # index with no rows yet is still the index of a record that exists.
    # The index is opened BEFORE the record is written: a traces.csv open in a
    # spreadsheet that denies writes used to fail after the txt section was in,
    # leaving a section nothing indexed and a traceback -- the next run hashed the
    # same files and wrote the section again.
    csv_append = csv_path.is_file()
    try:
        fh = open(csv_path, "a" if csv_append else "w", newline="", encoding="utf-8")  # noqa: SIM115
    except OSError as e:
        raise CustodyError(f"{TRACES_CSV} cannot be written ({type(e).__name__}: {e}). "
                           f"{how}") from None
    with fh:
        try:
            _write_txt(txt_path, entries, operator,
                       append=txt_path.is_file() and txt_path.stat().st_size > 0)
        except OSError as e:
            raise CustodyError(f"{TRACES_TXT} cannot be written ({type(e).__name__}: "
                               f"{e}). {how}") from None
        _write_csv(fh, entries, header=not csv_append,
                   glue=csv_append and not _ends_a_line(csv_path))
    return entries


def _rel_of(filename, root: Path) -> str:
    try:
        return str(Path(filename).relative_to(root))
    except (TypeError, ValueError):
        return str(filename)


def _size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


def _ends_a_line(path: Path) -> bool:
    """Whether the file is empty or ends in a line break. An index cut short, or
    hand-edited, can end mid-line: the first row appended after it was glued onto
    that line, and the original it named was never recognised as recorded again."""
    with open(path, "rb") as f:
        f.seek(0, 2)
        if f.tell() == 0:
            return True
        f.seek(-1, 2)
        return f.read(1) in (b"\n", b"\r")


def _write_txt(path: Path, entries: list[TraceEntry], operator: str,
               append: bool = False) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: list[str] = []
    if append:
        # A later delivery is its own event: own timestamp, own operator, own
        # total. Reading the file top to bottom gives the order things arrived.
        lines += ["", f"Added: {now}   Operator: {operator or '-'}   Tool: v{__version__}"]
    else:
        lines += ["Artifact-Engine - Integrity record (chain of custody)",
                  f"Generated: {now}   Operator: {operator or '-'}   Tool: v{__version__}"]
    lines += ["=" * 100, f"{'PATH':<55} {'SIZE':>12}  SHA256", "-" * 100]
    for e in entries:
        if not e.error:
            lines.append(f"{e.rel_path:<55} {fmt_size(e.size):>12}  {e.sha256}")
    failed = [e for e in entries if e.error]
    for e in failed:
        lines.append(f"{e.rel_path:<55} {'NOT HASHED':>12}  {e.error}")
    lines.append("=" * 100)
    lines.append(f"Total: {len(entries) - len(failed)} file(s)"
                 + (f", {len(failed)} NOT hashed (tried again by the next run)"
                    if failed else ""))
    body = "\n".join(lines) + "\n"
    with open(path, "a" if append else "w", encoding="utf-8") as fh:
        fh.write(body)


def _write_csv(fh, entries: list[TraceEntry], header: bool, glue: bool = False) -> None:
    if glue:
        fh.write("\r\n")
    w = csv.writer(fh)
    if header:
        w.writerow(["rel_path", "size_bytes", "sha256", "mtime_utc"])
    for e in entries:
        if not e.error:             # the next run tries an unhashed one again
            w.writerow([e.rel_path, e.size, e.sha256, e.mtime])
