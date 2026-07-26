"""Phase 4 - Consolidate a machine's CSVs and JSON into SQLite (.db) and Excel (.xlsx).

Walks every CSV under <machine>/CSVs -- EXCEPT anything inside a `VSS<n>` subfolder,
since VSS snapshots are consolidated as their own machines (own folder + .db) and
must not be re-absorbed into the live machine's .db -- AND every JSON under
<machine>/JSONs (the JSON-native LiveResponse output) and writes ALL of
them to BOTH the .db and the .xlsx - no size filtering. JSON tables get an `lr_`
prefix so the live/volatile state is told apart from the disk-based equivalents
(lr_services vs the registry services, etc.). The only thing the .xlsx can't take
is a sheet beyond Excel's hard structural limits (1,048,576 rows / 16,384 cols);
such a sheet is skipped from the .xlsx only and stays in the .db.

Robust: detects the separator, tries several encodings, unique table/sheet names
of <=31 characters (Excel limit).

With `merge_vss` (and `avoid_vss: false`), a host's live volume and its shadow
copies are consolidated as ONE unit -- see `plan_units` and `_build_merged`.
"""

from __future__ import annotations

import json as jsonlib
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import pandas as pd

from artifact_engine.core.detector import Machine
from artifact_engine.logging_setup import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

log = get_logger()

_DELIMITERS = [",", "|", "\t", ";"]
_ENCODINGS = ["utf-8", "latin1", "cp1252"]
_XLSX_MAX_ROWS = 1_048_576      # Excel hard limit (incl. header); bigger sheets -> .db only
_XLSX_MAX_COLS = 16_384         # Excel hard limit
# Case-root list of the per-volume outputs a merged run no longer produces.
STALE_LIST = "stale-outputs.txt"
# The .db is a derived artifact, rebuilt from scratch every run, so durability is
# irrelevant: drop fsync and the rollback journal to speed up the bulk inserts.
_PRAGMA_FAST = "PRAGMA synchronous=OFF; PRAGMA journal_mode=OFF; PRAGMA temp_store=MEMORY;"
# A merged build adds a GROUP BY over every column of tables with millions of rows.
# temp_store=MEMORY would build that sorter in RAM (a multi-GB spike on the biggest
# artifacts), so the merged path keeps its temporaries on disk and buys back the
# speed with a bigger page cache (negative = KiB, so 128 MB).
_PRAGMA_MERGE = ("PRAGMA synchronous=OFF; PRAGMA journal_mode=OFF; "
                 "PRAGMA temp_store=FILE; PRAGMA cache_size=-131072;")


def _detect_sep(path: Path, sample: int = 4096) -> str:
    try:
        with open(path, "rb") as fh:                 # read only the sample, not
            raw = fh.read(sample).decode("utf-8", errors="replace")  # the whole file
    except OSError:
        return ","
    return max(_DELIMITERS, key=lambda d: raw.count(d))


def _read_csv(path: Path) -> pd.DataFrame | None:
    sep = _detect_sep(path)
    for enc in _ENCODINGS:
        try:
            return pd.read_csv(path, sep=sep, on_bad_lines="skip", low_memory=False, encoding=enc)
        except pd.errors.EmptyDataError:
            return None
        except Exception:  # noqa: BLE001 - try next encoding
            continue
    return None


def _read_json(path: Path) -> pd.DataFrame | None:
    """Load a LiveResponse JSON artifact (array of objects, or the suspicious.json
    object whose `findings` array is the table) into a DataFrame. Nested dict/list
    cells are kept as JSON text so the table stays bounded (no column explosion)."""
    try:
        data = jsonlib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if isinstance(data, dict):
        # suspicious.json nests its rows under "findings"; correlation.json under
        # "entities" -- either becomes the table (else the object is a single row).
        arr = next((data[k] for k in ("findings", "entities") if isinstance(data.get(k), list)), None)
        records = arr if arr is not None else [data]
    elif isinstance(data, list):
        records = data
    else:
        return None
    if not records:
        return None
    try:
        df = pd.DataFrame(records)
    except Exception:  # noqa: BLE001
        return None
    if df.empty:
        return None
    for col in df.columns:
        if df[col].map(lambda v: isinstance(v, (dict, list))).any():
            df[col] = df[col].map(
                lambda v: jsonlib.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v)
    return df


def _to_db(conn: sqlite3.Connection | None, name: str,
           df: pd.DataFrame) -> tuple[bool, pd.DataFrame]:
    """Write one DataFrame to the .db with the int-too-large text fallback. Returns
    (wrote, df) -- df may have been converted to all-text on the fallback, so the
    caller writes that SAME frame to the .xlsx (keeping the two outputs consistent)."""
    if conn is None:
        return False, df
    try:
        df.to_sql(name, conn, if_exists="replace", index=False, chunksize=50_000)
        return True, df
    except Exception as e:  # noqa: BLE001
        # SQLite INTEGER is signed 64-bit; some artifacts (e.g. Amcache file IDs,
        # read as uint64) exceed it -> "int too large". Retry as all-text so the
        # FULL table is kept (replace overwrites any partial table).
        try:
            df = df.astype(str)
            df.to_sql(name, conn, if_exists="replace", index=False, chunksize=50_000)
            return True, df
        except Exception as e2:  # noqa: BLE001
            log.debug(f"sqlite: {name}: {e} / retry: {e2}")
            return False, df


def _append_rows(ws, df: pd.DataFrame, start: int) -> int:
    """Append a frame's rows to a worksheet, one whole row at a time.

    Values are handed over as Python natives: xlsxwriter falls back to `float()`
    for anything it does not recognise, which would quietly round a numpy int64
    past 2^53 (Amcache file IDs live up there), and NaN/NaT reach it as a float it
    refuses outright -- both become an empty cell instead.
    """
    r = start
    for row in df.itertuples(index=False, name=None):
        cells = []
        for v in row:
            if isinstance(v, str) or v is None:
                cells.append(v)
            elif v != v:                       # NaN / NaT -> empty cell
                cells.append(None)
            else:
                cells.append(v.item() if hasattr(v, "item") else v)
        ws.write_row(r, 0, cells)
        r += 1
    return r


def _sheet_open(xls, name: str, columns) -> object:
    """Start a sheet and write its header row.

    NOT `DataFrame.to_excel`: pandas emits cells COLUMN by column, and xlsxwriter's
    constant_memory mode flushes a row as soon as a later one is touched -- so
    every cell pandas writes back into an earlier row is silently dropped, leaving
    a sheet whose columns past the first are empty except on the very last row.
    Writing whole rows in order is what that mode requires, and it keeps the
    bounded memory the mode was chosen for in the first place.
    """
    ws = xls.book.add_worksheet(name[:31])
    ws.write_row(0, 0, [str(c) for c in columns])
    return ws


def _unique(name: str, used: set[str]) -> str:
    name = name[:31]
    base, i = name, 1
    while name in used:
        suffix = f"_{i}"
        name = base[: 31 - len(suffix)] + suffix
        i += 1
    used.add(name)
    return name


def _unique_name(csv: Path, used: set[str]) -> str:
    """Table/sheet name: the clean file basename (already <short>_<subtype>),
    <=31 chars and unique. VSS snapshots are their own machines (their own .db),
    so no volume prefix is needed -- the basename is the table name."""
    return _unique(csv.stem, used)


_RE_VSS_DIR = re.compile(r"^VSS\d+$", re.IGNORECASE)


def _iter_csvs(csv_root: Path) -> list[Path]:
    """Every CSV under a machine's CSVs/, EXCEPT those inside a `VSS<n>` subfolder.
    VSS snapshots are consolidated as their own machines (own .db), so the live
    machine must not re-absorb a nested/stale VSS output and bloat its .db."""
    if not csv_root.is_dir():
        return []
    return [p for p in csv_root.rglob("*.csv")
            if not any(_RE_VSS_DIR.match(part) for part in p.relative_to(csv_root).parts)]


def count_inputs(machine: Machine) -> int:
    """Number of input files build() will process (CSV + JSON), for a progress total."""
    csv_root = machine.path / "CSVs"
    json_root = machine.path / "JSONs"
    n = len(_iter_csvs(csv_root))
    n += sum(1 for _ in json_root.glob("*.json")) if json_root.is_dir() else 0
    return n


def build(machine: Machine, on_step: Callable[[], None] | None = None,
          emit_db: bool = True, emit_xlsx: bool = True) -> None:
    """Build <machine>/<name>.db and/or .xlsx from every CSV and JSON (no size filtering).

    `emit_db` / `emit_xlsx` select which outputs to produce (both default on). The
    input files are read once and fed to whichever output is enabled; the .xlsx pass
    dominates the time, so emit_xlsx=False is the big speed-up when you only need the
    queryable .db.

    `on_step` is pinged once per input file (the read/.db pass) and, when emit_xlsx,
    once per .xlsx sheet, so a caller can drive a two-phase per-machine progress bar.
    Steps = count_inputs(machine) [+ the sheets that fit Excel, when emit_xlsx].

    Memory: each table is read, written to the .db AND its .xlsx sheet, then dropped
    before the next is read -- so at most ONE DataFrame is held at a time (xlsxwriter
    is opened up front in constant_memory mode and flushes rows as they are written),
    instead of accumulating every machine's tables until the end."""
    if not emit_db and not emit_xlsx:
        return
    csv_root = machine.path / "CSVs"
    json_root = machine.path / "JSONs"
    csv_candidates = sorted(_iter_csvs(csv_root))   # VSS<n> subfolders excluded (own machine)
    # LiveResponse JSON (live volume only; lr_ prefix tells it apart from disk data).
    json_candidates = sorted(json_root.glob("*.json")) if json_root.is_dir() else []
    if not csv_candidates and not json_candidates:
        return

    db_path = machine.path / f"{machine.name}.db"
    xlsx_path = machine.path / f"{machine.name}.xlsx"
    used: set[str] = set()
    db_written = 0
    xlsx_written = 0

    conn: sqlite3.Connection | None = None
    if emit_db:
        # Rebuild from scratch so re-consolidation can't leave stale tables behind.
        try:
            db_path.unlink(missing_ok=True)
        except OSError as e:  # e.g. the .db is open in a viewer
            log.warning(f"[!] {db_path.name} is locked (open elsewhere?); not rebuilt: {e}")
            if not emit_xlsx:
                return          # nothing else to produce
        else:
            conn = sqlite3.connect(db_path)
            conn.executescript(_PRAGMA_FAST)
    # constant_memory: xlsxwriter flushes each row as it is written, so a big sheet
    # (e.g. MFT) never holds the whole workbook in RAM.
    # The workbook is opened here, before any table is read. If last run's .xlsx is
    # open in Excel that raises, and letting it escape would abandon the .db half
    # built (connection open, no tables, file left on disk looking valid) -- so it
    # degrades to .db-only, the same way a locked .db degrades to .xlsx-only above.
    xls = None
    if emit_xlsx:
        try:
            xls = pd.ExcelWriter(xlsx_path, engine="xlsxwriter",
                                 engine_kwargs={"options": {"constant_memory": True}})
        except OSError as e:
            log.warning(f"[!] {xlsx_path.name} is locked (open in Excel?); "
                        f"writing the .db only: {e}")
            if conn is None:
                return          # neither output can be produced

    def _emit(name: str, df: pd.DataFrame) -> None:
        nonlocal db_written, xlsx_written
        wrote_db, df = _to_db(conn, name, df)
        if wrote_db:
            db_written += 1
        if on_step:            # db-pass tick (once per readable input)
            on_step()
        if xls is not None and df.shape[0] <= _XLSX_MAX_ROWS - 1 and df.shape[1] <= _XLSX_MAX_COLS:
            try:
                _append_rows(_sheet_open(xls, name, df.columns), df, 1)
                xlsx_written += 1
            except Exception as e:  # noqa: BLE001
                log.debug(f"excel: sheet {name}: {e}")
            if on_step:        # xlsx-pass tick (once per sheet that fits)
                on_step()

    try:
        # CSVs: handler parsers no longer emit header-only CSVs (a 0-row result
        # writes no file), so an empty table here only comes from a parser that
        # still produces one. The .xlsx mirrors the .db except over-limit sheets.
        for csv in csv_candidates:
            df = _read_csv(csv)
            if df is not None:
                _emit(_unique_name(csv, used), df)
            elif on_step:      # advance even for an unreadable file (keeps the count exact)
                on_step()
        # LiveResponse JSON: each artifact (and the suspicious findings) as a table.
        for jf in json_candidates:
            df = _read_json(jf)
            if df is not None:
                _emit(_unique("lr_" + jf.stem, used), df)
            elif on_step:
                on_step()
    finally:
        if conn is not None:
            conn.close()
        if xls is not None:
            try:
                xls.close()    # ExcelWriter with no sheets still needs a clean close
            except Exception:  # noqa: BLE001
                pass
            if not xlsx_written:
                xlsx_path.unlink(missing_ok=True)   # don't leave an empty .xlsx

    if conn is not None and db_written == 0:
        db_path.unlink(missing_ok=True)


def consolidate_machine(idx: int, machine: Machine, q=None,
                        emit_db: bool = True, emit_xlsx: bool = True) -> tuple[int, str | None]:
    """Pool worker (module-level so it is picklable for a process pool).

    Builds the configured outputs for one machine and, if `q` is given (a progress
    queue), pushes `(idx, True)` per step and a final `(idx, False)` when finished.
    Returns `(idx, error_or_None)`: failures come back as data rather than being
    logged, since this may run in a child process with no log handlers."""
    err: str | None = None
    try:
        build(machine, on_step=(lambda: q.put((idx, True))) if q is not None else None,
              emit_db=emit_db, emit_xlsx=emit_xlsx)
    except Exception as e:  # noqa: BLE001 - reported to the parent, never silently dropped
        err = f"{type(e).__name__}: {e}"
    if q is not None:
        q.put((idx, False))   # machine finished -> bar to 100%
    return idx, err


# --------------------------------------------------------------------------- #
# Merged consolidation: one .db per HOST instead of one per volume
# --------------------------------------------------------------------------- #
# A machine with ten shadow copies is eleven machines here, so the analyst gets
# eleven .db files each holding its own evtx_Security -- and finding one logon
# means opening all eleven. Merging folds the same artifact across a host's
# volumes into ONE table, dropping the rows the volumes share and recording, per
# surviving row, which volumes carried it. The per-volume CSVs stay on disk
# untouched: this is a consolidated VIEW, not a rewrite of the evidence.

_VOL_COL = "_aeng_vol"          # per-row volume tag, only ever inside the staging table
_STAGE = "_aeng_stage"          # staging table, dropped as soon as its group is folded
_XLSX_CHUNK = 100_000           # rows per read_sql->to_excel hop (bounded memory)
_MAX_CANON_CASES = 500          # give up canonicalising `volumes` past this many combos
_PROV_SAMPLE = 50               # rows sampled per column when sniffing provenance


@dataclass
class Unit:
    """One consolidation output: either a single machine, or a host's volumes
    (live disk + shadow copies) folded into one .db/.xlsx/report.txt."""

    name: str                   # output basename (the host)
    path: Path                  # directory the outputs are written to
    members: list[Machine]      # contributing volumes, live first then VSS1..n
    labels: list[str] = field(default_factory=list)   # per-member volume label

    @property
    def primary(self) -> Machine:
        """The machine the unit is named and identified after (the live volume)."""
        return self.members[0]

    @property
    def merged(self) -> bool:
        return len(self.members) > 1


_VSS_SUFFIX = re.compile(r"_VSS\d+$", re.IGNORECASE)


def _host_of(machine: Machine) -> str:
    """The host a machine belongs to: `HOST_VSS3` and `HOST` are the same host."""
    return _VSS_SUFFIX.sub("", machine.name) if machine.is_vss else machine.name


def _vss_ordinal(machine: Machine) -> int:
    mo = re.search(r"(\d+)$", machine.name)
    return int(mo.group(1)) if mo else 0


def _vol_label(machine: Machine) -> str:
    """Short label for the volume a machine represents: `C`, `VSS3`, `live`."""
    return machine.volumes[0].name if machine.volumes else machine.name


def _labels_for(machines: list[Machine]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in machines:
        base = label = _vol_label(m)
        i = 1
        while label in seen:                # two volumes claiming one name
            label = f"{base}#{i}"
            i += 1
        seen.add(label)
        out.append(label)
    return out


def plan_units(results, merge_vss: bool = True):
    """Group `[(machine, runs)]` into consolidation units.

    Without `merge_vss` -- or with no shadow copies parsed -- this is the identity:
    one unit per machine, byte-for-byte today's behaviour. With it, a host's live
    volume and its `VSS<n>` siblings become a single unit whose outputs land in the
    collection folder (the parent both share), so `<coll>/HOST.db` sits beside
    `C/` and `VSS1/` rather than inside either.

    Grouping is by (collection folder, host name): siblings on disk that the
    detector already named after the same host. A group merges ONLY if it holds a
    live volume AND at least one snapshot of it -- merging is a fold of volumes,
    never of acquisitions. Two separate machines can legitimately share both keys:
    a LiveResponse-only collection is rooted at the collection folder itself, and a
    loose EVTX drop renamed after the host it logged sits beside it, so both have
    the CASE ROOT as their parent and the same name. Folding those together would
    conflate two acquisitions and write the result at the top of the case.
    """
    def solo(m: Machine, runs):
        return (Unit(m.name, m.path, [m], [_vol_label(m)]), runs)

    if not merge_vss or not any(m.is_vss for m, _ in results):
        return [solo(m, runs) for m, runs in results]

    groups: dict[tuple[str, str], list] = {}
    for m, runs in results:
        try:
            parent = str(m.path.parent.resolve()).lower()
        except OSError:                     # unreachable path: keep it ungrouped
            parent = str(m.path.parent).lower()
        groups.setdefault((parent, _host_of(m).lower()), []).append((m, runs))

    units: list[tuple[Unit, list]] = []
    for members in groups.values():
        live = [x for x in members if not x[0].is_vss]
        vss = sorted((x for x in members if x[0].is_vss), key=lambda x: _vss_ordinal(x[0]))
        if not live or not vss:
            units += [solo(m, runs) for m, runs in members]
            continue
        ordered = [live[0], *vss]
        machines = [m for m, _ in ordered]
        runs = [r for _, rs in ordered for r in rs]
        primary = machines[0]
        units.append((Unit(primary.name, primary.path.parent, machines,
                           _labels_for(machines)), runs))
        # Anything else that merely shares the folder and the name is its own
        # acquisition and keeps its own outputs.
        units += [solo(m, r) for m, r in live[1:]]
    return units


def count_unit_inputs(unit: Unit) -> int:
    return sum(count_inputs(m) for m in unit.members)


def stale_outputs(unit: Unit) -> list[Path]:
    """Per-volume outputs a MERGED unit will no longer produce but that an earlier
    (unmerged) run may have left behind. Reported, never deleted: removing files
    from inside a case is the analyst's call, not the engine's."""
    if not unit.merged:
        return []
    out: list[Path] = []
    for m in unit.members:
        for p in (m.path / f"{m.name}.db", m.path / f"{m.name}.xlsx", m.path / "report.txt"):
            if p.is_file():
                out.append(p)
    return out


def write_stale_list(paths: list[Path], root: Path) -> Path | None:
    """Write the EXACT list of stale per-volume outputs to `<root>/stale-outputs.txt`.

    One absolute path per line and nothing else, so the list can be acted on as it
    stands (`Get-Content stale-outputs.txt | Remove-Item`) instead of rebuilt by
    hand from a count and one example. Rebuilding it by hand is precisely where it
    goes wrong: the same folders also hold the outputs this run DOES rebuild, and
    the two are told apart only by which volume directory they sit in -- a filter
    that is easy to write too broadly (catching a live machine's current
    report.txt) or too narrowly (missing the per-snapshot .db files, which are the
    ones holding the gigabytes).

    Nothing is deleted here; that stays the analyst's call. An empty list truncates
    a file an earlier run wrote, because its contents may already have been acted
    on and a list that no longer matches the disk is worse than no list at all.
    """
    dest = root / STALE_LIST
    if not paths:
        if dest.is_file():
            dest.write_text("", encoding="utf-8")
        return None
    dest.write_text("".join(f"{p}\n" for p in paths), encoding="utf-8")
    return dest


def _q(name: str) -> str:
    """A SQLite identifier, quoted."""
    return '"' + str(name).replace('"', '""') + '"'


def _volumes_col(cols: list[str]) -> str:
    """Name for the provenance column, stepped aside if the artifact already has
    one called `volumes` (a duplicate column name would fail the CREATE TABLE)."""
    taken = {c.lower() for c in cols}
    name = "volumes"
    i = 1
    while name.lower() in taken:
        name = f"aeng_volumes_{i}"
        i += 1
    return name


def _read_columns(path: Path) -> list[str] | None:
    """Just the header of a CSV -- the union of headers across volumes has to be
    known BEFORE the first row is inserted, so the staging table is created once
    with every column any volume contributes."""
    sep = _detect_sep(path)
    for enc in _ENCODINGS:
        try:
            return list(pd.read_csv(path, sep=sep, nrows=0, encoding=enc).columns)
        except pd.errors.EmptyDataError:
            return None
        except Exception:  # noqa: BLE001 - try next encoding
            continue
    return None


def _unit_groups(unit: Unit) -> tuple[dict[str, list[tuple[str, Path]]], dict[str, str]]:
    """Map every input file of every member to the artifact it belongs to.

    Keyed by the path RELATIVE to the volume's CSVs/ root (`EventLogs/
    evtx_Security.csv`), not the basename: two different artifacts that happen to
    share a basename in different categories must not be folded into one table.
    Returns (key -> [(volume label, file)], key -> table basename).
    """
    groups: dict[str, list[tuple[str, Path]]] = {}
    names: dict[str, str] = {}
    for label, m in zip(unit.labels, unit.members):
        csv_root = m.path / "CSVs"
        for p in sorted(_iter_csvs(csv_root)):
            key = "csv:" + p.relative_to(csv_root).as_posix().lower()
            groups.setdefault(key, []).append((label, p))
            names.setdefault(key, p.stem)
        json_root = m.path / "JSONs"
        if json_root.is_dir():
            for p in sorted(json_root.glob("*.json")):
                key = "json:" + p.name.lower()
                groups.setdefault(key, []).append((label, p))
                names.setdefault(key, "lr_" + p.stem)
    return groups, names


def _sniff_provenance(df: pd.DataFrame, root: Path, label: str, found: set[str]) -> None:
    """Flag columns whose values embed the volume's own location on disk.

    EZ-tools artifacts carry a `SourceFile` holding the full path of the file they
    parsed -- which differs per volume by construction, so leaving it in the
    grouping key would make every row unique and the merge a no-op (measured: a
    whole-row match found ZERO duplicates across eleven volumes until this column
    was excluded). Sniffed from the data instead of a column-name list, so a
    parser that names it differently is still caught.
    """
    root_s = str(root).lower()
    tag = f"\\{label}\\".lower()
    head = df.head(_PROV_SAMPLE)
    for col in df.columns:
        if col in found:
            continue
        try:
            vals = head[col].dropna()
        except Exception:  # noqa: BLE001
            continue
        if vals.empty:
            continue
        v = str(vals.iloc[0]).lower()
        if root_s in v or tag in v:
            found.add(col)


def _read_any(path: Path) -> pd.DataFrame | None:
    """One input file, whichever kind it is (LiveResponse ships JSON, not CSV)."""
    return _read_json(path) if path.suffix.lower() == ".json" else _read_csv(path)


def _write_single(conn: sqlite3.Connection | None, name: str,
                  source: tuple[str, Path]) -> tuple[int, pd.DataFrame | None]:
    """An artifact only ONE volume produced: written through unchanged, with a
    constant `volumes` column.

    Deliberately NOT folded: there is nothing to merge, and collapsing a volume's
    own repeated rows is not this feature's job -- merging removes what the volumes
    duplicate of each other, never what an artifact legitimately repeats. This is
    also the path every LiveResponse JSON takes (it exists on the live volume only).
    """
    label, path = source
    df = _read_any(path)
    if df is None:
        return 0, None
    df[_volumes_col(list(df.columns))] = label
    wrote, df = _to_db(conn, name, df)
    return (len(df), df) if wrote else (0, None)


def _fold_group(conn: sqlite3.Connection, name: str, sources: list[tuple[str, Path]],
                roots: dict[str, Path], as_text: bool) -> tuple[int, dict[str, int]]:
    """Stage every volume's copy of one artifact, then fold it into `name`.

    Deduplication happens IN SQLite: the volumes are appended to a staging table
    and collapsed with `GROUP BY <every non-provenance column>`, which is bounded
    by disk rather than by RAM (a Python set over 2.6M rows is not). The grouping
    key is the whole row on purpose -- an identifier key would be smaller, but a
    cleared log restarts its record IDs, and then two genuinely different events
    share one. Whole-row means the worst case is "a duplicate survives", never
    "an event is lost".

    Type drift between volumes (a column pandas reads as int in one file and as
    text in another) is absorbed by SQLite's column affinity: the staging table is
    declared once from the first volume, and later inserts are converted to it.

    Returns (rows staged, rows staged per volume).
    """
    conn.execute(f"DROP TABLE IF EXISTS {_q(_STAGE)}")
    # Union of the headers, first spelling wins; case-insensitive so a volume that
    # capitalises a column differently lands in the same one instead of a new one.
    cols: list[str] = []
    canon: dict[str, str] = {}
    for _label, p in sources:
        for c in _read_columns(p) or []:
            if c.lower() not in canon:
                canon[c.lower()] = c
                cols.append(c)
    if not cols:
        return 0, {}

    prov: set[str] = set()
    per_vol: dict[str, int] = {}
    staged = 0
    for label, p in sources:
        df = _read_any(p)
        if df is None:
            continue
        df = df.rename(columns=lambda c: canon.get(str(c).lower(), c))
        if df.columns.has_duplicates:       # a file carrying both `Time` and `time`
            log.debug(f"merge: {p.name}: duplicate column(s) after folding case")
            df = df.loc[:, ~df.columns.duplicated()]
        df = df.reindex(columns=cols)       # missing columns -> NULL, order fixed
        _sniff_provenance(df, roots[label], label, prov)
        if as_text:
            df = df.astype(str)
        df[_VOL_COL] = label
        df.to_sql(_STAGE, conn, if_exists="append", index=False, chunksize=50_000)
        per_vol[label] = per_vol.get(label, 0) + len(df)
        staged += len(df)
    if not staged:
        conn.execute(f"DROP TABLE IF EXISTS {_q(_STAGE)}")
        return 0, {}

    grouped = [c for c in cols if c not in prov] or cols
    volcol = _volumes_col(cols)
    select = ", ".join(_q(c) if c in grouped else f"MAX({_q(c)}) AS {_q(c)}" for c in cols)
    conn.execute(f"DROP TABLE IF EXISTS {_q(name)}")
    conn.execute(
        f"CREATE TABLE {_q(name)} AS SELECT {select}, "
        f"group_concat(DISTINCT {_q(_VOL_COL)}) AS {_q(volcol)} "
        f"FROM {_q(_STAGE)} GROUP BY {', '.join(_q(c) for c in grouped)}"
    )
    conn.execute(f"DROP TABLE IF EXISTS {_q(_STAGE)}")
    return staged, per_vol


def _canonicalise_volumes(conn: sqlite3.Connection, name: str, volcol: str,
                          order: list[str]) -> dict[str, int]:
    """Put `volumes` in volume order and count what is unique to each volume.

    `group_concat` emits its members in scan order, so the same pair of volumes can
    come out as `C,VSS3` in one table and `VSS3,C` in the next. The distinct
    combinations are few, so they are rewritten in one pass with a CASE (never one
    UPDATE per combination, which would be one full scan each).

    Returns rows found in exactly one volume, per volume -- the number that tells
    the analyst which snapshot is worth opening.
    """
    rank = {v: i for i, v in enumerate(order)}
    try:
        combos = conn.execute(
            f"SELECT {_q(volcol)}, COUNT(*) FROM {_q(name)} GROUP BY 1").fetchall()
    except sqlite3.Error as e:
        log.debug(f"merge: {name}: volume stats unavailable: {e}")
        return {}
    unique: dict[str, int] = {}
    rewrite: list[tuple[str, str]] = []
    for raw, n in combos:
        parts = sorted({p for p in str(raw or "").split(",") if p},
                       key=lambda v: (rank.get(v, len(rank)), v))
        if len(parts) == 1:
            unique[parts[0]] = unique.get(parts[0], 0) + n
        fixed = ",".join(parts)
        if raw is not None and fixed != raw:
            rewrite.append((raw, fixed))
    if rewrite and len(rewrite) <= _MAX_CANON_CASES:
        cases = " ".join("WHEN ? THEN ?" for _ in rewrite)
        params = [x for pair in rewrite for x in pair]
        try:
            conn.execute(
                f"UPDATE {_q(name)} SET {_q(volcol)} = "
                f"CASE {_q(volcol)} {cases} ELSE {_q(volcol)} END", params)
            conn.commit()                   # an UPDATE opens a transaction; DDL later
        except sqlite3.Error as e:          # cosmetic only, never fatal
            log.debug(f"merge: {name}: could not order the volume column: {e}")
    return unique


def _sheet_from_table(conn: sqlite3.Connection, xls, name: str) -> bool:
    """Write a merged table to its .xlsx sheet, streaming it out of SQLite.

    The deduplicated table only exists in the .db, so the sheet has to be read back
    -- in chunks, because a table that fits Excel can still be a million rows and
    xlsxwriter is in constant_memory mode precisely so nothing is held whole."""
    try:
        n = conn.execute(f"SELECT COUNT(*) FROM {_q(name)}").fetchone()[0]
    except sqlite3.Error:
        return False
    if n > _XLSX_MAX_ROWS - 1:
        return False
    sql = f"SELECT * FROM {_q(name)}"
    try:
        ws = None
        row = 1                             # row 0 is the header
        for chunk in pd.read_sql_query(sql, conn, chunksize=_XLSX_CHUNK):
            if ws is None:
                if chunk.shape[1] > _XLSX_MAX_COLS:
                    return False
                ws = _sheet_open(xls, name, chunk.columns)
            row = _append_rows(ws, chunk, row)
        return ws is not None
    except Exception as e:  # noqa: BLE001
        log.debug(f"excel: sheet {name}: {e}")
        return False


def _empty_stats(unit: Unit) -> dict:
    return {"merged": unit.merged, "volumes": list(unit.labels),
            "artifacts": {}, "rows": {}, "unique": {}, "total_rows": 0,
            "merged_rows": 0, "tables": 0}


def _build_merged(unit: Unit, on_step: Callable[[], None] | None,
                  emit_db: bool, emit_xlsx: bool) -> dict:
    """Fold a host's volumes into one .db/.xlsx. See `_fold_group` for the dedup."""
    stats = _empty_stats(unit)
    groups, names = _unit_groups(unit)
    if not groups:
        return stats
    roots = {label: m.path for label, m in zip(unit.labels, unit.members)}

    db_path = unit.path / f"{unit.name}.db"
    xlsx_path = unit.path / f"{unit.name}.xlsx"
    tmp_db: Path | None = None
    conn: sqlite3.Connection | None = None
    if emit_db:
        try:
            db_path.unlink(missing_ok=True)     # rebuilt from scratch, no stale tables
        except OSError as e:
            log.warning(f"[!] {db_path.name} is locked (open elsewhere?); not rebuilt: {e}")
            if not emit_xlsx:
                return stats
        else:
            conn = sqlite3.connect(db_path)
    if conn is None:
        if not emit_xlsx:
            return stats
        # The deduplication IS a SQL GROUP BY, so an .xlsx-only merge still needs a
        # database to do it in -- a scratch one, removed on the way out.
        tmp_db = unit.path / f".{unit.name}.aeng-merge.db"
        try:
            tmp_db.unlink(missing_ok=True)
            conn = sqlite3.connect(tmp_db)
        except (OSError, sqlite3.Error) as e:
            log.warning(f"[!] {unit.name}: cannot merge without a scratch database: {e}")
            return stats
    conn.executescript(_PRAGMA_MERGE)

    xls = None
    if emit_xlsx:
        try:
            xls = pd.ExcelWriter(xlsx_path, engine="xlsxwriter",
                                 engine_kwargs={"options": {"constant_memory": True}})
        except OSError as e:
            log.warning(f"[!] {xlsx_path.name} is locked (open in Excel?); "
                        f"writing the .db only: {e}")
            if tmp_db is not None:          # the scratch db existed only for the .xlsx
                conn.close()
                tmp_db.unlink(missing_ok=True)
                return stats

    used: set[str] = set()
    db_written = xlsx_written = 0
    try:
        for key in sorted(groups):
            sources = groups[key]
            name = _unique(names[key], used)
            df = None
            try:
                if len(sources) == 1:       # nothing to merge: written through
                    staged, df = _write_single(conn, name, sources[0])
                    per_vol = unique = {sources[0][0]: staged}
                else:
                    staged, per_vol = _fold_group(conn, name, sources, roots, as_text=False)
                    unique = {}
            except Exception as e:  # noqa: BLE001
                # Same fallback as the single-machine path: SQLite's INTEGER is
                # signed 64-bit and some artifacts (Amcache file IDs) overflow it.
                # Retry the WHOLE group as text -- a half-staged table cannot be
                # topped up, it has to be rebuilt.
                log.debug(f"merge: {name}: {e}; retrying as text")
                try:
                    staged, per_vol = _fold_group(conn, name, sources, roots, as_text=True)
                    unique = {}
                except Exception as e2:  # noqa: BLE001
                    log.debug(f"merge: {name}: retry failed: {e2}")
                    staged, per_vol, unique = 0, {}, {}
            if on_step:
                for _ in sources:           # one db-pass tick per input file
                    on_step()
            if not staged:
                continue
            db_written += 1
            for label, n in per_vol.items():
                stats["rows"][label] = stats["rows"].get(label, 0) + n
                stats["artifacts"][label] = stats["artifacts"].get(label, 0) + 1
            stats["total_rows"] += staged
            if df is None:                  # folded: normalise `volumes` and count
                cols = [r[1] for r in conn.execute(f"PRAGMA table_info({_q(name)})")]
                unique = _canonicalise_volumes(conn, name, cols[-1] if cols else "volumes",
                                               unit.labels)
            for label, n in unique.items():
                stats["unique"][label] = stats["unique"].get(label, 0) + n
            stats["merged_rows"] += conn.execute(
                f"SELECT COUNT(*) FROM {_q(name)}").fetchone()[0]
            if xls is not None:
                # A written-through table is still in hand; a folded one only
                # exists in the .db and has to be streamed back out of it.
                try:
                    if df is not None:
                        if df.shape[0] <= _XLSX_MAX_ROWS - 1 and df.shape[1] <= _XLSX_MAX_COLS:
                            _append_rows(_sheet_open(xls, name, df.columns), df, 1)
                            xlsx_written += 1
                    elif _sheet_from_table(conn, xls, name):
                        xlsx_written += 1
                except Exception as e:  # noqa: BLE001
                    log.debug(f"excel: sheet {name}: {e}")
                if on_step:                 # xlsx-pass tick (once per sheet)
                    on_step()
    finally:
        stats["tables"] = db_written
        try:
            conn.commit()
            # Staging is transient but its pages are not: dropping the table only
            # moves them to the free list, so the merged .db would keep the
            # high-water mark of the biggest artifact it ever staged (measured:
            # 214 MB of file for 94k surviving rows). VACUUM rewrites it down to
            # what is actually left -- cheap here, since that is the small part.
            if emit_db and tmp_db is None and db_written:
                conn.execute("VACUUM")
        except sqlite3.Error as e:
            log.debug(f"merge: {unit.name}: {e}")
        conn.close()
        if xls is not None:
            try:
                xls.close()
            except Exception:  # noqa: BLE001
                pass
            if not xlsx_written:
                xlsx_path.unlink(missing_ok=True)
        if tmp_db is not None:
            tmp_db.unlink(missing_ok=True)
        elif emit_db and db_written == 0:
            db_path.unlink(missing_ok=True)
    return stats


def build_unit(unit: Unit, on_step: Callable[[], None] | None = None,
               emit_db: bool = True, emit_xlsx: bool = True) -> dict:
    """Build the outputs for one unit: a plain machine, or a merged host."""
    if not emit_db and not emit_xlsx:
        return _empty_stats(unit)
    if not unit.merged:
        build(unit.primary, on_step=on_step, emit_db=emit_db, emit_xlsx=emit_xlsx)
        return _empty_stats(unit)
    return _build_merged(unit, on_step, emit_db, emit_xlsx)


def consolidate_unit(idx: int, unit: Unit, q=None, emit_db: bool = True,
                     emit_xlsx: bool = True) -> tuple[int, str | None, dict]:
    """Pool worker for one unit (module-level so it is picklable).

    Returns `(idx, error_or_None, stats)`: like `consolidate_machine`, failures come
    back as data because this may run in a child process with no log handlers."""
    err: str | None = None
    stats = _empty_stats(unit)
    try:
        stats = build_unit(unit, on_step=(lambda: q.put((idx, True))) if q is not None else None,
                           emit_db=emit_db, emit_xlsx=emit_xlsx)
    except Exception as e:  # noqa: BLE001 - reported to the parent, never silently dropped
        err = f"{type(e).__name__}: {e}"
    if q is not None:
        q.put((idx, False))   # unit finished -> bar to 100%
    return idx, err, stats
