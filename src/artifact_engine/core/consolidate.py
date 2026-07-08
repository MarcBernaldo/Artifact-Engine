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
"""

from __future__ import annotations

import json as jsonlib
import re
import sqlite3
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
# The .db is a derived artifact, rebuilt from scratch every run, so durability is
# irrelevant: drop fsync and the rollback journal to speed up the bulk inserts.
_PRAGMA_FAST = "PRAGMA synchronous=OFF; PRAGMA journal_mode=OFF; PRAGMA temp_store=MEMORY;"


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
    xls = pd.ExcelWriter(xlsx_path, engine="xlsxwriter",
                         engine_kwargs={"options": {"constant_memory": True}}) if emit_xlsx else None

    def _emit(name: str, df: pd.DataFrame) -> None:
        nonlocal db_written, xlsx_written
        wrote_db, df = _to_db(conn, name, df)
        if wrote_db:
            db_written += 1
        if on_step:            # db-pass tick (once per readable input)
            on_step()
        if xls is not None and df.shape[0] <= _XLSX_MAX_ROWS - 1 and df.shape[1] <= _XLSX_MAX_COLS:
            try:
                df.to_excel(xls, sheet_name=name, index=False)
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
