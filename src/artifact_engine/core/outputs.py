"""What a parser wrote last time, so a re-run that finds less removes the rest (v0.7.106).

A parser writes into its private work dir and `runner._merge_into` moves what it
produced into the shared category folder, replacing files of the same name.
What it did NOT produce this time was left alone -- and `write_csv` writes no
file for zero rows. So a detection that stopped matching (a false positive
fixed, a catalog entry withdrawn) kept its previous table on disk, and the
consolidated database went on reporting it. Measured on a real case: 211 rows
of .NET's `createdump.exe` and ten module-manifest "log clearing" lines, both
fixed in v0.7.103/104, still in `suspicious_tools` / `suspicious_commands`.

Each run that merges files records, in `.<parser>.outputs` beside its `.done`
marker, every top-level name it put in the folder and that file's modification
time once there. The next `ok` run removes a recorded name it did not produce
only if the file is still exactly the one recorded (same modification time):

  - names are compared without case, as Windows resolves them (`Evtx_RDP.csv`
    and `evtx_rdp.csv` are one file, the one this run just wrote);
  - a file changed since -- another parser took the name -- is not ours and stays;
  - a run that ends `skipped` or `error` removes nothing (a skip can be a
    quarantined tool rather than the evidence, an error is no result), but what
    it did merge -- hayabusa moves its views before it fails -- is recorded, so
    the next `ok` run can still clean it;
  - a stale file that cannot be removed (open in Excel) stays recorded and is
    retried.

A parser with no record yet -- everything parsed before v0.7.106 -- is judged by
the names its manifest declares under `outputs:` directly in `{out}`: one of
those this run did not produce, last modified before this run began, is the
previous run's and is removed. Declared names are unique per folder (no two
bundled manifests share one), and the hunts declare theirs.

A parser that no longer exists -- renamed, or folded into another -- has no run
of its own to clean up after it. Its successor names it under `replaces:` in its
manifest with the names it wrote, and each `ok` run of the successor retires it
(`retire`, v0.7.156). Those names have no other owner, so they go whatever their
modification time -- one opened and saved in Excel, or re-stamped by a copy, is
still the retired table -- except one the successor itself just wrote; a name only
its record holds goes by the rule above. Then its record and marker go. One it
cannot remove stays in its record and fails the successor's run, which is retried.

The record is plain text and not `.json`/`.csv`: the consolidation globs those,
dot-files included.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def record_path(out_dir: Path, parser_id: str) -> Path:
    return Path(out_dir) / f".{parser_id}.outputs"


def produced(work: Path) -> list[str]:
    """The top-level names a parser left in its work dir, before they are merged."""
    try:
        return sorted(p.name for p in Path(work).iterdir())
    except OSError:
        return []


def _read(out_dir: Path, parser_id: str) -> dict[str, int] | None:
    """{name: mtime_ns} from the record, or None when there is none."""
    try:
        text = record_path(out_dir, parser_id).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return None
    out: dict[str, int] = {}
    for ln in text.splitlines():
        name, _, stamp = ln.strip().partition("\t")
        if name:
            out[name] = int(stamp) if stamp.isdigit() else -1
    return out


def _stamp(path: Path) -> int | None:
    """The latest modification under `path` (itself for a file), or None if gone."""
    try:
        newest = path.lstat().st_mtime_ns
    except OSError:
        return None
    if path.is_dir() and not path.is_symlink():
        for root, dirs, files in os.walk(path):
            for n in (*dirs, *files):
                try:
                    newest = max(newest, os.lstat(os.path.join(root, n)).st_mtime_ns)
                except OSError:
                    continue
    return newest


def _safe(name: str) -> bool:
    """A bare name: never a path that could leave the folder, never a marker."""
    return bool(name) and name not in (".", "..") and "/" not in name and "\\" not in name \
        and ":" not in name and not name.endswith((".done", ".outputs"))


def _write(out_dir: Path, parser_id: str, entries: dict[str, int]) -> None:
    try:
        record_path(out_dir, parser_id).write_text(
            "".join(f"{n}\t{entries[n]}\n" for n in sorted(entries) if _safe(n)),
            encoding="utf-8")
    except OSError:
        pass


def _current(out_dir: Path, names: list[str]) -> dict[str, int]:
    return {n: s for n in names if (s := _stamp(out_dir / n)) is not None}


def _bootstrap(out_dir: Path, declared, started_ns: int) -> dict[str, int]:
    """Without a record: the declared names on disk from before this run."""
    out = {}
    for name in declared:
        stamp = _stamp(out_dir / name) if _safe(name) else None
        if stamp is not None and started_ns and stamp < started_ns:
            out[name] = stamp
    return out


def note(out_dir: Path, parser_id: str, names: list[str],
         declared: list[str] | tuple = (), started_ns: int = 0) -> None:
    """A run that did not end `ok` but merged `names`: record them, remove nothing.
    Without a record yet, the declared outputs from before this run are recorded
    with them, so the next `ok` run still judges those."""
    out_dir = Path(out_dir)
    if not names:
        return
    previous = _read(out_dir, parser_id)
    if previous is None:
        previous = _bootstrap(out_dir, declared, started_ns)
    previous.update(_current(out_dir, names))
    _write(out_dir, parser_id, previous)


def settle(out_dir: Path, parser_id: str, names: list[str],
           declared: list[str] | tuple = (), started_ns: int = 0) -> list[str]:
    """After an `ok` run: remove what is still the previous run's and this one did
    not produce, then record `names`. Returns the names removed. Never raises:
    this is bookkeeping, and a failure leaves at worst one stale table, which is
    what happened before."""
    out_dir = Path(out_dir)
    previous = _read(out_dir, parser_id)
    candidates: dict[str, int | None] = dict(previous) if previous is not None \
        else dict.fromkeys(declared)
    fresh = {n.casefold() for n in names}
    removed: list[str] = []
    kept: dict[str, int] = {}         # stale but locked: retried next run
    for name, stamp in sorted(candidates.items()):
        if not _safe(name) or name.casefold() in fresh:
            continue
        target = out_dir / name
        now = _stamp(target)
        if now is None:
            continue
        if stamp is None:
            if not started_ns or now >= started_ns:
                continue              # bootstrap: only what predates this run
        elif now != stamp:
            continue                  # changed since we recorded it: not ours any more
        try:
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink()
            removed.append(name)
        except OSError:
            kept[name] = now
    _write(out_dir, parser_id, {**kept, **_current(out_dir, names)})
    return removed


def retire(out_dir: Path, parser_id: str, declared: list[str] | tuple = (),
           fresh: list[str] | tuple = ()) -> list[str]:
    """Remove what a parser that no longer exists left in `out_dir`: its `declared`
    names whatever their age, a name only its record holds if unchanged since, never
    one in `fresh` (what the successor just wrote). Then its record and marker -- a
    file that could not be removed keeps the record, to be retried. Returns the
    names it could not remove. Never raises."""
    out_dir = Path(out_dir)
    previous = _read(out_dir, parser_id) or {}
    owned = {n.casefold() for n in declared}
    skip = {n.casefold() for n in fresh}
    left: list[str] = []
    for name in sorted({*previous, *declared}):
        if not _safe(name) or name.casefold() in skip:
            continue
        target = out_dir / name
        now = _stamp(target)
        if now is None or (name.casefold() not in owned and previous.get(name) != now):
            continue                  # gone, or changed since: not the retired one's
        try:
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink()
        except OSError:
            left.append(name)
    if not left:                      # else the record stays as it was: the retry's list
        for leftover in (record_path(out_dir, parser_id), out_dir / f".{parser_id}.done"):
            try:
                leftover.unlink(missing_ok=True)
            except OSError:
                pass
    return left
