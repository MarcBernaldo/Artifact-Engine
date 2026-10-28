"""The web timeline read in slices, by several processes at once (v0.7.112).

`art_web_metrics` reads every request of `art_web_access.csv` and spends 16-20 us of
Python on each: on a 7.3M-request server, about 3 minutes on one core, after
`art_web_access` itself (and so did `web_hunt`, removed in v0.7.170). The raw logs
cannot be split -- a gzip stream is read from its start, and one file held 53%
of that server's requests -- but the timeline can: it is one request per line,
and no field holds a line break (`iter_log_lines` split the logs on every one),
so any byte offset moved to the next newline is the start of a row.

`slices(ctx)` cuts the timeline into ranges of whole rows, and `in_order` runs a
function over each in a process pool and hands the results back in FILE order,
so a caller that folds them one after another sees the requests in the order a
single pass would have. What a slice's result must be for that fold to be exact
is the caller's business (see `lin_web_metrics._Tally.merge`).

Only for a timeline worth it: below `MIN_BYTES` the pool's start-up (each worker
imports the package again on Windows) costs more than it saves, and the raw-log
fallback of `iter_records` is never split.
"""

from __future__ import annotations

import csv
import io
import os
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from artifact_engine.handlers._webcommon import _MAX_FIELD, _PREPARSED, Record, _source, request_row

MIN_BYTES = 256 * 1024 * 1024    # ~800k requests: below it, one pass
SLICE_BYTES = 128 * 1024 * 1024  # one task; bounds what a worker holds
_MAX_WORKERS = 4


def workers() -> int:
    """Processes per splitting parser: a quarter of the cores, at most four --
    the parse phase already runs up to `max_workers` parsers side by side."""
    return min(_MAX_WORKERS, (os.cpu_count() or 1) // 4)


def ranges(path: Path, size: int) -> list[tuple[int, int]]:
    """[lo, hi) byte ranges of whole rows covering the file after its header,
    each about `size` long."""
    total = path.stat().st_size
    with path.open("rb") as fh:
        fh.readline()                      # the header
        lo = fh.tell()
        out = []
        while lo < total:
            fh.seek(min(lo + size, total))
            if fh.tell() < total:
                fh.readline()              # to the start of the next row
            hi = fh.tell()
            out.append((lo, hi))
            lo = hi
    return out


def slices(ctx) -> list[tuple[Path, int, int]] | None:
    """The timeline as (path, lo, hi) slices, or None when the requests should be
    read in one pass (`iter_records`). Raises `HandlerSkip` as it does."""
    _, pre = _source(ctx)
    if pre is None or workers() < 2:
        return None
    try:
        if pre.stat().st_size < MIN_BYTES:
            return None
    except OSError:
        return None
    return [(pre, lo, hi) for lo, hi in ranges(pre, SLICE_BYTES)]


def read(path: Path, lo: int, hi: int):
    """(Record, source) for every row of one slice -- `_from_csv`'s answer for
    those rows: same decoding, same row-length check."""
    if csv.field_size_limit() < _MAX_FIELD:
        csv.field_size_limit(_MAX_FIELD)
    with path.open("rb") as fh:
        fh.seek(lo)
        data = io.BytesIO(fh.read(hi - lo))
    # the reader `_from_csv` has, over these bytes: decoded as it streams
    text = io.TextIOWrapper(data, encoding="utf-8", errors="replace", newline="")
    for r in csv.reader(text):
        if not request_row(r):
            continue
        yield Record(r[1], r[0], r[3], r[6], r[7], r[4], r[5], r[8], r[9],
                     edge_ip=r[2]), r[10]


def in_order(fn, parts, *args):
    """`fn(path, lo, hi, *args)` for each slice, in a pool of `workers()`
    processes; results yielded in the order of `parts`. At most two per worker
    are in flight or waiting, so a slow consumer does not pile them up."""
    n = workers()
    ex = ProcessPoolExecutor(max_workers=n)
    try:
        todo = iter(parts)
        pending: deque = deque()
        for p in todo:
            pending.append(ex.submit(fn, *p, *args))
            if len(pending) >= 2 * n:
                break
        while pending:
            result = pending.popleft().result()
            nxt = next(todo, None)
            if nxt is not None:
                pending.append(ex.submit(fn, *nxt, *args))
            yield result
    finally:
        # a consumer that stops early (or fails) does not wait for the rest
        ex.shutdown(wait=True, cancel_futures=True)


def describe(parts) -> str:
    return (f"web: reading the pre-parsed timeline ({_PREPARSED.name}) in "
            f"{len(parts)} slice(s), {workers()} process(es)")
