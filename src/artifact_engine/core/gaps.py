"""What a run did not cover, said where the run's verdict is decided (AE-108).

A lateral graph that could not be written, a memory image left out, a parser
manifest dropped, an event log left unstaged: each was one log line, and the run
ended `complete`. The places that find one call `add`; `cmd_run` empties the list
at its start and hands what is in it to `report.build_run_summary`, where any
entry makes the run `incomplete` (`not_covered`).

Only the parent process adds: everything that reports here runs there, never in
a parse worker, whose list would be another process's.
"""

from __future__ import annotations

import threading

_lock = threading.Lock()
_found: list[dict] = []


def add(what: str, detail: str) -> None:
    """One thing this run did not cover: `what` is the kind, `detail` the line."""
    with _lock:
        _found.append({"what": what, "detail": detail[:300]})


def reset() -> None:
    with _lock:
        _found.clear()


def taken() -> list[dict]:
    with _lock:
        return list(_found)
