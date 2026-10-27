"""What the MCP server lets an assistant do with a case (v0.7.167).

The server (`artifact_engine.mcp_server`) only registers these functions with
the MCP SDK; everything they do is here, importable and testable without it.

Two kinds of tool:

- READ. Cases, machines, tables, read-only SQL on a machine's `.db`, its
  findings and `report.txt`, a value searched across the case (`sweep`) and the
  lateral-movement timeline. A sweep reads every table of every machine, which
  on a large case takes minutes: past `SWEEP_WAIT` it goes on in a thread of the
  server and is collected with `sweep_result`. Answers are SMALL on purpose -- a row cap, long
  cells cut, `has_more` and the totals said -- so they fit the context of a
  local model as well as a large one, and so a 400,000-row table is paged, never
  dumped. The SQL runs on a read-only connection with an authorizer that allows
  reading and nothing else (no ATTACH, no PRAGMA, no write), under a time limit.
- LAUNCH. `aeng run` / `aeng lateral` on a case, started in the background with
  the interpreter running the server; `run_status` follows them. One thing at a
  time per case: a run or a sweep.

A case is a folder directly under one of the roots the server was started with,
named by that folder's name alone: `..`, a path, a nested name are refused, and
every file a tool reads -- a machine's database, its report, the lateral CSV,
the run summary -- must resolve inside the case, so a link or junction in the evidence does not
lead the assistant out of the folders the analyst handed it.
"""

from __future__ import annotations

import csv
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from artifact_engine.core import sweep as sweepmod

MAX_ROWS = 200              # the most rows one call returns
DEFAULT_ROWS = 50
MAX_CELL = 300              # characters kept of one cell
SQL_SECONDS = 30            # a query running longer is interrupted
REPORT_CHARS = 8000         # report.txt characters per page
TAIL_LINES = 40             # output lines a run status carries
SWEEP_WAIT = 20             # seconds a sweep call waits before answering with its id

_ALLOWED = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
            getattr(sqlite3, "SQLITE_RECURSIVE", 33)}


class ToolError(ValueError):
    """A request the tools refuse, said in words the assistant can act on."""


def _cell(v):
    if isinstance(v, bytes):
        return f"<{len(v)} bytes>"
    if isinstance(v, str) and len(v) > MAX_CELL:
        return v[:MAX_CELL] + f"... (+{len(v) - MAX_CELL} chars)"
    return v


def _limit(limit: int) -> int:
    return max(1, min(int(limit or DEFAULT_ROWS), MAX_ROWS))


@dataclass
class _Run:
    id: str
    case: str
    kind: str
    proc: subprocess.Popen
    started: float
    output: deque = field(default_factory=lambda: deque(maxlen=TAIL_LINES))
    finished: float | None = None


@dataclass
class _SweepJob:
    """A sweep in a thread of the server. Hits are folded into groups machine by
    machine, so a common value (a user name in every log) costs a counter, not a
    list of every row it was in."""
    id: str
    case: str
    needles: list[str]
    started: float
    machines: int | None = None          # None while the case is still being walked
    groups: dict = field(default_factory=dict)
    searched: list[str] = field(default_factory=list)
    unreadable: list[dict] = field(default_factory=list)
    hidden: dict[str, int] = field(default_factory=dict)
    error: str = ""
    finished: float | None = None
    done: threading.Event = field(default_factory=threading.Event)


class Workspace:
    """The case folders an assistant may read and process."""

    def __init__(self, roots: list[Path], python: str | None = None) -> None:
        self.roots = [Path(r).resolve() for r in roots]
        if not self.roots:
            raise ToolError("no case root given")
        self.python = python or sys.executable
        self._runs: dict[str, _Run] = {}
        self._sweeps: dict[str, _SweepJob] = {}
        self._lock = threading.Lock()

    # --- where things are ---------------------------------------------------------

    def case_path(self, case: str) -> Path:
        """`case`, a folder directly under one of the roots, by its name; anything
        else -- a path, `..`, a nested name, a link out of the root -- is refused."""
        name = (case or "").strip()
        if not name:
            raise ToolError("name a case: list_cases() shows them")
        if any(c in name for c in "/\\:") or name in (".", ".."):
            raise ToolError("give the case by its folder name, as list_cases() shows it")
        for root in self.roots:
            p = (root / name).resolve()
            if p.parent == root and p.is_dir():
                return p
        raise ToolError(f"no case {name!r} under the roots: list_cases() shows them")

    @staticmethod
    def _inside(path: Path, case: Path) -> bool:
        try:
            return path.resolve().is_relative_to(case)
        except (OSError, ValueError):
            return False

    def _databases(self, case: str) -> list[tuple[str, Path]]:
        return self._databases_in(self.case_path(case))

    def _databases_in(self, path: Path) -> list[tuple[str, Path]]:
        return [(label, db) for label, db in sweepmod.find_case_databases(path)
                if self._inside(db, path)]

    def _machine_db(self, case: str, machine: str) -> Path:
        dbs = self._databases(case)
        for label, db in dbs:
            if label == machine:
                return db
        names = ", ".join(label for label, _ in dbs) or "none: run the case first"
        raise ToolError(f"no machine {machine!r} in {case!r}; machines: {names}")

    # --- read -------------------------------------------------------------------

    def list_cases(self) -> list[dict]:
        out = []
        for root in self.roots:
            if not root.is_dir():
                continue
            for d in sorted(p for p in root.iterdir()
                            if p.is_dir() and p.resolve().parent == root):
                summary = d / "run-summary.json"
                last: dict = {}
                if summary.is_file() and self._inside(summary, d.resolve()):
                    try:
                        s = json.loads(summary.read_text(encoding="utf-8"))
                        last = {k: s.get(k) for k in ("status", "finished_at", "duration_seconds")
                                if s.get(k) is not None}
                        if isinstance(s.get("totals"), dict):
                            last["totals"] = s["totals"]
                    except (OSError, ValueError):
                        last = {"status": "run-summary.json unreadable"}
                out.append({"case": d.name, "root": str(root),
                            "machines": len(self._databases(d.name)),
                            "last_run": last or None})
        return out

    def list_machines(self, case: str) -> list[dict]:
        out = []
        for label, db in self._databases(case):
            d = db.parent
            out.append({"machine": label, "db_mb": round(db.stat().st_size / 2**20, 1),
                        "report": (d / "report.txt").is_file(),
                        "findings": (d / "findings.csv").is_file()})
        return out

    @staticmethod
    def _open(db: Path) -> sqlite3.Connection:
        """`db` opened read-only: a write fails whatever the statement. A UNC path
        (a root on a share) is written `file:////server/share/...`: the
        `file://server/...` that `as_uri` gives is an authority SQLite refuses."""
        posix = db.as_posix()
        uri = ("file://" + urllib.parse.quote(posix, safe="/:$") if posix.startswith("//")
               else db.as_uri())
        return sqlite3.connect(uri + "?mode=ro", uri=True)

    def _connect(self, db: Path) -> sqlite3.Connection:
        """`_open`, with an authorizer that allows reading and nothing else."""
        conn = self._open(db)
        conn.set_authorizer(
            lambda action, *_: sqlite3.SQLITE_OK if action in _ALLOWED else sqlite3.SQLITE_DENY)
        return conn

    def list_tables(self, case: str, machine: str, name_contains: str = "") -> list[dict]:
        conn = self._connect(self._machine_db(case, machine))
        try:
            names = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            needle = name_contains.lower()
            out = []
            for n in names:
                if needle and needle not in n.lower():
                    continue
                rows = conn.execute(f'SELECT COUNT(*) FROM "{n.replace(chr(34), "")}"').fetchone()[0]
                out.append({"table": n, "rows": rows})
            return out
        finally:
            conn.close()

    def describe_table(self, case: str, machine: str, table: str, sample: int = 3) -> dict:
        res = self.query(case, machine, f'SELECT * FROM "{table.replace(chr(34), "")}"',
                         limit=max(1, min(int(sample or 3), 20)))
        return {"table": table, "columns": res["columns"], "rows_total": res.get("rows_total"),
                "sample": res["rows"]}

    def query(self, case: str, machine: str, sql: str, limit: int = DEFAULT_ROWS,
              offset: int = 0) -> dict:
        """One read-only SELECT on a machine's database, a page of its rows."""
        text = (sql or "").strip().rstrip(";").strip()
        if not text:
            raise ToolError("give a SELECT statement")
        if text.split(None, 1)[0].upper() not in ("SELECT", "WITH"):
            raise ToolError("only reading is allowed: one SELECT (or WITH ... SELECT); "
                            "no PRAGMA, ATTACH or write")
        limit, offset = _limit(limit), max(0, int(offset or 0))
        conn = self._connect(self._machine_db(case, machine))
        deadline = time.monotonic() + SQL_SECONDS
        conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10_000)
        try:
            cur = conn.execute(f"SELECT * FROM ({text}) LIMIT ? OFFSET ?", (limit + 1, offset))
            cols = [d[0] for d in cur.description]
            rows = [[_cell(v) for v in r] for r in cur.fetchall()]
            total = None
            if offset == 0 and len(rows) <= limit:
                total = len(rows)
            elif time.monotonic() < deadline:
                try:
                    total = conn.execute(f"SELECT COUNT(*) FROM ({text})").fetchone()[0]
                except sqlite3.Error:
                    total = None
        except sqlite3.DatabaseError as e:
            msg = str(e)
            if "interrupted" in msg:
                raise ToolError(f"the query ran past {SQL_SECONDS}s and was stopped: narrow it "
                                f"(a WHERE, fewer columns) or page with limit/offset") from None
            if "not authorized" in msg or "prohibited" in msg:
                raise ToolError("only reading is allowed: one SELECT, no PRAGMA, ATTACH "
                                "or write") from None
            raise ToolError(f"SQL error: {msg}") from None
        finally:
            conn.close()
        more = len(rows) > limit
        return {"columns": cols, "rows": rows[:limit], "offset": offset,
                "returned": min(len(rows), limit), "has_more": more, "rows_total": total}

    def findings(self, case: str, machine: str, limit: int = DEFAULT_ROWS,
                 offset: int = 0) -> dict:
        """The machine's flagged rows (findings.csv), most selective tables first."""
        db = self._machine_db(case, machine)
        path = db.parent / "findings.csv"
        if not path.is_file() or not self._inside(path, self.case_path(case)):
            return {"findings": [], "note": "no findings.csv: nothing flagged, or the run "
                                            "did not build this machine's outputs"}
        with path.open(encoding="utf-8", errors="replace", newline="") as fh:
            rows = list(csv.DictReader(fh))
        limit, offset = _limit(limit), max(0, int(offset or 0))
        page = [{k: _cell(v) for k, v in r.items()} for r in rows[offset:offset + limit]]
        return {"findings": page, "total": len(rows), "offset": offset,
                "has_more": offset + limit < len(rows),
                "hint": "each row is `SELECT * FROM <table> WHERE rowid = <rowid>` away"}

    def report(self, case: str, machine: str, offset: int = 0) -> dict:
        """A page of the machine's report.txt (log coverage first, then findings)."""
        path = self._machine_db(case, machine).parent / "report.txt"
        if not path.is_file() or not self._inside(path, self.case_path(case)):
            raise ToolError(f"no report.txt for {machine!r}")
        text = path.read_text(encoding="utf-8", errors="replace")
        offset = max(0, int(offset or 0))
        page = text[offset:offset + REPORT_CHARS]
        return {"text": page, "offset": offset, "total_chars": len(text),
                "next_offset": offset + len(page) if offset + len(page) < len(text) else None}

    def sweep(self, case: str, values: list[str], include_collection: bool = False,
              limit: int = DEFAULT_ROWS) -> dict:
        """Where each value appears across every machine of the case. The machines
        are `_databases`, so a junction in the evidence is not followed here either.
        Answers within `SWEEP_WAIT` seconds: finished, or still running with the id
        `sweep_result` collects it by -- the case is walked in the thread too, a
        large evidence tree takes a while. Nothing else at a time on the case: not
        a sweep, nor a run rebuilding the databases it reads."""
        needles, _ = sweepmod.merge_needles([str(v) for v in values or []])
        if not needles:
            raise ToolError("give one or more values to look for")
        path = self.case_path(case)
        with self._lock:
            self._refuse_busy(path)
            job = _SweepJob(uuid.uuid4().hex[:8], str(path), needles, time.time())
            self._sweeps[job.id] = job
        threading.Thread(target=self._sweep_job, args=(job, path, include_collection),
                         daemon=True).start()
        job.done.wait(SWEEP_WAIT)
        return self.sweep_result(job.id, limit)

    def _refuse_busy(self, path: Path) -> None:
        """Refuse work on `path` while a run or a sweep is on it, on a folder inside
        it or on one around it: a run deletes and rebuilds the databases a sweep
        reads, and two runs would write one tree. Called holding the lock."""
        def overlaps(other: Path) -> bool:
            return other == path or other.is_relative_to(path) or path.is_relative_to(other)

        for r in self._runs.values():
            if r.proc.poll() is None and overlaps(Path(r.case)):
                raise ToolError(f"a {r.kind} is already running on this case: "
                                f"run_status({r.id!r})")
        for j in self._sweeps.values():
            if not j.done.is_set() and overlaps(Path(j.case)):
                raise ToolError("a sweep is already running on this case: "
                                f"sweep_result({j.id!r})")

    def _sweep_job(self, job: _SweepJob, path: Path, include_collection: bool) -> None:
        try:
            dbs = self._databases_in(path)
            job.machines = len(dbs)
            for label, db in dbs:
                hits, why, hidden = sweepmod.sweep_database(label, db, job.needles,
                                                            include_collection)
                if why:
                    job.unreadable.append({"machine": label, "why": why})
                    continue
                for h in hits:
                    g = job.groups.setdefault(
                        (h.machine, h.table, h.column, h.needle),
                        {"machine": h.machine, "table": h.table, "column": h.column,
                         "value": h.needle, "hits": 0, "example": _cell(h.context)})
                    g["hits"] += 1
                if hidden:
                    job.hidden[label] = hidden
                job.searched.append(label)
        except Exception as e:  # noqa: BLE001 - said in sweep_result, not lost
            job.error = f"{type(e).__name__}: {e}"
        finally:
            job.finished = time.time()
            job.done.set()

    def sweep_result(self, sweep_id: str, limit: int = DEFAULT_ROWS) -> dict:
        """A sweep's answer, or how far it has got."""
        job = self._sweeps.get(sweep_id)
        if job is None:
            raise ToolError(f"no sweep {sweep_id!r} started by this server")
        out = {"sweep_id": job.id, "case": Path(job.case).name,
               "elapsed_s": round((job.finished or time.time()) - job.started)}
        if not job.done.is_set():
            return {**out, "state": "running", "machines_searched": len(job.searched),
                    "machines_total": job.machines,
                    "hint": "every table of every machine is read: ask sweep_result "
                            "again in a minute"}
        if job.error:
            return {**out, "state": "failed", "error": job.error,
                    "searched": job.searched}
        limit = _limit(limit)
        hits = sorted(job.groups.values(),
                      key=lambda g: (-g["hits"], g["machine"], g["table"]))
        found = {g["value"] for g in hits}
        return {**out, "state": "finished", "hits": hits[:limit], "groups_total": len(hits),
                "has_more": len(hits) > limit, "searched": job.searched,
                "not_found": [n for n in job.needles if n not in found],
                "unreadable": job.unreadable, "hidden_collection_rows": job.hidden}

    def lateral(self, case: str, user: str = "", host: str = "", suspicious_only: bool = False,
                limit: int = DEFAULT_ROWS, offset: int = 0) -> dict:
        """Rows of the case's lateral_movement.csv (who authenticated where), filtered."""
        path = self.case_path(case) / "lateral_movement.csv"
        if not path.is_file() or not self._inside(path, self.case_path(case)):
            return {"rows": [], "note": "no lateral_movement.csv: no logon events in the "
                                        "case, or `aeng lateral` has not run"}
        u, h = user.lower(), host.lower()
        with path.open(encoding="utf-8", errors="replace", newline="") as fh:
            rows = [r for r in csv.DictReader(fh)
                    if (not u or u in (r.get("user") or "").lower())
                    and (not h or h in (r.get("src") or "").lower()
                         or h in (r.get("dst") or "").lower())
                    and (not suspicious_only or (r.get("suspicious") or "").strip())]
        limit, offset = _limit(limit), max(0, int(offset or 0))
        return {"rows": [{k: _cell(v) for k, v in r.items()} for r in rows[offset:offset + limit]],
                "total": len(rows), "offset": offset, "has_more": offset + limit < len(rows)}

    # --- launch -----------------------------------------------------------------

    def _command(self, kind: str, case: Path, args: list[str]) -> list[str]:
        """`aeng <kind> -p <case>`, with the interpreter running this server."""
        return [self.python, "-m", "artifact_engine", kind, "-p", str(case), *args]

    def _start(self, case: str, kind: str, args: list[str]) -> dict:
        path = self.case_path(case)
        with self._lock:
            self._refuse_busy(path)
            env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
            proc = subprocess.Popen(
                self._command(kind, path, args),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                env=env, text=True, encoding="utf-8", errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            run = _Run(id=uuid.uuid4().hex[:8], case=str(path), kind=kind, proc=proc,
                       started=time.time())
            self._runs[run.id] = run
        threading.Thread(target=self._drain, args=(run,), daemon=True).start()
        return {"run_id": run.id, "case": case, "kind": kind,
                "hint": "processing takes minutes to hours: poll run_status(run_id)"}

    @staticmethod
    def _drain(run: _Run) -> None:
        for line in run.proc.stdout:
            run.output.append(line.rstrip())
        run.proc.wait()
        run.finished = time.time()

    def start_run(self, case: str, force: bool = False) -> dict:
        return self._start(case, "run", ["--force"] if force else [])

    def start_lateral(self, case: str) -> dict:
        return self._start(case, "lateral", [])

    def run_status(self, run_id: str) -> dict:
        run = self._runs.get(run_id)
        if run is None:
            raise ToolError(f"no run {run_id!r} started by this server: list_runs()")
        code = run.proc.poll()
        end = run.finished or time.time()
        out = {"run_id": run.id, "kind": run.kind, "case": Path(run.case).name,
               "state": "running" if code is None else ("finished" if code == 0 else
                                                        f"exited {code}"),
               "elapsed_s": round(end - run.started), "last_output": list(run.output)}
        if code is not None and run.kind == "run":
            summary = Path(run.case) / "run-summary.json"
            try:
                if not self._inside(summary, Path(run.case)):
                    raise OSError("outside the case")
                s = json.loads(summary.read_text(encoding="utf-8"))
                out["summary"] = {k: s.get(k) for k in ("status", "totals") if k in s}
            except (OSError, ValueError):
                pass
        return out

    def list_runs(self) -> list[dict]:
        return [{"run_id": r.id, "kind": r.kind, "case": Path(r.case).name,
                 "running": r.proc.poll() is None} for r in self._runs.values()]
