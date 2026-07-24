"""Phase 3 - Plan and run the parsers for all machines.

Execution model: a SINGLE global worker pool processes all tasks
(machine x volume x parser) at once, respecting dependencies by level. This way
no workers sit idle when one machine finishes before another: parallelism is
spread across the whole set, not per machine.

Writes one run.json per machine and shows a per-machine progress bar.
"""

from __future__ import annotations

import json
import logging
import shutil
import sys
import threading
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from dataclasses import asdict, dataclass
from itertools import zip_longest

from artifact_engine.config import Config
from artifact_engine.core import procs, runner
from artifact_engine.core.detector import Machine, Volume
from artifact_engine.core.progress import Progress
from artifact_engine.logging_setup import get_logger
from artifact_engine.models import ParserManifest

log = get_logger()

# Live-diagnostics cadence: how often the heartbeat samples in-flight tasks, and
# how long a task must have been running to be flagged as slow/possibly stuck.
_HEARTBEAT_EVERY = 10.0
_SLOW_AFTER = 20.0
# When the slowest in-flight task exceeds this, dump every thread's stack to the
# on-disk log (and again at most once per interval): a STUCK handler shows up as
# a frame inside its module -- the exact file:line of the hang, not just its name.
_STACK_DUMP_AFTER = 120.0


def _log_file_only(msg: str) -> None:
    """Emit a line ONLY to the on-disk log (never the console), so per-task
    tracing doesn't corrupt the live progress bars -- not even under `-v`, where
    a normal DEBUG log would print to stdout mid-repaint."""
    rec = log.makeRecord(log.name, logging.DEBUG, __name__, 0, msg, (), None)
    for h in log.handlers:
        if isinstance(h, logging.FileHandler):
            h.handle(rec)


def _dump_stacks() -> None:
    """Write every worker thread's current stack to the on-disk log. A stuck
    Python handler is caught red-handed: one thread's top frames sit inside its
    handler module, giving the exact file:line of the hang. Limits: only THREADS
    are visible (a process-pool child can't be introspected from the parent;
    thread pools are the common case) and a stuck EXTERNAL tool shows as its
    thread waiting in procs.run/communicate -- the parser name from the heartbeat
    plus that wait frame still identifies it."""
    frames = sys._current_frames()
    me = threading.get_ident()
    for t in threading.enumerate():
        f = frames.get(t.ident)
        if f is None or t.ident == me or t.daemon and "heartbeat" in t.name:
            continue
        stack = "".join(traceback.format_stack(f))
        _log_file_only(f"thread stack [{t.name}]:\n{stack}")


def _topo_order(parsers: list[ParserManifest]) -> list[ParserManifest]:
    """Topological order by `depends_on` (dependencies outside the set are ignored)."""
    by_id = {p.id: p for p in parsers}
    seen: set[str] = set()
    ordered: list[ParserManifest] = []

    def visit(p: ParserManifest) -> None:
        if p.id in seen:
            return
        seen.add(p.id)
        for dep in p.depends_on:
            if dep in by_id:
                visit(by_id[dep])
        ordered.append(p)

    for p in parsers:
        visit(p)
    return ordered


def _levels(parsers: list[ParserManifest]) -> dict[str, int]:
    """Level of each parser = length of its dependency chain (0 = no deps)."""
    by_id = {p.id: p for p in parsers}
    memo: dict[str, int] = {}

    def lvl(p: ParserManifest) -> int:
        if p.id in memo:
            return memo[p.id]
        memo[p.id] = 0  # break cycles
        deps = [by_id[d] for d in p.depends_on if d in by_id]
        memo[p.id] = 0 if not deps else 1 + max(lvl(d) for d in deps)
        return memo[p.id]

    return {p.id: lvl(p) for p in parsers}


def _applicable(machine: Machine, parsers: list[ParserManifest]) -> list[ParserManifest]:
    return [p for p in parsers
            if p.os in (machine.os, "any") and (p.on_vss or not machine.is_vss)]


# Manifest category -> DFIR output folder
_CATEGORY_DIR = {
    "filesystem": "Filesystem",
    "execution": "Execution",
    "eventlogs": "EventLogs",
    "registry": "Registry",
    "shellbags": "FilesystemAccess",   # shellbags = folder-access evidence; own folder, not buried in Registry/
    "systeminfo": "SystemInfo",
    "shell": "Shell",
    "browser": "Browser",
    "persistence": "Persistence",
    "search": "Search",
    "network": "Network",
    "processes": "Processes",
    "detections": "Detections",
    "web": "Web",
}


def _out_dir(machine: Machine, category: str):
    # LiveResponse stays JSON-native in its own `JSONs/` folder (sibling of CSVs),
    # deliberately outside CSVs/ so the CSV->db/xlsx consolidation never touches it.
    # VSS snapshots are their own machines, so there is no per-volume subfolder.
    if category == "liveresponse":
        return machine.path / "JSONs"
    return machine.path / "CSVs" / _CATEGORY_DIR.get(category, category or "Other")


def cleanup_outputs(machine: Machine) -> None:
    """Tidy a machine's output tree after parsing: drop leftover scratch dirs and
    an empty JSONs/ folder. Each parser isolates its run in a `.work_<id>/` dir
    that it rmtree's on completion, but that rmtree can be blocked mid-run by AV
    on Windows (and is skipped entirely for cached parsers), leaving empty scratch
    dirs behind; an empty JSONs/ is left on machines with no LiveResponse (the DC).
    Runs after the pool has joined, so there is no race with a live parser."""
    base = machine.path
    for root in (base / "CSVs", base / "JSONs"):
        if root.is_dir():
            for d in root.rglob(".work_*"):
                if d.is_dir():
                    shutil.rmtree(d, ignore_errors=True)
    js = base / "JSONs"
    try:
        if js.is_dir() and not any(js.iterdir()):
            js.rmdir()
    except OSError:
        pass


def _plan_pools(py: int, cmd: int, max_workers: int, parse_processes: bool) -> tuple[bool, int, int]:
    """Pool sizing -> (use_proc, proc_workers, thread_workers).

    #3: the process pool only spawns when python tasks outnumber the workers, so
    each worker (which re-imports the package on Windows spawn) amortises its
    startup over several tasks; below that python runs on threads (no spawn).
    #2: each pool is sized to its OWN load capped at max_workers -- not the total
    -- so the two pools don't both inflate to the full worker count (which
    doubled effective concurrency on mixed Windows+Linux batches)."""
    use_proc = parse_processes and py > max_workers
    proc_workers = min(max_workers, py) if use_proc else 0
    thread_load = cmd + (0 if use_proc else py)
    thread_workers = max(1, min(max_workers, thread_load)) if thread_load else 0
    return use_proc, proc_workers, thread_workers


@dataclass
class _Task:
    m_idx: int
    machine: Machine
    volume: Volume
    parser: ParserManifest
    level: int


# Module-level worker so it is picklable for the process pool. Returns the
# machine index alongside the result so the parent can update progress/state.
def _run_task(payload):
    m_idx, parser, evidence, out, tools, assets, mname, vname, force = payload
    ctx = runner.ParserContext(
        evidence=evidence, out=out, tools=tools, assets=assets,
        machine_name=mname, volume=vname, log=get_logger(),
    )
    return m_idx, runner.run_parser(parser, ctx, force=force)


def _write_manifest(machine: Machine, runs: list[runner.ParserRun]) -> None:
    data = {
        "machine": machine.name,
        "os": machine.os,
        "collector": machine.collector,
        "source": machine.source,
        "runs": [asdict(r) for r in runs],
    }
    try:
        (machine.path / "run.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError as e:
        log.warning(f"[!] could not write run.json for {machine.name}: {e}")


def run_all(machines: list[Machine], parsers: list[ParserManifest],
            cfg: Config, force: bool = False) -> list[tuple[Machine, list[runner.ParserRun]]]:
    """Run the parsers of all machines in a global pool. Returns (machine, runs)."""
    labels: list[str] = []
    totals: list[int] = []
    machine_runs: dict[int, list[runner.ParserRun]] = {}
    per_machine: list[list[_Task]] = []

    for i, m in enumerate(machines):
        applicable = _topo_order(_applicable(m, parsers))
        levels = _levels(applicable)
        labels.append(m.display or m.name)
        totals.append(len(applicable) * max(1, len(m.volumes)))
        machine_runs[i] = []
        per_machine.append(
            [_Task(i, m, vol, p, levels[p.id]) for vol in m.volumes for p in applicable]
        )

    # Interleave round-robin across machines so the global pool spreads work over
    # all machines at once (instead of draining one machine before the next).
    tasks: list[_Task] = [t for group in zip_longest(*per_machine) for t in group if t is not None]

    if not tasks:
        return [(m, []) for m in machines]

    progress = Progress(labels, totals)
    done = [0] * len(machines)

    def _payload(t: _Task):
        return (t.m_idx, t.parser, t.volume.path,
                _out_dir(t.machine, t.parser.category),
                cfg.tools_dir, cfg.assets_dir, t.machine.name, t.volume.name, force)

    # Pre-skip parsers already completed (.done marker present): account them
    # without dispatching, so a re-run doesn't pay the pool/process-spawn cost
    # just to have each worker return "already parsed".
    to_run: list[_Task] = []
    for t in tasks:
        if runner.is_cached(t.parser, _out_dir(t.machine, t.parser.category), force):
            machine_runs[t.m_idx].append(runner.cached_run(t.parser, t.volume.name))
            done[t.m_idx] += 1
        else:
            to_run.append(t)

    # Split the work by execution model:
    #  - python handlers are CPU-bound -> a process pool gives real parallelism
    #    past the GIL, but spawning a worker re-imports the package (costly on
    #    Windows), so it only pays off with enough tasks to amortise it (#3).
    #  - command parsers run external tools (GIL released; Ctrl+C needs
    #    procs.cancel_all to reach their Popens) -> threads.
    py = sum(1 for t in to_run if not t.parser.command)
    cmd = len(to_run) - py
    cached = len(tasks) - len(to_run)
    use_proc, proc_workers, thread_workers = _plan_pools(py, cmd, cfg.max_workers, cfg.parse_processes)

    if to_run:
        pools = ([f"{proc_workers} proc"] if proc_workers else []) + \
                ([f"{thread_workers} thread"] if thread_workers else [])
        log.info(f"    {len(to_run)} task(s) to run | {' + '.join(pools)}"
                 + (f" | {cached} cached" if cached else ""))
    else:
        log.info(f"    all {len(tasks)} task(s) already parsed (use --force to re-run)")

    progress.start()
    for i in range(len(machines)):   # reflect the pre-skips on the bars at once
        progress.update(i, done=done[i], status="done" if done[i] >= totals[i] else None)

    if to_run:
        thread_ex = ThreadPoolExecutor(max_workers=thread_workers) if thread_workers else None
        proc_ex = ProcessPoolExecutor(max_workers=proc_workers) if use_proc else None

        def _pool_for(t: _Task):
            return proc_ex if (proc_ex and not t.parser.command) else thread_ex

        # In-flight registry (task -> submit time), guarded so the heartbeat thread
        # can sample it while the main thread drains completions.
        pending: dict = {}
        pend_lock = threading.Lock()
        stop_hb = threading.Event()

        def _slowest():
            now = time.monotonic()
            with pend_lock:
                items = [(now - ts, t) for t, ts in pending.values() if now - ts >= _SLOW_AFTER]
            items.sort(key=lambda x: x[0], reverse=True)
            return items

        def _heartbeat():
            # Surface the slowest in-flight parser(s) both live (footer under the
            # bars) and on disk, so a hang/slow parser names itself even though
            # run.json is only written once the whole pool has joined. Past
            # _STACK_DUMP_AFTER the watchdog also dumps thread stacks: the log
            # then holds the exact file:line where a stuck handler sits.
            last_dump = 0.0
            while not stop_hb.wait(_HEARTBEAT_EVERY):
                slow = _slowest()
                if slow:
                    progress.set_note("slow: " + ", ".join(
                        f"{t.parser.id}@{t.machine.name} {int(e)}s" for e, t in slow[:3]))
                    _log_file_only("still running: " + "; ".join(
                        f"{t.parser.id} @{t.machine.name} {int(e)}s" for e, t in slow))
                    now = time.monotonic()
                    if slow[0][0] >= _STACK_DUMP_AFTER and now - last_dump >= _STACK_DUMP_AFTER:
                        _dump_stacks()
                        last_dump = now
                else:
                    progress.set_note("")

        hb = threading.Thread(target=_heartbeat, daemon=True, name="aeng-heartbeat")
        hb.start()
        try:
            # By dependency level; the common case is a single level (maximum parallelism)
            for level in sorted({t.level for t in to_run}):
                futs = {}
                for t in [x for x in to_run if x.level == level]:
                    fut = _pool_for(t).submit(_run_task, _payload(t))
                    with pend_lock:
                        pending[fut] = (t, time.monotonic())
                    futs[fut] = t
                for fut in as_completed(futs):
                    with pend_lock:
                        pending.pop(fut, None)
                    m_idx, result = fut.result()
                    machine_runs[m_idx].append(result)
                    done[m_idx] += 1
                    status = "done" if done[m_idx] >= totals[m_idx] else None
                    progress.update(m_idx, done=done[m_idx], status=status)
                    _log_file_only(f"done {result.parser_id} @{machines[m_idx].name} "
                                   f"{result.status} {result.duration_s}s")
        except BrokenProcessPool:
            # A worker process died abruptly (killed, out of memory, or the
            # evidence tree was renamed/deleted mid-run). The raw exception says
            # nothing useful -- name the in-flight tasks and the likely causes.
            now = time.monotonic()
            with pend_lock:
                stuck = sorted(((now - ts, t) for t, ts in pending.values()),
                               key=lambda x: x[0], reverse=True)
            stop_hb.set()
            progress.set_note("")
            progress.stop()
            log.error("[!] a parser worker process died abruptly. In flight:")
            for e, t in stuck[:10]:
                log.error(f"    {t.parser.id} @{t.machine.name}  {int(e)}s")
            _log_file_only("BrokenProcessPool with in-flight: " + "; ".join(
                f"{t.parser.id} @{t.machine.name} {int(e)}s" for e, t in stuck))
            log.error("    likely causes: out of memory; evidence files renamed/"
                      "deleted while the run was going; antivirus killing workers.")
            log.error("    fix the cause and re-run: completed parsers are cached "
                      "(.done) and will be skipped.")
            procs.cancel_all()
            if thread_ex:
                thread_ex.shutdown(wait=False, cancel_futures=True)
            if proc_ex:
                proc_ex.shutdown(wait=False, cancel_futures=True)
            raise SystemExit(1) from None
        except KeyboardInterrupt:
            # Name whatever was still running when the analyst gave up: the prime
            # suspect for "it just hangs and never finishes, with no error".
            now = time.monotonic()
            with pend_lock:
                stuck = sorted(((now - ts, t) for t, ts in pending.values()),
                               key=lambda x: x[0], reverse=True)
            stop_hb.set()
            progress.set_note("")
            progress.stop()
            if stuck:
                log.warning(f"[!] {len(stuck)} task(s) still running at cancel "
                            f"(prime suspects for the hang):")
                for e, t in stuck[:10]:
                    log.warning(f"    {t.parser.id} @{t.machine.name}  {int(e)}s")
                _log_file_only("cancelled with in-flight: " + "; ".join(
                    f"{t.parser.id} @{t.machine.name} {int(e)}s" for e, t in stuck))
                _dump_stacks()   # exact file:line of whatever was stuck -> log
                log.warning("    thread stacks written to aeng-run.log")
            procs.cancel_all()
            if thread_ex:
                thread_ex.shutdown(wait=False, cancel_futures=True)
            if proc_ex:
                proc_ex.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            stop_hb.set()
        if thread_ex:
            thread_ex.shutdown(wait=True)
        if proc_ex:
            proc_ex.shutdown(wait=True)
        progress.set_note("")
    progress.stop()

    results: list[tuple[Machine, list[runner.ParserRun]]] = []
    for i, m in enumerate(machines):
        _write_manifest(m, machine_runs[i])
        results.append((m, machine_runs[i]))
    return results
