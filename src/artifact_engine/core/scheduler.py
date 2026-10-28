"""Phase 3 - Plan and run the parsers for all machines.

Execution model: one global set of workers (a process pool and a thread pool)
processes every task (machine x volume x parser); a task is ready once its own
machine's dependencies have finished (v0.7.130), and ready tasks are handed to
the pools only as workers free up -- heavy parsers first, then machine by machine
(v0.7.133). No worker sits idle while any machine has work, and each machine's
outputs are complete as it finishes rather than all at the end.

Writes one run.json per machine and shows one progress bar per host (its live
volume, snapshots, LiveResponse, other acquisitions and memory share a line; see
console_groups).
"""

from __future__ import annotations

import heapq
import json
import shutil
import signal
import sys
import threading
import time
import traceback
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, ThreadPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool
from dataclasses import asdict, dataclass
from itertools import zip_longest

from artifact_engine.config import Config
from artifact_engine.core import asset_state, console_groups, procs, retired, runner
from artifact_engine.core.detector import Machine, Volume
from artifact_engine.core.memory import POINTER as MEMORY_POINTER
from artifact_engine.core.progress import Progress
from artifact_engine.logging_setup import get_logger, log_file_only
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
    """Per-task tracing that never reaches the console -- see logging_setup for
    why. Kept as a local alias so the call sites read unchanged."""
    log_file_only(msg, log)


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
    # A memory unit is a folder holding a pointer, never a filesystem: the disk
    # parsers would only queue there to skip, and seventy "skipped" lines would
    # bury the memory parsers in its summary (v0.7.88). And only its own kernel's:
    # a Linux image is not asked the Windows plugins (v0.7.113).
    if machine.collector == "memory":
        return [p for p in parsers
                if MEMORY_POINTER in p.requires and p.os in (machine.os, "any")]
    # And the other way round (v0.7.115): a disk or collection machine has no
    # image, so every memory parser of its OS only queued there to skip, on each
    # machine and VSS snapshot, and a skip is dispatched again on every run.
    return [p for p in parsers
            if p.os in (machine.os, "any") and (p.on_vss or not machine.is_vss)
            and MEMORY_POINTER not in p.requires]


# Manifest category -> DFIR output folder
_CATEGORY_DIR = {
    "filesystem": "Filesystem",
    "execution": "Execution",
    "eventlogs": "EventLogs",
    "registry": "Registry",
    # shellbags (reg_shellbags, removed in v0.7.161): kept so core/retired finds
    # the folder its tables were left in
    "shellbags": "FilesystemAccess",
    "systeminfo": "SystemInfo",
    "shell": "Shell",
    "browser": "Browser",
    "persistence": "Persistence",
    "search": "Search",
    "network": "Network",
    "processes": "Processes",
    "detections": "Detections",
    "web": "Web",
    # A container is a system of its own, invisible to every host-level parser
    # here, so its tables get a folder of their own rather than being filed
    # under the host's processes (v0.7.84).
    "containers": "Containers",
    # Volatility 3 over a memory image: a unit of its own (v0.7.88).
    "memory": "Memory",
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


def _worker_init() -> None:
    """Give a pool worker the Ctrl+C cleanup the parent cannot perform for it.

    `procs._active` is module state and a spawned worker gets its own copy, so the
    parent's `cancel_all()` only ever reaches Popens the PARENT opened. Routing
    `command:` parsers to threads was done for exactly that reason -- but three
    parsers (hayabusa, sum, usn) are Python handlers with no `command:`,
    so they run here and open their tool from here, outside that guarantee.

    Ctrl+C in a console already reaches those tools directly: they inherit the
    console process group, so CTRL_C_EVENT is delivered to them too. What the
    parent cannot do for them is the part `cancel_all` exists for -- escalating to
    kill() when a tool ignores the request and keeps reading the evidence after the
    engine has said it stopped. This installs that escalation where the Popens
    actually are, then defers to the previous handler so nothing else changes.
    """
    previous = signal.getsignal(signal.SIGINT)

    def _cancel_then_default(signum, frame):
        procs.cancel_all()
        if callable(previous):
            previous(signum, frame)

    try:
        signal.signal(signal.SIGINT, _cancel_then_default)
    except (ValueError, OSError):
        # Not this process's main thread, or no console to deliver on. The worker
        # is still perfectly able to parse; it just cannot clean up after itself.
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


def _key(t: _Task) -> tuple:
    return (t.m_idx, str(t.volume.path), t.parser.id)


def _machine_key(t: _Task) -> tuple:
    return (t.m_idx, t.parser.id)


def _dependencies(tasks: list[_Task]) -> dict[tuple, list[tuple]]:
    """For each task, one entry per task it waits for: a dependency of its own
    machine, on any of that machine's volumes, that is itself among `tasks` (a
    cached one has nothing to wait for). Only a dependency at a LOWER level
    counts, so a cycle -- which `_levels` breaks by putting its back edge at 0 --
    cannot leave a task waiting for good, as the level-by-level loop never did."""
    present: dict[tuple, list[_Task]] = {}
    for t in tasks:
        present.setdefault(_machine_key(t), []).append(t)
    out: dict[tuple, list[tuple]] = {}
    for t in tasks:
        # dict.fromkeys: an id named twice is still one dependency to wait for
        out[_key(t)] = [(t.m_idx, dep) for dep in dict.fromkeys(t.parser.depends_on)
                        for d in present.get((t.m_idx, dep), []) if d.level < t.level]
    return out


def _marker_mtime(machine: Machine, parser: ParserManifest) -> float | None:
    try:
        return runner.marker_path(_out_dir(machine, parser.category), parser.id).stat().st_mtime
    except OSError:
        return None


def _older_than_a_dependency(t, by_id: dict) -> bool:
    """True when a parser this one reads completed after this one did: its
    tables were built from what that parser wrote before (v0.7.96)."""
    mine = _marker_mtime(t.machine, t.parser)
    if mine is None:
        return False
    for dep in t.parser.depends_on:
        d = by_id.get(dep)
        theirs = _marker_mtime(t.machine, d) if d is not None else None
        if theirs is not None and theirs > mine:
            return True
    return False


# Module-level worker so it is picklable for the process pool. Returns the
# machine index alongside the result so the parent can update progress/state.
def _run_task(payload):
    m_idx, parser, evidence, out, tools, assets, mname, vname, force, internal = payload
    ctx = runner.ParserContext(
        evidence=evidence, out=out, tools=tools, assets=assets,
        machine_name=mname, volume=vname, log=get_logger(),
        internal_networks=internal,
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


def write_manifests(results: list[tuple[Machine, list[runner.ParserRun]]]) -> None:
    """(Re)write every machine's run.json. Public so a caller can refresh them after
    a LATE rename -- a loose EVTX drop only learns its real host name once its events
    are parsed (detector.name_evtx_drops), i.e. after run_all wrote the manifests."""
    for machine, runs in results:
        _write_manifest(machine, runs)


def run_all(machines: list[Machine], parsers: list[ParserManifest],
            cfg: Config, force: bool = False) -> list[tuple[Machine, list[runner.ParserRun]]]:
    """Run the parsers of all machines in a global pool. Returns (machine, runs)."""
    # What a parser removed from the engine left in these machines goes first, so
    # nothing below consolidates a table no parser produces any more.
    left = retired.sweep(machines, _out_dir, parsers=parsers)
    totals: list[int] = []
    machine_runs: dict[int, list[runner.ParserRun]] = {i: [] for i in range(len(machines))}
    per_machine: list[list[_Task]] = []
    # One it could not delete is consolidated this run: an error of that id on that
    # machine, so the run's verdict and run-summary say so, not only a log line.
    for i, pid, name in left:
        vol = machines[i].volumes[0].name if machines[i].volumes else ""
        machine_runs[i].append(runner.ParserRun(
            pid, vol, "error", 0.0,
            f"removed parser: could not delete {name} (open in another program?); "
            "it is consolidated this run and retried next run"))

    for i, m in enumerate(machines):
        applicable = _topo_order(_applicable(m, parsers))
        levels = _levels(applicable)
        totals.append(len(applicable) * max(1, len(m.volumes)))
        per_machine.append(
            [_Task(i, m, vol, p, levels[p.id]) for vol in m.volumes for p in applicable]
        )

    # Round-robin across machines: since v0.7.133 only the final tie-break of the
    # dispatch order, which `_pump` sets (heavy parsers first, then lowest machine).
    tasks: list[_Task] = [t for group in zip_longest(*per_machine) for t in group if t is not None]

    if not tasks:
        return [(m, machine_runs[i]) for i, m in enumerate(machines)]

    # One bar per HOST, not per machine: its live volume, snapshots, a second
    # acquisition and its memory share a line (v0.7.122). Counters stay per
    # machine; `_show` sums a host's members onto its bar.
    groups = console_groups.group(machines)
    line_of = {i: g for g, (_label, members) in enumerate(groups) for i in members}
    progress = Progress([text for text, _ in groups],
                        [sum(totals[i] for i in members) for _, members in groups],
                        noun="hosts")
    done = [0] * len(machines)

    def _show(m_idx: int) -> None:
        g = line_of[m_idx]
        members = groups[g][1]
        finished = all(done[i] >= totals[i] for i in members)
        progress.update(g, done=sum(done[i] for i in members),
                        status="done" if finished else None)

    def _payload(t: _Task):
        return (t.m_idx, t.parser, t.volume.path,
                _out_dir(t.machine, t.parser.category),
                cfg.tools_dir, cfg.assets_dir, t.machine.name, t.volume.name,
                # A stale parser is forced: `run_parser` checks its own marker
                # again and would answer "cached" without running it.
                force or (t.m_idx, str(t.volume.path), t.parser.id) in stale_keys,
                # A tuple, not the list: this crosses into a process-pool worker.
                tuple(cfg.internal_networks))

    # Pre-skip parsers already completed (.done marker present): account them
    # without dispatching, so a re-run doesn't pay the pool/process-spawn cost
    # just to have each worker return "already parsed".
    #
    # A parser whose own fingerprint is unchanged is still NOT cached when
    # something it depends on runs again: it reads that parser's tables, and the
    # ones it built last time came from the old ones (v0.7.96). Measured: a
    # changed alert_mem_yara re-ran and the mem_findings built on it stayed cached, so
    # the alerts kept the severities of the run before. `tasks` keeps each
    # machine's topological order, so this also carries down a chain.
    #
    # "Runs again" means it wrote a new marker, which is only known once it has
    # finished: a dependency that is dispatched but ends skipped or failed (no
    # Sysmon channel, an image with no kernel) changed nothing, and treating its
    # dispatch as a change would re-run its dependents on every run. So a
    # dependent that is cached on its own fingerprint but has a dependency in
    # this run is `pending`: when its dependencies have finished (`_release`) it
    # re-runs only if a dependency's marker is now newer than its own,
    # and is accounted cached otherwise. A dependency that re-ran in an EARLIER
    # run counts by the same test -- what a case processed before this check
    # existed is left holding. A dependent forced this way that then fails keeps
    # its older marker and is retried next run, as any failed parser is.
    by_id = {p.id: p for p in parsers}
    to_run: list[_Task] = []
    rerun: set[tuple] = set()
    stale_keys: set[tuple] = set()
    pending_keys: set[tuple] = set()
    for t in tasks:
        here = (t.m_idx, str(t.volume.path))
        key = (*here, t.parser.id)
        if _older_than_a_dependency(t, by_id):
            stale_keys.add(key)
        elif runner.is_cached(t.parser, _out_dir(t.machine, t.parser.category), force):
            if not asset_state.unchanged(t.parser, _out_dir(t.machine, t.parser.category),
                                         cfg.assets_dir):
                # a list it reads was edited: run it, forced past its own marker
                stale_keys.add(key)
            elif not any((*here, dep) in rerun for dep in t.parser.depends_on):
                machine_runs[t.m_idx].append(runner.cached_run(t.parser, t.volume.name))
                done[t.m_idx] += 1
                continue
            else:
                pending_keys.add(key)
        to_run.append(t)
        rerun.add(key)

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
        _show(i)

    if to_run:
        thread_ex = ThreadPoolExecutor(max_workers=thread_workers) if thread_workers else None
        proc_ex = (ProcessPoolExecutor(max_workers=proc_workers, initializer=_worker_init)
                   if use_proc else None)

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
        # Each task is ready as soon as ITS dependencies have finished, on its
        # own machine (v0.7.130). Until then a whole dependency level waited for
        # the slowest task of that level on ANY machine: measured on a
        # 15-machine case, one 28-minute DeepBlue held every machine's level-1
        # parsers for ~15 minutes while nothing else ran.
        #
        # Ready tasks wait HERE, not in the pools' queues, and a pool is handed
        # one only when it has a free worker (v0.7.133): heavy parsers first,
        # then the lowest machine. Handed everything at once, the pools ran it
        # first come first served, so a dependent released late sat behind every
        # other machine's queued work and all 29 machines of a measured case
        # finished within the last 90 s of a 946 s parse. Machine by machine,
        # each one's outputs are ready as it finishes; heavy ones first, so no
        # 10-minute parser starts late and stretches the tail.
        waiting_on = _dependencies(to_run)
        unblocks: dict[tuple, list[_Task]] = {}
        for t in to_run:
            for dep in set(waiting_on[_key(t)]):
                unblocks.setdefault(dep, []).append(t)
        left = {_key(t): len(waiting_on[_key(t)]) for t in to_run}
        futs: dict = {}
        asset_states: dict[tuple, str] = {}
        released: set[tuple] = set()
        order = {_key(t): i for i, t in enumerate(to_run)}
        by_key = {_key(t): t for t in to_run}
        lanes = {"proc": proc_ex, "thread": thread_ex}
        cap = {"proc": max(1, proc_workers), "thread": max(1, thread_workers)}
        busy = {"proc": 0, "thread": 0}
        ready: dict[str, list] = {"proc": [], "thread": []}

        def _lane(t: _Task) -> str:
            return "proc" if (proc_ex and not t.parser.command) else "thread"

        def _pump() -> None:
            """Hand each pool its next tasks, while it has free workers."""
            for lane, heap in ready.items():
                while heap and busy[lane] < cap[lane]:
                    t = by_key[heapq.heappop(heap)[-1]]
                    # the state of the lists it reads as it starts, recorded when it
                    # ends: one edited while it runs is a change next time
                    out = _out_dir(t.machine, t.parser.category)
                    asset_states[_key(t)] = (asset_state.digest(t.parser, cfg.assets_dir),
                                             asset_state.begin(out, t.parser.id))
                    fut = lanes[lane].submit(_run_task, _payload(t))
                    busy[lane] += 1
                    with pend_lock:
                        pending[fut] = (t, time.monotonic())
                    futs[fut] = t

        def _release(t: _Task) -> list[_Task]:
            """Dispatch `t`, or account it cached; the tasks it finished, if any.
            Once only: a cascade of cached releases can reach a task the loop
            below is still about to start."""
            key = _key(t)
            if key in released:
                return []
            released.add(key)
            if key in pending_keys:
                if not _older_than_a_dependency(t, by_id):
                    machine_runs[t.m_idx].append(runner.cached_run(t.parser, t.volume.name))
                    done[t.m_idx] += 1
                    _show(t.m_idx)
                    return [t]
                stale_keys.add(key)
            heavy = 0 if t.parser.weight == "heavy" else 1
            heapq.heappush(ready[_lane(t)], (heavy, t.m_idx, order[key], key))
            return []

        def _finished(t: _Task) -> None:
            """`t` is done (ran, failed or cached): release what waited on it."""
            stack = [t]
            while stack:
                for child in unblocks.get(_machine_key(stack.pop()), []):
                    left[_key(child)] -= 1
                    if left[_key(child)] == 0:
                        stack += _release(child)

        try:
            for t in to_run:
                if left[_key(t)] == 0:
                    for cached in _release(t):
                        _finished(cached)
            _pump()
            while futs:
                finished, _ = wait(list(futs), return_when=FIRST_COMPLETED)
                for fut in finished:
                    t = futs.pop(fut)
                    busy[_lane(t)] -= 1
                    with pend_lock:
                        pending.pop(fut, None)
                    m_idx, result = fut.result()
                    # Say here what the parser said there. A pool worker's logger
                    # has no handlers, so the call it made reached nothing; this is
                    # the first point in the run where it can actually be written.
                    runner.replay_logs(result)
                    if _key(t) in asset_states:
                        started_with, before = asset_states.pop(_key(t))
                        # only `ok` applied the lists: a skip leaves the old tables,
                        # whatever skipped it (a missing module, the lists deleted)
                        asset_state.record(_out_dir(t.machine, t.parser.category), t.parser.id,
                                           started_with if result.status == "ok" else before)
                    machine_runs[m_idx].append(result)
                    done[m_idx] += 1
                    _show(m_idx)
                    _log_file_only(f"done {result.parser_id} @{machines[m_idx].name} "
                                   f"{result.status} {result.duration_s}s")
                    if result.trace:
                        # Written HERE, in the parent, because the worker that
                        # produced it has no log handlers to write it with.
                        _log_file_only(f"traceback {result.parser_id} "
                                       f"@{machines[m_idx].name}: {result.trace}")
                    _finished(t)
                _pump()
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
