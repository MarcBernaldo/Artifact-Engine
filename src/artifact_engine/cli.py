"""Artifact Engine command-line entry point."""

from __future__ import annotations

import argparse
import getpass
import logging
import multiprocessing
import os
import platform
import queue
import re
import sys
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path

from artifact_engine import __version__
from artifact_engine.config import Config, install_dir, load_config
from artifact_engine.core import (
    consolidate,
    extractor,
    hashing,
    pipeline,
    procs,
    report,
    scheduler,
    sweep,
)
from artifact_engine.core.hashing import fmt_size
from artifact_engine.core.progress import Progress
from artifact_engine.logging_setup import (
    RAZER_GREEN,
    console_supports_color,
    get_logger,
    log_file_only,
    setup_logging,
)
from artifact_engine.registry import load_parsers, load_profiles

log = get_logger()

# Exit codes. 0 clean, 1 the command could not do its job at all, 130 interrupted:
#
# 2 is the one worth naming. It means the command RAN and its answer is INCOMPLETE:
# for `run`, a parser errored or an acquisition did not extract whole; for `sweep`,
# a machine could not be searched. Not a failure, and not a clean result either, and
# the difference is invisible to anything that only reads the exit code. Whatever
# produces it must also say on the console what was missed.
EXIT_INCOMPLETE = 2


def interpreter_risks_memoryview_crash(name: str = os.name, version=sys.version_info) -> bool:
    """True on an interpreter that can kill a run outright, with no error at all.

    CPython 3.10 on Windows: the cyclic collector runs `tp_clear` on a `memoryview`
    that still has a buffer exported, `memory_clear()` throws away the error
    `_memory_release()` hands back and clears `mbuf` regardless, and the NEXT
    release dereferences the resulting NULL (`--self->mbuf->exports`). The parent
    dies with 0xC0000005, no traceback, no last log line.

    The views come from the process pool's own pipes -- every overlapped write
    holds a `Py_buffer` on its source -- so it only bites when that pool is used.
    Verified by reproduction: 3.10.11 raises `BufferError: memoryview has 1
    exported buffer` from tp_clear and then faults; 3.13.14 never reaches it.
    Only 3.10 is claimed here because only 3.10 was measured; 3.11 and 3.12 were
    not tested either way.
    """
    return name == "nt" and version[:2] == (3, 10)


def _warn_interpreter(cfg: Config) -> None:
    """Warn about the crash-prone interpreter AND take the process pool away.

    The detection existed and only ever printed; the flag that avoids the fault
    was left for the analyst to find in a warning among hundreds of startup
    lines. Since the failure mode is the run dying with no error at all, and the
    pool's own pipes are what reach the bug, turning it off is the only
    behaviour that matches the severity -- the same call already made for the
    right-click menu, which refuses to register this interpreter at all.
    """
    if not cfg.parse_processes or not interpreter_risks_memoryview_crash():
        return
    log.warning("[!] Python 3.10 on Windows can end this run with no error at all: a "
                "known interpreter bug (null dereference in _memory_release) is "
                "reached through the process pool's pipes.")
    cfg.parse_processes = False
    log.warning("    Process pool DISABLED for this run, which is what avoids it; task "
                "concurrency halves unless you raise max_workers. Parsed output "
                "survives the fault anyway -- re-running WITHOUT --force resumes from "
                "the .done markers. To get the pool back, run a newer Python "
                "(verified clean on 3.13).")


def _log_version() -> None:
    """Record the tool version + interpreter/OS in the on-disk run log. The
    banner shows the version on the console only; putting it in the LOG makes a
    shared aeng-run.log self-identifying (which build produced these outputs),
    so 'missing outputs' reports can be pinned to a version instead of guessed."""
    log.info(f"[=] Artifact Engine v{__version__} | Python {platform.python_version()}"
             f" | {platform.system()} {platform.release()}")


def _log_config(cfg: Config) -> None:
    """Record WHICH config is in force, and the settings that change what gets
    parsed and produced.

    Two files can layer (the tool's own as the baseline, a per-case one over it),
    so all of them are named in order rather than just the winner. `avoid_vss`
    alone is the difference between parsing a host's shadow copies and ignoring
    them; left unlogged, the only way to tell which settings produced a set of
    outputs is to infer it from what is missing.
    """
    if cfg.sources:
        for i, src in enumerate(cfg.sources):
            label = "Config" if i == 0 else "     +"    # the second one overrides
            log.info(f"[=] {label}: {src}")
    else:
        log.info(f"[=] Config: built-in defaults (none found beside the tool "
                 f"or in {Path.cwd()})")
    log.info(f"[=] workers {cfg.max_workers} | avoid_vss {str(cfg.avoid_vss).lower()} | "
             f"merge_vss {str(cfg.merge_vss).lower()} | db {str(cfg.emit_db).lower()} | "
             f"xlsx {str(cfg.emit_xlsx).lower()}")


BANNER = rf"""
   _         _   _  __         _     ___           _
  /_\  _ _  | |_(_)/ _|__ _ __| |_  | __|_ _  __ _(_)_ _  ___
 / _ \| '_| |  _| |  _/ _` / _|  _| | _|| ' \/ _` | | ' \/ -_)
/_/ \_\_|    \__|_|_| \__,_\__|\__| |___|_||_\__, |_|_||_\___|
                                             |___/   v{__version__}
"""


# --------------------------------------------------------------------------- #
# Command: run
# --------------------------------------------------------------------------- #
def _unit_label(unit: consolidate.Unit) -> str:
    """Console label for a consolidation unit. A merged host shows how many volumes
    went into it, so the analyst can see at a glance that one bar covers eleven."""
    base = unit.primary.display or unit.primary.name
    return f"{base} +{len(unit.members) - 1} VSS" if unit.merged else base


def _report_stale(units, root: Path) -> None:
    """Name every per-volume output an earlier, unmerged run left behind.

    Nothing is removed -- deleting inside a case is the analyst's call -- but a
    count and one example are not something anyone can act on, so the EXACT list
    goes to stale-outputs.txt at the case root (see consolidate.write_stale_list).
    The size is worth showing: these are whole per-snapshot databases, and on a
    host with eleven volumes they are the bulk of what the case folder holds."""
    stale = [p for u, _ in units for p in consolidate.stale_outputs(u)]
    dest = consolidate.write_stale_list(stale, root)
    if not dest:
        return
    total = 0
    for p in stale:
        try:
            total += p.stat().st_size
        except OSError:                 # vanished between the scan and here
            pass
    log.warning(f"[!] {len(stale)} per-volume output(s) from an earlier unmerged run are "
                f"still on disk ({fmt_size(total)}); this run does NOT rebuild them")
    log.info(f"    exact list -> {dest.name}  (nothing was deleted)")


def _consolidate_all(results, cfg: Config, root: Path, force: bool = False) -> None:
    """Build the configured outputs (.db/.xlsx) + report for all machines, with a
    per-unit progress bar. Each bar advances through the read/.db pass (one step
    per input file) and, when emit_xlsx, the .xlsx pass (one step per sheet) -- the
    latter dominates, as xlsxwriter writes cell by cell.

    A "unit" is one machine, or -- with merge_vss -- a host's live volume together
    with its shadow copies, folded into a single .db/.xlsx/report.txt (see
    consolidate.plan_units). Merging is also FASTER than not merging: the .xlsx
    pass, which dominates consolidation, runs once per host instead of once per
    snapshot.

    Consolidation is almost entirely pure-Python (GIL-bound: the .xlsx pass barely
    overlaps on threads), so with more than one unit it runs in a PROCESS pool
    for real parallelism -- each unit is independent (its own .db/.xlsx). Workers
    push progress through a manager queue that a drain thread applies to the bars;
    a single unit (or parse_processes=false) stays in-process on threads."""
    if not results:
        return
    units = consolidate.plan_units(results, merge_vss=cfg.merge_vss)
    labels = [_unit_label(u) for u, _ in units]
    # Outputs an earlier, unmerged run left inside the snapshot folders, so a stale
    # VSS3/HOST.db is not mistaken for this run's output.
    _report_stale(units, root)
    # Steps per unit: inputs (read/db pass) plus, when emit_xlsx, the sheets
    # (<= inputs). Counting inputs is a cheap glob; the few giant tables that skip
    # the .xlsx leave slack that the per-unit done marker snaps to full.
    mult = 2 if cfg.emit_xlsx else 1
    totals = [max(1, mult * consolidate.count_unit_inputs(u)) for u, _ in units]
    progress = Progress(labels, totals)
    done = [0] * len(units)

    workers = max(1, min(cfg.max_workers, len(units)))
    use_proc = cfg.parse_processes and workers > 1
    manager = multiprocessing.Manager() if use_proc else None
    q = manager.Queue() if manager else queue.Queue()

    # The drain thread is the SOLE writer of the bars: workers enqueue their own
    # ticks, so per machine the steps and the final done marker arrive in order
    # (no race with the result loop).
    def _drain() -> None:
        while True:
            item = q.get()
            if item is None:
                return
            idx, step = item
            if step:
                done[idx] = min(done[idx] + 1, totals[idx])
                progress.update(idx, done=done[idx])
            else:
                progress.update(idx, done=totals[idx], status="done")

    progress.start()
    drainer = threading.Thread(target=_drain, daemon=True)
    drainer.start()
    pool = ProcessPoolExecutor if use_proc else ThreadPoolExecutor
    ex = pool(max_workers=workers)
    stats: list[dict] = [{} for _ in units]
    failed: list[str] = []      # reported to the console once the bars are gone
    try:
        futs = {ex.submit(consolidate.consolidate_unit, i, u, q, cfg.emit_db, cfg.emit_xlsx, force): i
                for i, (u, _runs) in enumerate(units)}
        for fut in as_completed(futs):
            _idx, err, st = fut.result()
            stats[_idx] = st
            if err:
                # the bars are live: to the log file only, or the repaint
                # anchor desyncs and every later frame stacks on screen
                log_file_only(f"FAILED consolidation {units[_idx][0].name}: {err}")
                failed.append(units[_idx][0].name)
    except KeyboardInterrupt:
        procs.cancel_all()
        ex.shutdown(wait=False, cancel_futures=True)
        q.put(None)
        drainer.join(timeout=1)
        progress.stop()
        if manager:
            manager.shutdown()
        raise
    ex.shutdown(wait=True)
    q.put(None)                 # all workers done -> let the drainer finish the queue
    drainer.join(timeout=5)
    progress.stop()
    if manager:
        manager.shutdown()
    # Now that the bars are down, stdout is ours again. Deferring the message is
    # the point; dropping it would hide a unit whose .db never got built.
    for name in failed:
        log.error(f"[!] FAILED consolidation {name} (detail in aeng-run.log)")
    # Say which units were skipped and on what basis. "It finished fast" is not an
    # answer an analyst can act on; "unchanged, 414 inputs" is.
    skipped = [(u.name, st) for (u, _r), st in zip(units, stats) if st.get("cached")]
    if skipped:
        log.info(f"[=] {len(skipped)} unit(s) unchanged since the last build, not rebuilt "
                 f"(--force rebuilds anyway):")
        for name, st in skipped:
            log.info(f"    {name}: {st.get('inputs', 0)} input(s), all identical")

    # report.txt per unit, in the parent: cheap (text only), keeps logging here,
    # and lets the pool worker stay pure/picklable.
    for (u, runs), st in zip(units, stats):
        try:
            report.build(u.primary, runs, out_dir=u.path,
                         volume_labels=u.labels if u.merged else None, stats=st,
                         db_path=u.path / f"{u.name}.db")
        except Exception as e:  # noqa: BLE001 - one unit must not abort the rest
            log.error(f"    FAILED report {u.name}: {e}")
        if st.get("merged") and st.get("total_rows"):
            log.info(f"    {u.name}: {len(u.members)} volume(s) merged | "
                     f"{st['total_rows']:,} row(s) -> {st['merged_rows']:,} after "
                     f"deduplication ({st['tables']} table(s))")


def cmd_run(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        log.error(f"[!] path does not exist or is not a directory: {root}")
        return 1

    cfg = load_config(Path(args.config) if args.config else None)
    setup_logging(
        level=logging.DEBUG if args.verbose else logging.INFO,
        log_file=root / "aeng-run.log",
    )
    print(f"{RAZER_GREEN}{BANNER}\033[0m" if console_supports_color() else BANNER)
    _log_version()
    _log_config(cfg)
    _warn_interpreter(cfg)
    t_run = time.perf_counter()

    # Phase 0 - Integrity (before touching anything)
    log.info("[+] Computing integrity (SHA256 of originals)...")
    t = time.perf_counter()
    entries = hashing.generate_traces(root, max_workers=cfg.max_workers, operator=_operator(),
                                      include_drops=cfg.traces_include_drops)
    if entries:
        log.info(f"    {len(entries)} file(s) -> {hashing.TRACES_TXT}  ({time.perf_counter()-t:.1f}s)")

    # Phase 1 - Extraction (parallel; parent containers + nested wrappers only)
    log.info("[+] Extracting acquisitions...")
    t = time.perf_counter()
    results = extractor.extract_all(
        root, tools_dir=cfg.tools_dir, max_depth=cfg.extract_depth, max_workers=cfg.max_workers
    )
    ok = sum(1 for r in results if r.ok)
    for r in results:
        if r.ok:
            suffix = "  (with warnings)" if r.warning_detail else ""
            log.info(f"    OK    {r.archive.name}{suffix}")
            if r.warning_detail:
                log.info(f"          warning: {r.warning_detail}")
        else:
            log.error(f"    FAILED {r.archive.name}: {r.error}")
    log.info(f"    {ok}/{len(results)} extracted  ({time.perf_counter()-t:.1f}s)")
    # Kept for the end of the run. Said here it is true and useless: phase 1 of a
    # 60-machine triage scrolls off long before the run finishes, and what an
    # analyst acts on is the last screen.
    acquisitions = list(results)

    # Phase 1b - Velociraptor LiveResponse (nested under each collection; the
    # volatile/live state nothing else captures). Extracted in place to json later.
    vr = extractor.extract_velociraptor(root, tools_dir=cfg.tools_dir)
    vr_ok = sum(1 for r in vr if r.ok)
    acquisitions += vr
    if vr:
        log.info(f"    {vr_ok}/{len(vr)} Velociraptor LiveResponse extracted")

    # Phase 1c - archives dropped inside loose-drop folders (weblogs-*/fortigate-*:
    # exports named any which way). Runs after 1 so a drop .zip extracted at the
    # root also gets its inner containers opened.
    wl = extractor.extract_drops(root, tools_dir=cfg.tools_dir)
    acquisitions += wl
    if wl:
        log.info(f"    {sum(1 for r in wl if r.ok)}/{len(wl)} drop archive(s) extracted")

    # Phase 2 - Machine detection
    log.info("[+] Detecting machines...")
    profiles = load_profiles(cfg.all_profile_dirs)
    parsers = load_parsers(cfg.all_parser_dirs)
    # Loose EVTX drops get the winevt/Logs layout the event-log toolchain expects,
    # so the same 17 parsers run over them unchanged (see prepare_evtx_drops).
    machines = pipeline.detect(root, cfg, profiles, stage_drops=True)
    # The per-machine names are shown once, in the parsing bars below; here just
    # the count and the OS/collector mix (full source mapping under -v).
    kinds = ", ".join(sorted({f"{m.os}/{m.collector}" for m in machines}))
    log.info(f"    {len(machines)} machine(s)  ({kinds})")
    if args.verbose:
        dw = max((len(m.display) for m in machines), default=0)
        for m in machines:
            log.info(f"    {m.display:<{dw}}  {m.source}")

    # Phase 3 - Parsing per machine (parallel, per-machine progress bar)
    log.info("[+] Parsing (triage tools)...")
    t = time.perf_counter()
    results = scheduler.run_all(machines, parsers, cfg, force=getattr(args, "force", False))
    for m, _runs in results:
        scheduler.cleanup_outputs(m)        # drop scratch .work_* dirs / empty JSONs
    # A loose EVTX drop could only be named after its folder at detection time; its
    # parsed events now name the real host. Rename BEFORE consolidation so every
    # output that carries a machine name -- run.json, <machine>.db/.xlsx, report.txt,
    # run-summary and the lateral graph -- agrees on one, instead of the folder in
    # the ones written here and the host in the ones written in phase 5.
    if pipeline.rename_parsed_drops(machines):
        scheduler.write_manifests(results)        # run.json was written under the old one
    log.info(f"    parsing done  ({time.perf_counter()-t:.1f}s)")

    # Phase 4 - Consolidation (configured outputs) and report, parallel across machines
    outs = " / ".join(
        x for x in (".db" if cfg.emit_db else "", ".xlsx" if cfg.emit_xlsx else "", "report.txt") if x
    )
    log.info(f"[+] Consolidating results ({outs})...")
    t = time.perf_counter()
    _consolidate_all(results, cfg, root, force=getattr(args, "force", False))
    log.info(f"    consolidation done  ({time.perf_counter()-t:.1f}s)")

    # Phase 5 - Cross-machine lateral-movement graph (Windows logon correlation)
    summary_line = pipeline.describe_graph(pipeline.lateral_graph(machines, root))
    if summary_line:
        log.info(f"[+] Lateral movement: {summary_line}")

    # Cross-machine rollup (run-summary.txt / .json at the root)
    incomplete = extractor.incomplete_acquisitions(acquisitions)
    summary = report.build_run_summary(root, results, incomplete=incomplete)
    tot = summary["totals"]
    log.info(f"[+] Done in {time.perf_counter()-t_run:.1f}s | {summary['machines']} machine(s) | "
             f"OK {tot['ok']} | skipped {tot['skipped']} | errors {tot['errors']}")
    if incomplete:
        # The counts above are the reason this has to be said again, here. A
        # parser whose input was cut out of the archive does not error -- it finds
        # nothing, self-gates, and lands in `skipped`, next to every artifact the
        # machine's distro genuinely does not have. So a run over half a tarball
        # ends "OK 2 | skipped 37 | errors 0", which is what a clean triage of a
        # quiet host looks like, and nothing on the screen says otherwise.
        log.warning(f"[!] {len(incomplete)} acquisition(s) did NOT extract whole - "
                    "the parsers below them read part of an archive:")
        for a in incomplete:
            detail = f"  -- {a['detail']}" if a.get("detail") else ""
            log.warning(f"        {a['archive']}: {a['status']}{detail}")
    if tot["errors"]:
        log.warning(f"[!] {tot['errors']} parser error(s) - see run-summary.txt")
    if tot["errors"] or incomplete:
        # 2, not 1: the run finished and its output is on disk, which is not the
        # same as `aeng run` refusing to start (1). A script that chains something
        # after a triage needs to tell those apart -- and a run that reported
        # errors on the console while exiting 0 taught whoever automated it that
        # the exit code says nothing. Errors are rare enough for this to mean
        # something: a real 60-machine run over three cases produced three.
        return EXIT_INCOMPLETE
    return 0


# --------------------------------------------------------------------------- #
# Command: lateral
# --------------------------------------------------------------------------- #
def cmd_lateral(args: argparse.Namespace) -> int:
    """Rebuild lateral_movement.csv/.html from already-parsed outputs, without
    re-running parsers or consolidation (there is no cache for those here: this
    is the cheap path to refresh the graph after an engine update)."""
    root = Path(args.path).resolve()
    if not root.is_dir():
        log.error(f"[!] path does not exist or is not a directory: {root}")
        return 1
    cfg = load_config(Path(args.config) if args.config else None)
    setup_logging(level=logging.DEBUG if args.verbose else logging.INFO,
                  log_file=root / "aeng-run.log")
    _log_version()
    profiles = load_profiles(cfg.all_profile_dirs)
    # stage_drops=False: this command re-reads a parsed case, and staging an EVTX
    # drop rewrites the evidence layout. A read path does not do that on its way past.
    machines = pipeline.detect(root, cfg, profiles, stage_drops=False)
    if not machines:
        return 1
    log.info(f"[+] Rebuilding lateral movement from {len(machines)} machine(s)...")
    t = time.perf_counter()
    summary_line = pipeline.describe_graph(pipeline.lateral_graph(machines, root))
    log.info(f"    {summary_line}" if summary_line
             else "    no logon edges found (machines parsed?)")
    log.info(f"[+] Done in {time.perf_counter()-t:.1f}s")
    return 0


# --------------------------------------------------------------------------- #
# Command: sweep
# --------------------------------------------------------------------------- #
def cmd_sweep(args: argparse.Namespace) -> int:
    """Look for a value across every machine already consolidated in a case.

    The retrospective half of working a case machine by machine: what machine seven
    taught you, asked of machines one to six without re-parsing any of them.

    Rows under a collection's own copy of the disk are dropped unless
    `--include-collection` is given, and the number dropped is always reported --
    a duplicate of a real hit is noise, but a hit nobody was told about is a wrong
    answer.
    """
    root = Path(args.path).resolve()
    if not root.is_dir():
        log.error(f"[!] path does not exist or is not a directory: {root}")
        return 1
    setup_logging(level=logging.DEBUG if args.verbose else logging.INFO,
                  log_file=root / "aeng-run.log")
    _log_version()

    found = sweep.find_case_databases(root)
    if not found:
        log.error(f"[!] no consolidated machine databases under {root}. "
                  f"Run `aeng run` first.")
        return 1

    log.info(f"[+] Sweeping {len(found)} machine(s) for {len(args.value)} value(s)...")
    t = time.perf_counter()
    result = sweep.sweep(root, args.value, include_collection=args.include_collection)

    by_machine: dict[str, list] = {}
    for h in result.hits:
        by_machine.setdefault(h.machine, []).append(h)

    for machine in sorted(by_machine):
        hits = by_machine[machine]
        log.info(f"    {machine}  {len(hits)} hit(s)")
        seen: set[tuple[str, str, str]] = set()
        for h in hits:
            k = (h.table, h.column, h.needle)
            if k in seen:
                continue
            seen.add(k)
            same = sum(1 for x in hits if (x.table, x.column, x.needle) == k)
            log.info(f"        {h.needle} in {h.table}.{h.column}"
                     + (f" x{same}" if same > 1 else ""))
            if args.verbose:
                log.info(f"            {h.context}")

    quiet = [m for m in result.searched if m not in by_machine]
    if quiet:
        log.info(f"    no hits on {len(quiet)}: {', '.join(sorted(quiet))}")

    # Hidden is not absent. A machine where every hit sat inside the collector's
    # own copy of the disk reads as clean above, and it is not.
    if result.hidden:
        total = sum(result.hidden.values())
        log.info(f"[=] {total} row(s) hidden as the collection's own copy of the "
                 f"disk (--include-collection searches them too):")
        for machine in sorted(result.hidden):
            log.info(f"        {machine}: {result.hidden[machine]}")

    # The half of the answer that is not the hits. A sweep over a case where some
    # machines could not be opened has not established that they are clean, and
    # saying so is the difference between a result and a false reassurance.
    if result.unreadable:
        log.warning(f"[!] {len(result.unreadable)} machine(s) were NOT searched - "
                    f"'no hits' does not cover them:")
        for machine, why in result.unreadable:
            log.warning(f"        {machine}: {why}")

    log.info(f"[+] {len(result.hits)} hit(s) across {len(by_machine)} machine(s) "
             f"in {time.perf_counter() - t:.1f}s")
    if not result.clean:
        return EXIT_INCOMPLETE
    return 0


# --------------------------------------------------------------------------- #
# Command: setup
# --------------------------------------------------------------------------- #
def cmd_setup(args: argparse.Namespace) -> int:
    setup_logging(level=logging.INFO)
    print(f"{RAZER_GREEN}{BANNER}\033[0m" if console_supports_color() else BANNER)
    cfg = load_config()
    cfg.tools_dir.mkdir(parents=True, exist_ok=True)
    log.info(f"[+] Tools directory: {cfg.tools_dir}")

    _write_default_config(cfg)

    parsers = load_parsers(cfg.all_parser_dirs)
    tools = {p.tool.binary: p.tool for p in parsers if p.tool and p.tool.source}
    if not tools:
        log.info("[=] No parser declares binaries to download")
        return 0

    from artifact_engine.core.downloader import fetch_tool  # deferred import (uses requests)

    ok = fail = 0
    for binary, tool in tools.items():
        target = cfg.tools_dir / binary
        if target.is_file():
            log.info(f"[=] {binary} already present")
            ok += 1
            continue
        if fetch_tool(tool, cfg.tools_dir):
            ok += 1
        else:
            fail += 1

    # Offline IP-origin databases for the web hunt (huntweb).
    from artifact_engine.core.downloader import (
        fetch_hayabusa,
        fetch_web_assets,
        fetch_yara_rules,
    )
    geo = fetch_web_assets(cfg.assets_dir)
    # Community YARA rules (signature-base) for the lin_yara scan.
    sigs = fetch_yara_rules(cfg.assets_dir).total
    # Hayabusa (Sigma-based EVTX detection) for the Windows event-log scan.
    haya = fetch_hayabusa(cfg.tools_dir)
    # AFTER every fetch, so the lockfile also covers hayabusa (downloaded here, not
    # from a parser manifest) instead of recording only what existed beforehand.
    _write_tools_lock(cfg.tools_dir, parsers)
    log.info(f"[+] Setup: {ok} tool(s) ready, {fail} failed, "
             f"{geo}/3 geo asset(s), {sigs} yara rule file(s), "
             f"hayabusa {'ready' if haya else 'unavailable'}")
    return 0 if fail == 0 else 1


def _write_tools_lock(tools_dir: Path, parsers) -> None:
    """Record sha256/size/source of every ready tool binary -> tools.lock.json.

    Audit trail of exactly which tool builds produced the outputs (DFIR
    defensibility). EZ tools ship from rolling 'latest' URLs, so we RECORD rather
    than hard-pin the hash: pinning would break setup on every upstream release.

    Covers the binaries fetched OUTSIDE the parser manifests too. Hayabusa is a
    Python-handler parser with no `tool:` section, so walking the manifests alone
    left the one downloaded executable we run unrecorded -- exactly the build an
    "which version produced this detection?" question would ask about.
    """
    import json

    from artifact_engine.core.downloader import file_sha256

    lock: dict[str, dict] = {}
    for p in parsers:
        if not (p.tool and p.tool.source):
            continue
        b = tools_dir / p.tool.binary
        if p.tool.binary in lock or not b.is_file():
            continue
        src = p.tool.source
        lock[p.tool.binary] = {
            "sha256": file_sha256(b),
            "size": b.stat().st_size,
            "source": src.url or (f"{src.repo}:{src.asset}" if src.repo else ""),
        }
    for extra, source in _EXTRA_BINARIES:
        for b in sorted(tools_dir.glob(extra)):
            key = str(b.relative_to(tools_dir)).replace("\\", "/")
            if key not in lock:
                lock[key] = {"sha256": file_sha256(b), "size": b.stat().st_size,
                             "source": source}
    if not lock:
        return
    lock_path = tools_dir / "tools.lock.json"
    # Compare before overwriting. Recording alone never detected anything: the
    # file was rewritten wholesale every time, so a binary whose bytes changed
    # looked exactly like one that had not. Pinning is still the wrong control --
    # the EZ tools ship from rolling "latest" URLs and a real release would fail
    # every setup -- but a hash that moves is worth SAYING, because the operator
    # knows whether they asked for it and the file cannot know.
    try:
        old = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        old = {}
    changed = [k for k, v in lock.items()
               if k in old and old[k].get("sha256") != v.get("sha256")]
    added = sorted(set(lock) - set(old))
    if changed:
        log.warning(f"[!] {len(changed)} tool binary(ies) changed since the last "
                    f"lock -- expected after an update, NOT after a plain setup:")
        for k in sorted(changed):
            log.warning(f"    {k}: {old[k].get('sha256', '?')[:12]} -> "
                        f"{lock[k]['sha256'][:12]}")
    if added and old:
        log.info(f"[=] {len(added)} tool(s) newly recorded: {', '.join(added[:6])}")
    try:
        lock_path.write_text(
            json.dumps(lock, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
        )
        log.info(f"[+] Recorded {len(lock)} tool hash(es) -> tools.lock.json")
    except OSError as e:
        log.warning(f"[!] could not write tools.lock.json: {e}")


# --------------------------------------------------------------------------- #
# Commands: Windows right-click integration
# --------------------------------------------------------------------------- #
# Executables `setup` fetches outside the parser manifests (glob under tools_dir ->
# recorded source), so tools.lock.json covers every binary the engine actually runs.
_EXTRA_BINARIES = (
    ("hayabusa/hayabusa*.exe", "Yamato-Security/hayabusa:win-x64"),
)

# --------------------------------------------------------------------------- #
# Command: update
# --------------------------------------------------------------------------- #
_GIT_TIMEOUT = 180


def _git(root: Path, *args: str) -> tuple[int, str]:
    """Run git in `root` and never let it ask for anything.

    A credential or passphrase prompt here would hang the update behind a cursor
    the analyst may not even be looking at, so the prompt is disabled and a
    missing credential comes back as a plain failure we can report."""
    import subprocess

    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="",
               SSH_ASKPASS="", GCM_INTERACTIVE="never")
    try:
        p = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                           text=True, timeout=_GIT_TIMEOUT, env=env, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)
    return p.returncode, (p.stdout + p.stderr).strip()


def _install_root() -> Path | None:
    """The git checkout the RUNNING engine is imported from, or None when it was
    installed some other way (a wheel in site-packages has no `.git`)."""
    import artifact_engine

    pkg = Path(artifact_engine.__file__).resolve().parent      # <root>/src/artifact_engine
    root = pkg.parents[1]
    return root if (root / ".git").exists() else None


def _disk_version(root: Path) -> str:
    """Version as written in the checkout. Read from the FILE, not `__version__`:
    after a pull the running process still holds the old value in memory."""
    try:
        txt = (root / "src" / "artifact_engine" / "__init__.py").read_text(encoding="utf-8")
    except OSError:
        return ""
    mo = re.search(r'__version__\s*=\s*"([^"]+)"', txt)
    return mo.group(1) if mo else ""


def _update_engine(check_only: bool) -> tuple[str, str]:
    """Fast-forward the checkout to origin. Returns (status, detail).

    Deliberately timid: it refuses on a dirty tree, a detached HEAD or a branch
    that has commits of its own. This checkout may well be where somebody is
    working, and an update command has no business resolving that -- reporting
    what is in the way is more useful than a merge nobody asked for.
    """
    root = _install_root()
    if root is None:
        import artifact_engine
        return "skipped", (f"not a git checkout ({Path(artifact_engine.__file__).parent}) "
                           f"-- update it the way it was installed")

    rc, branch = _git(root, "rev-parse", "--abbrev-ref", "HEAD")
    if rc or not branch:
        return "failed", f"git unavailable or not a repository: {branch}"
    if branch == "HEAD":
        return "blocked", "detached HEAD -- check out a branch first"

    rc, dirty = _git(root, "status", "--porcelain")
    if rc:
        return "failed", f"git status failed: {dirty}"
    if dirty:
        n = len(dirty.splitlines())
        return "blocked", (f"{n} uncommitted change(s) in {root} -- commit or stash "
                           f"them first; nothing was touched")

    rc, out = _git(root, "fetch", "--quiet", "origin")
    if rc:
        last = out.splitlines()[-1] if out else "unknown error"
        return "failed", f"cannot reach origin: {last}"

    rc, counts = _git(root, "rev-list", "--left-right", "--count", f"HEAD...origin/{branch}")
    if rc:
        return "failed", f"no upstream for {branch}: {counts}"
    ahead, behind = (int(x) for x in counts.split())
    if ahead:
        return "blocked", f"{ahead} local commit(s) not on origin/{branch} -- push or reset first"
    if not behind:
        return "current", f"v{_disk_version(root)} on {branch}, up to date with origin"
    if check_only:
        return "available", f"{behind} commit(s) behind origin/{branch}"

    before_v = _disk_version(root)
    _rc, head = _git(root, "rev-parse", "HEAD")
    rc2, out = _git(root, "merge", "--ff-only", f"origin/{branch}")
    if rc2:
        return "failed", f"fast-forward refused: {out.splitlines()[-1] if out else ''}"
    after_v = _disk_version(root)

    # A dependency change needs a reinstall that this command must not do for you
    # -- it would be rewriting the environment it is running inside.
    _rc, changed = _git(root, "diff", "--name-only", head, "HEAD")
    note = ""
    if "pyproject.toml" in changed:
        note = "  (pyproject changed: re-run `pip install -e .`)"
    moved = f"v{before_v} -> v{after_v}" if before_v != after_v else f"v{after_v}"
    return "updated", f"{moved}, {behind} commit(s){note}"


def _digest(path: Path) -> str:
    """SHA256 of a file, or '' when it is not there -- so 'absent' and 'present'
    compare as different without a special case at every call site."""
    from artifact_engine.core.downloader import file_sha256

    try:
        return file_sha256(path)
    except OSError:
        return ""


def _update_content(cfg: Config, check_only: bool, with_tools: bool) -> list[tuple[str, str, str]]:
    """Refresh the detection content and the lookup databases.

    This is where `update` differs from `setup`: setup fills in what is missing
    and leaves everything else alone, so today there is no way to pick up a new
    YARA rule short of deleting the folder. Here everything volatile is re-read
    from upstream, and what changed is reported -- a detection set that moved
    under an analyst without saying so is its own kind of bug.
    """
    from artifact_engine.core import downloader as dl

    rows: list[tuple[str, str, str]] = []

    # -- rule sets ---------------------------------------------------------- #
    if check_only:
        rows.append(("signature-base YARA", "available", "refreshed on every update"))
    else:
        sync = dl.fetch_yara_rules(cfg.assets_dir)
        if not sync.ok:
            rows.append(("signature-base YARA", "failed", "download failed, rules left as they were"))
        elif sync.changed:
            rows.append(("signature-base YARA", "updated",
                         f"{sync.total} rule file(s)  (+{sync.added} new, -{sync.removed} withdrawn)"))
        else:
            rows.append(("signature-base YARA", "current", f"{sync.total} rule file(s)"))

    # -- tools that carry a rule set inside them ---------------------------- #
    have = dl.installed_hayabusa_version(cfg.tools_dir)
    want = dl.latest_tag(dl.HAYABUSA_REPO)
    rows.append(_bump("hayabusa", have, want, check_only,
                      lambda: dl.fetch_hayabusa(cfg.tools_dir, force=True)))

    parsers = load_parsers(cfg.all_parser_dirs)
    chainsaw = next((p for p in parsers
                     if p.tool and p.tool.source and "chainsaw" in p.tool.binary), None)
    if chainsaw:
        have = dl.installed_chainsaw_version(cfg.tools_dir, chainsaw.tool.binary)
        want = dl.latest_tag(dl.CHAINSAW_REPO)
        rows.append(_bump("chainsaw", have, want, check_only,
                          # its zip bundles rules/ + sigma/: drop them so a rule
                          # upstream withdrew does not outlive the update
                          lambda: dl.fetch_tool(chainsaw.tool, cfg.tools_dir,
                                                purge_dirs=("chainsaw/rules", "chainsaw/sigma"))))

    # -- lookup databases --------------------------------------------------- #
    if check_only:
        rows.append(("geo + Tor databases", "available", "refreshed on every update"))
    else:
        # Report what actually MOVED, not what was asked for: saying "updated"
        # when the bytes came back identical is the kind of small untruth that
        # makes an analyst distrust the rest of the report.
        names = ("dbip-country-lite.mmdb", "dbip-asn-lite.mmdb", "tor-exit-nodes.txt")
        before = [_digest(cfg.assets_dir / n) for n in names]
        geo = dl.fetch_web_assets(cfg.assets_dir, force=True)
        moved = sum(1 for n, b in zip(names, before) if _digest(cfg.assets_dir / n) != b)
        tor = cfg.assets_dir / "tor-exit-nodes.txt"
        exits = len(tor.read_text(encoding="utf-8", errors="replace").split()) if tor.is_file() else 0
        st = "failed" if geo < 3 else ("updated" if moved else "current")
        detail = f"{geo}/3 ready, {exits:,} Tor exit node(s)"
        rows.append(("geo + Tor databases", st,
                     detail + (f"  ({moved} file(s) changed)" if moved else "  (unchanged)")))

    # -- every other parser binary (opt-in: hundreds of MB) ----------------- #
    if with_tools and not check_only:
        ok = fail = 0
        for p in parsers:
            if not (p.tool and p.tool.source) or (chainsaw and p is chainsaw):
                continue
            if dl.fetch_tool(p.tool, cfg.tools_dir):
                ok += 1
            else:
                fail += 1
        rows.append(("parser binaries", "updated" if not fail else "failed",
                     f"{ok} refreshed, {fail} failed"))
    return rows


def _bump(name: str, have: str, want: str, check_only: bool, fetch) -> tuple[str, str, str]:
    """One versioned tool: compare, then fetch only if it actually moved.

    An unknown local version counts as out of date -- that is the state of an
    install from before this command existed, and refetching once is cheaper than
    leaving it unresolved forever."""
    if not want:
        return (name, "failed", f"cannot read the latest release (installed {have or 'unknown'})")
    if have == want:
        return (name, "current", have)
    move = f"{have or 'unknown'} -> {want}"
    if check_only:
        return (name, "available", move)
    return (name, "updated" if fetch() else "failed", move)


def cmd_update(args: argparse.Namespace) -> int:
    """Bring the engine and everything it detects with up to date."""
    setup_logging(level=logging.INFO)
    print(f"{RAZER_GREEN}{BANNER}\033[0m" if console_supports_color() else BANNER)
    _log_version()
    cfg = load_config(Path(args.config) if args.config else None)
    check = getattr(args, "check", False)
    t0 = time.perf_counter()
    if check:
        log.info("[+] Checking for updates (nothing will be changed)...")

    log.info("[+] Engine")
    status, detail = _update_engine(check)
    log.info(f"    {status:<10} {detail}")
    if status == "updated":
        log.warning("[!] the running process still holds the OLD code -- re-run aeng "
                    "to use the version just pulled")

    # The interpreter belongs in an update report. It is the one component this
    # command cannot fix, and on Windows 3.10 it is also the one that ends a run
    # with no error at all -- reporting every rule as current while sitting on it
    # would be a clean bill of health for the wrong patient.
    interp = "current"
    if interpreter_risks_memoryview_crash():
        interp = "at risk"
        log.warning(f"    {interp:<10} Python {platform.python_version()} on Windows can end a "
                    f"RUN with no error (interpreter bug, not the engine)")
        log.warning("               this command is unaffected; `aeng run` is not. "
                    "Use a newer Python -- verified clean on 3.13")

    log.info("[+] Detection content and databases")
    rows = _update_content(cfg, check, getattr(args, "tools", False))
    width = max(len(n) for n, _, _ in rows)
    for name, st, detail in rows:
        log.info(f"    {name:<{width}}  {st:<10} {detail}")

    if not check:
        _write_tools_lock(cfg.tools_dir, load_parsers(cfg.all_parser_dirs))

    tally = [s for _, s, _ in rows] + [status, interp]
    done = tally.count("updated")
    fail = tally.count("failed")
    blocked = tally.count("blocked") + tally.count("available") + tally.count("at risk")
    log.info(f"[+] {'Check' if check else 'Update'} done in {time.perf_counter()-t0:.1f}s | "
             f"{done} updated | {tally.count('current')} already current | "
             f"{blocked} pending | {fail} failed")
    return 1 if fail else 0


_MENU_LABEL = "Process with Artifact Engine"
_MENU_KEYS = (  # (registry path under HKCU, folder-path placeholder)
    (r"Software\Classes\Directory\shell\ArtifactEngine", "%1"),            # right-click ON a folder
    (r"Software\Classes\Directory\Background\shell\ArtifactEngine", "%V"),  # right-click INSIDE a folder
)


def _require_windows() -> bool:
    if os.name != "nt":
        log.error("[!] the right-click menu is a Windows-only feature")
        return False
    return True


def cmd_install_menu(args: argparse.Namespace) -> int:
    """Register a per-user 'Process with Artifact Engine' entry on folders.

    HKCU (no admin needed). On Windows 11 the entry appears under
    'Show more options' (the legacy menu), as do all registry-based verbs.
    """
    setup_logging(level=logging.INFO)
    if not _require_windows():
        return 1
    import winreg

    # Whatever interpreter registers the menu is FROZEN into the registry, so on
    # Python 3.10 for Windows every future right-click would run on the one that
    # ends a run with no error at all. That failure is invisible by construction --
    # no traceback, no last log line, just a console that closes -- so there is no
    # feedback loop that would ever point back here. Refusing is the only moment
    # this can be caught. `INSTALL.bat` reaches this through a bare `python`, which
    # is exactly how the wrong one gets in.
    if interpreter_risks_memoryview_crash() and not getattr(args, "force", False):
        log.error(f"[!] refusing to register Python {platform.python_version()} in the "
                  f"right-click menu: it ends a run with no error at all, and the menu "
                  f"would freeze it in for every future run.")
        log.error("    Re-run install-menu with a newer interpreter (verified clean on "
                  "3.13), or pass --force to register it anyway.")
        return 1

    # Run aeng with the exact interpreter that has the package installed; cmd /k
    # keeps the console open so the analyst can read the run output.
    icon = r"%SystemRoot%\System32\SHELL32.dll,209"
    for path, placeholder in _MENU_KEYS:
        command = f'cmd /k ""{sys.executable}" -m artifact_engine run -p "{placeholder}""'
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, _MENU_LABEL)
            winreg.SetValueEx(k, "Icon", 0, winreg.REG_EXPAND_SZ, icon)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path + r"\command") as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, command)
    log.info(f"[+] Installed right-click menu '{_MENU_LABEL}' (current user)")
    log.info("    On Windows 11 it lives under 'Show more options'. "
             "Run 'aeng uninstall-menu' to remove it.")
    return 0


def cmd_uninstall_menu(args: argparse.Namespace) -> int:
    setup_logging(level=logging.INFO)
    if not _require_windows():
        return 1
    import winreg

    removed = 0
    for path, _ in _MENU_KEYS:
        for sub in (path + r"\command", path):   # leaf first: DeleteKey needs an empty key
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
                removed += 1
            except FileNotFoundError:
                pass
            except OSError as e:
                log.warning(f"[!] could not remove {sub}: {e}")
    log.info(f"[+] Removed right-click menu ({removed} key(s))" if removed
             else "[=] Right-click menu was not installed")
    return 0


# --------------------------------------------------------------------------- #
# Commands: list
# --------------------------------------------------------------------------- #
def cmd_list_parsers(args: argparse.Namespace) -> int:
    setup_logging(level=logging.INFO)
    cfg = load_config()
    parsers = load_parsers(cfg.all_parser_dirs)
    for p in sorted(parsers, key=lambda x: (x.os, x.id)):
        kind = "cmd" if p.command else "py"
        print(f"  [{p.os:<7}] {p.id:<28} ({kind})  {p.description}")
    print(f"\nTotal: {len(parsers)} parser(s)")
    return 0


def cmd_list_profiles(args: argparse.Namespace) -> int:
    setup_logging(level=logging.INFO)
    cfg = load_config()
    profiles = load_profiles(cfg.all_profile_dirs)
    for p in sorted(profiles, key=lambda x: x.id):
        print(f"  [{p.os:<7}] {p.id:<22} collector={p.collector}")
    print(f"\nTotal: {len(profiles)} profile(s)")
    return 0


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _operator() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return ""


def _write_default_config(cfg: Config) -> None:
    """Write the starting `config.yaml` WHERE THE ENGINE LOOKS FOR IT.

    Beside the tool, not in whatever directory setup happened to be run from:
    that is the location a later run finds regardless of where it is launched
    (`config.config_candidates`). Writing it to the cwd -- what this did until the
    lookup changed -- meant `aeng setup` in a case folder produced settings that
    every subsequent run outside that folder silently ignored. Falls back to the
    cwd when the engine is not running from a checkout, since then there is no
    tool folder to speak of.
    """
    cfg_path = (install_dir() or Path.cwd()) / "config.yaml"
    if cfg_path.is_file():
        return
    cfg_path.write_text(
        f"max_workers: {os.cpu_count() or 4}\n"
        "avoid_vss: true   # set false to also parse VSS snapshots (slower)\n"
        "merge_vss: true   # with avoid_vss: false, one .db per HOST (volumes merged,\n"
        "                  # duplicate rows collapsed) instead of one per snapshot\n"
        "emit_db: true     # build the queryable SQLite .db per machine\n"
        "emit_xlsx: true   # build the Excel .xlsx per machine (set false: much faster)\n"
        "traces_include_drops: true  # false: skip hashing files inside "
        "weblogs*/fortigate*/evtx* drops\n",
        encoding="utf-8",
    )
    log.info(f"[+] Default config written to {cfg_path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aeng", description="Artifact Engine - DFIR triage")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    pr = sub.add_parser("run", help="process a folder of evidence")
    pr.add_argument("-p", "--path", required=True, help="parent folder with the .zip/.tar.gz")
    pr.add_argument("-c", "--config", help="path to config.yaml")
    pr.add_argument("-v", "--verbose", action="store_true")
    pr.add_argument("--force", action="store_true", help="re-parse even if output already exists")
    pr.set_defaults(func=cmd_run)

    pl = sub.add_parser("lateral", help="rebuild the lateral-movement graph from existing outputs")
    pl.add_argument("-p", "--path", required=True, help="processed evidence folder (after 'aeng run')")
    pl.add_argument("-c", "--config", help="path to config.yaml")
    pl.add_argument("-v", "--verbose", action="store_true")
    pl.set_defaults(func=cmd_lateral)

    pw = sub.add_parser("sweep", help="look for a value across every machine in a case")
    pw.add_argument("-p", "--path", required=True, help="processed evidence folder (after 'aeng run')")
    pw.add_argument("-q", "--value", required=True, action="append", metavar="VALUE",
                    help="what to look for; repeat for several")
    pw.add_argument("-v", "--verbose", action="store_true", help="show the matching text")
    pw.add_argument("--include-collection", action="store_true",
                    help="also search the collector's own copy of the disk "
                         "(hidden by default; the count is always reported)")
    pw.set_defaults(func=cmd_sweep)

    ps = sub.add_parser("setup", help="download binaries and prepare the config")
    ps.set_defaults(func=cmd_setup)

    pu = sub.add_parser("update",
                        help="update the engine, the detection rules and the lookup databases")
    pu.add_argument("--check", action="store_true",
                    help="report what is out of date without changing anything")
    pu.add_argument("--tools", action="store_true",
                    help="also re-download every parser binary (hundreds of MB)")
    pu.add_argument("-c", "--config", help="path to config.yaml")
    pu.set_defaults(func=cmd_update)

    plp = sub.add_parser("list-parsers", help="list the loaded parsers")
    plp.set_defaults(func=cmd_list_parsers)

    plf = sub.add_parser("list-profiles", help="list the loaded profiles")
    plf.set_defaults(func=cmd_list_profiles)

    pim = sub.add_parser("install-menu",
                         help="add the Windows right-click 'Process with Artifact Engine' entry")
    pim.add_argument("--force", action="store_true",
                     help="register even an interpreter known to end runs with no error")
    pim.set_defaults(func=cmd_install_menu)

    pum = sub.add_parser("uninstall-menu", help="remove the Windows right-click entry")
    pum.set_defaults(func=cmd_uninstall_menu)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        # Ctrl+C: terminate external processes (7-Zip, parsers) in flight and exit cleanly
        procs.cancel_all()
        log.warning("\n[!] Cancelled by user (Ctrl+C)")
        return 130
