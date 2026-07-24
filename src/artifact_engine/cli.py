"""Artifact Engine command-line entry point."""

from __future__ import annotations

import argparse
import getpass
import logging
import multiprocessing
import os
import platform
import queue
import sys
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path

from artifact_engine import __version__
from artifact_engine.config import Config, load_config
from artifact_engine.core import (
    consolidate, detector, extractor, hashing, lateral, procs, report, scheduler,
)
from artifact_engine.core.progress import Progress
from artifact_engine.logging_setup import RAZER_GREEN, get_logger, setup_logging
from artifact_engine.registry import load_parsers, load_profiles

log = get_logger()


def _log_version() -> None:
    """Record the tool version + interpreter/OS in the on-disk run log. The
    banner shows the version on the console only; putting it in the LOG makes a
    shared aeng-run.log self-identifying (which build produced these outputs),
    so 'missing outputs' reports can be pinned to a version instead of guessed."""
    log.info(f"[=] Artifact Engine v{__version__} | Python {platform.python_version()}"
             f" | {platform.system()} {platform.release()}")


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
def _consolidate_all(results, cfg: Config) -> None:
    """Build the configured outputs (.db/.xlsx) + report for all machines, with a
    per-machine progress bar. Each bar advances through the read/.db pass (one step
    per input file) and, when emit_xlsx, the .xlsx pass (one step per sheet) -- the
    latter dominates, as xlsxwriter writes cell by cell.

    Consolidation is almost entirely pure-Python (GIL-bound: the .xlsx pass barely
    overlaps on threads), so with more than one machine it runs in a PROCESS pool
    for real parallelism -- each machine is independent (its own .db/.xlsx). Workers
    push progress through a manager queue that a drain thread applies to the bars;
    a single machine (or parse_processes=false) stays in-process on threads."""
    if not results:
        return
    labels = [m.display or m.name for m, _ in results]
    # Steps per machine: inputs (read/db pass) plus, when emit_xlsx, the sheets
    # (<= inputs). Counting inputs is a cheap glob; the few giant tables that skip
    # the .xlsx leave slack that the per-machine done marker snaps to full.
    mult = 2 if cfg.emit_xlsx else 1
    totals = [max(1, mult * consolidate.count_inputs(m)) for m, _ in results]
    progress = Progress(labels, totals)
    done = [0] * len(results)

    workers = max(1, min(cfg.max_workers, len(results)))
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
    try:
        futs = {ex.submit(consolidate.consolidate_machine, i, m, q, cfg.emit_db, cfg.emit_xlsx): i
                for i, (m, _runs) in enumerate(results)}
        for fut in as_completed(futs):
            _idx, err = fut.result()
            if err:
                log.error(f"    FAILED consolidation {results[_idx][0].name}: {err}")
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

    # report.txt per machine, in the parent: cheap (text only), keeps logging here,
    # and lets the pool worker stay pure/picklable.
    for m, runs in results:
        try:
            report.build(m, runs)
        except Exception as e:  # noqa: BLE001 - one machine must not abort the rest
            log.error(f"    FAILED report {m.name}: {e}")


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
    print(f"{RAZER_GREEN}{BANNER}\033[0m" if sys.stdout.isatty() else BANNER)
    _log_version()
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

    # Phase 1b - Velociraptor LiveResponse (nested under each collection; the
    # volatile/live state nothing else captures). Extracted in place to json later.
    vr = extractor.extract_velociraptor(root, tools_dir=cfg.tools_dir)
    vr_ok = sum(1 for r in vr if r.ok)
    if vr:
        log.info(f"    {vr_ok}/{len(vr)} Velociraptor LiveResponse extracted")

    # Phase 1c - archives dropped inside loose-drop folders (weblogs-*/fortigate-*:
    # exports named any which way). Runs after 1 so a drop .zip extracted at the
    # root also gets its inner containers opened.
    wl = extractor.extract_drops(root, tools_dir=cfg.tools_dir)
    if wl:
        log.info(f"    {sum(1 for r in wl if r.ok)}/{len(wl)} drop archive(s) extracted")

    # Phase 2 - Machine detection
    log.info("[+] Detecting machines...")
    profiles = load_profiles(cfg.all_profile_dirs)
    parsers = load_parsers(cfg.all_parser_dirs)
    machines = detector.detect_machines(root, profiles, avoid_vss=cfg.avoid_vss)
    detector.assign_display_names(machines)
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
    log.info(f"    parsing done  ({time.perf_counter()-t:.1f}s)")

    # Phase 4 - Consolidation (configured outputs) and report, parallel across machines
    outs = " / ".join(
        x for x in (".db" if cfg.emit_db else "", ".xlsx" if cfg.emit_xlsx else "", "report.txt") if x
    )
    log.info(f"[+] Consolidating results ({outs})...")
    t = time.perf_counter()
    _consolidate_all(results, cfg)
    log.info(f"    consolidation done  ({time.perf_counter()-t:.1f}s)")

    # Phase 5 - Cross-machine lateral-movement graph (Windows logon correlation)
    lat = lateral.build(machines, root)
    if lat["edges"]:
        log.info(f"[+] Lateral movement: {lat['edges']} edge(s), {lat['hosts']} host(s), "
                 f"{lat['suspicious']} suspicious, {lat.get('chains', 0)} pivot chain(s) "
                 f"(lateral_movement.csv) | "
                 f"graph {lat.get('graph_hosts', 0)} host(s) -> lateral_movement.html")

    # Cross-machine rollup (run-summary.txt / .json at the root)
    summary = report.build_run_summary(root, results)
    tot = summary["totals"]
    log.info(f"[+] Done in {time.perf_counter()-t_run:.1f}s | {summary['machines']} machine(s) | "
             f"OK {tot['ok']} | skipped {tot['skipped']} | errors {tot['errors']}")
    if tot["errors"]:
        log.warning(f"[!] {tot['errors']} parser error(s) - see run-summary.txt")
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
    machines = detector.detect_machines(root, profiles, avoid_vss=cfg.avoid_vss)
    if not machines:
        return 1
    log.info(f"[+] Rebuilding lateral movement from {len(machines)} machine(s)...")
    t = time.perf_counter()
    lat = lateral.build(machines, root)
    if lat["edges"]:
        log.info(f"    {lat['edges']} edge(s), {lat['hosts']} host(s), "
                 f"{lat['suspicious']} suspicious, {lat.get('chains', 0)} pivot chain(s) "
                 f"(lateral_movement.csv) | "
                 f"graph {lat.get('graph_hosts', 0)} host(s) -> lateral_movement.html")
    else:
        log.info("    no logon edges found (machines parsed?)")
    log.info(f"[+] Done in {time.perf_counter()-t:.1f}s")
    return 0


# --------------------------------------------------------------------------- #
# Command: setup
# --------------------------------------------------------------------------- #
def cmd_setup(args: argparse.Namespace) -> int:
    setup_logging(level=logging.INFO)
    print(f"{RAZER_GREEN}{BANNER}\033[0m" if sys.stdout.isatty() else BANNER)
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
    _write_tools_lock(cfg.tools_dir, parsers)

    # Offline IP-origin databases for the web hunt (huntweb).
    from artifact_engine.core.downloader import (
        fetch_hayabusa, fetch_web_assets, fetch_yara_rules,
    )
    geo = fetch_web_assets(cfg.assets_dir)
    # Community YARA rules (signature-base) for the lin_yara scan.
    sigs = fetch_yara_rules(cfg.assets_dir)
    # Hayabusa (Sigma-based EVTX detection) for the Windows event-log scan.
    haya = fetch_hayabusa(cfg.tools_dir)
    log.info(f"[+] Setup: {ok} tool(s) ready, {fail} failed, "
             f"{geo}/3 geo asset(s), {sigs} yara rule file(s), "
             f"hayabusa {'ready' if haya else 'unavailable'}")
    return 0 if fail == 0 else 1


def _write_tools_lock(tools_dir: Path, parsers) -> None:
    """Record sha256/size/source of every ready tool binary -> tools.lock.json.

    Audit trail of exactly which tool builds produced the outputs (DFIR
    defensibility). EZ tools ship from rolling 'latest' URLs, so we RECORD rather
    than hard-pin the hash: pinning would break setup on every upstream release.
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
    if not lock:
        return
    try:
        (tools_dir / "tools.lock.json").write_text(
            json.dumps(lock, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
        )
        log.info(f"[+] Recorded {len(lock)} tool hash(es) -> tools.lock.json")
    except OSError as e:
        log.warning(f"[!] could not write tools.lock.json: {e}")


# --------------------------------------------------------------------------- #
# Commands: Windows right-click integration
# --------------------------------------------------------------------------- #
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
    cfg_path = Path.cwd() / "config.yaml"
    if cfg_path.is_file():
        return
    cfg_path.write_text(
        f"max_workers: {os.cpu_count() or 4}\n"
        "avoid_vss: true   # set false to also parse VSS snapshots (slower)\n"
        "emit_db: true     # build the queryable SQLite .db per machine\n"
        "emit_xlsx: true   # build the Excel .xlsx per machine (set false: much faster)\n"
        "traces_include_drops: true  # false: skip hashing files inside weblogs*/fortigate* drops\n"
        "use_iris: false\n"
        "iris_url: \"\"\n"
        "iris_token: \"\"\n",
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

    ps = sub.add_parser("setup", help="download binaries and prepare the config")
    ps.set_defaults(func=cmd_setup)

    plp = sub.add_parser("list-parsers", help="list the loaded parsers")
    plp.set_defaults(func=cmd_list_parsers)

    plf = sub.add_parser("list-profiles", help="list the loaded profiles")
    plf.set_defaults(func=cmd_list_profiles)

    pim = sub.add_parser("install-menu", help="add the Windows right-click 'Process with Artifact Engine' entry")
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
