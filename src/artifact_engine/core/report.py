"""Phase 4 - Informative per-machine report (identity + execution).

Purely informative, no detections or severity. Includes the machine
identification and the detailed execution block: each parser with its status,
duration and, if it failed, the reason.
"""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine import __version__
from artifact_engine.core import coverage, findings
from artifact_engine.core.detector import Machine
from artifact_engine.core.runner import ParserRun
from artifact_engine.logging_setup import get_logger

log = get_logger()


def _machine_info(machine: Machine) -> dict:
    # machine_info.json is written by the win_machine_info parser under CSVs/
    csvs = machine.path / "CSVs"
    if csvs.is_dir():
        for f in (csvs / "machine_info.json", *csvs.rglob("machine_info.json")):
            if f.is_file():
                try:
                    return json.loads(f.read_text(encoding="utf-8"))
                except Exception:  # noqa: BLE001
                    return {}
    return {}


def _contribution_block(stats: dict) -> list[str]:
    """Per-volume contribution table for a merged host.

    The point of merging is that the analyst no longer opens eleven databases --
    but they still need to know WHICH snapshot holds something the live disk lost.
    That is the last column: rows that survived deduplication in exactly one
    volume. A snapshot contributing thousands of them is worth a look; one
    contributing none is a copy of its neighbours.
    """
    labels = stats.get("volumes") or []
    if not labels:
        return []
    rows, arts, uniq = stats.get("rows", {}), stats.get("artifacts", {}), stats.get("unique", {})
    w = max(max((len(x) for x in labels), default=6), len("Volume"))
    out = [
        "",
        "Volume contribution (merged):",
        f"  {'Volume':<{w}}  {'Artifacts':>9}  {'Rows':>12}  {'Only in this volume':>19}",
    ]
    for label in labels:
        out.append(f"  {label:<{w}}  {arts.get(label, 0):>9}  {rows.get(label, 0):>12,}  "
                   f"{uniq.get(label, 0):>19,}")
    total, merged = stats.get("total_rows", 0), stats.get("merged_rows", 0)
    dropped = total - merged
    pct = f" ({dropped / total * 100:.1f}% shared)" if total else ""
    out.append("")
    out.append(f"  {stats.get('tables', 0)} table(s) | {total:,} row(s) read | "
               f"{merged:,} after merging{pct}")
    return out


def build(machine: Machine, runs: list[ParserRun], out_dir: Path | None = None,
          volume_labels: list[str] | None = None, stats: dict | None = None,
          db_path: Path | None = None) -> str | None:
    """Write report.txt for a machine, or for a merged host.

    `out_dir` overrides where it lands (a merged host reports in the collection
    folder its volumes share, not inside one of them), `volume_labels` names every
    volume folded in, and `stats` adds the contribution table.

    `db_path` is the consolidated database this unit just produced. Given one, the
    report also carries what the parsers FLAGGED -- until v0.7.23 it said only
    which parsers had RUN, and every finding a real case produced had to be dug
    out of the .db by hand afterwards -- above it, the window those flags could
    have been set in at all (v0.7.24), the copies of the machine that live on
    the machine (v0.7.26), and the endpoint-security logs that arrived and were
    not read (v0.7.85).

    Returns `None`, or the reason `report.txt` could not be written. It is given
    back rather than only logged because the caller owns the run's verdict, and a
    unit with no report to read is a unit whose outputs are incomplete (v0.7.79).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    info = _machine_info(machine)
    os_str = " ".join(str(x) for x in (info.get("product_name"), info.get("build")) if x) or machine.os
    vols = volume_labels or [v.name for v in machine.volumes]

    lines = [
        "Artifact Engine - Machine report",
        "=" * 60,
        f"Machine  : {info.get('machine_name') or machine.name}",
        f"OS       : {os_str}",
        f"Collector: {machine.collector}",
        f"Source   : {machine.source}",
        f"Volumes  : {', '.join(vols) or '-'}",
    ]
    # Linux machine_info adds these; Windows reports just skip them.
    for label, key in (("Timezone", "timezone"), ("Boot", "boot_time"),
                       ("CPU", "cpu"), ("Memory", "memory")):
        if info.get(key):
            lines.append(f"{label:<9}: {info[key]}")
    if info.get("IPs"):
        lines.append(f"IPs      : {', '.join(info['IPs'])}")
    if info.get("users"):
        lines.append(f"Users    : {', '.join(sorted(info['users']))}")
    lines += [
        f"Generated: {now}",
        "",
        "Parser execution:",
    ]
    ok = sum(1 for r in runs if r.status == "ok")
    cached = sum(1 for r in runs if r.status == "cached")
    skip = sum(1 for r in runs if r.status == "skipped")
    err = sum(1 for r in runs if r.status == "error")
    for r in runs:
        detail = f"  {r.detail}" if r.detail else ""
        lines.append(f"  {r.status.upper():8} {r.parser_id:<22} [{r.volume}] {r.duration_s:>6.1f}s{detail}")
    lines.append("")
    # `ok + cached` is what this volume has, and `ok` alone is what this run did.
    # Both are worth reading, and conflating either with `skipped` was the defect.
    done = f"OK {ok + cached}" + (f" ({cached} cached)" if cached else "")
    lines.append(f"Total: {len(runs)} parser(s) | {done} | skipped {skip} | errors {err}")
    if stats and stats.get("merged"):
        lines += _contribution_block(stats)

    dest = out_dir or machine.path
    if db_path is not None:
        # Coverage first, deliberately: the findings below it can only be read
        # correctly against the window the logs actually span.
        lines += coverage.render(*coverage.read(db_path))
        lines += coverage.render_collection(coverage.read_collection(db_path))
        lines += coverage.render_av(coverage.read_av(db_path))
        found = findings.collect(db_path)
        lines += findings.render(found, case_hint=str(dest.parent))
        findings.write_findings_csv(found, dest)

    try:
        (dest / "report.txt").write_text(
            "\n".join(lines) + "\n", encoding="utf-8")
    except OSError as e:
        # Returned, not just warned: a unit with no report.txt is a unit whose
        # outputs are incomplete, and the caller is the one that owns the verdict.
        log.warning(f"[!] could not write report.txt for {machine.name}: {e}")
        return f"report.txt: {e}"
    return None


# The shape of run-summary.json, and the only thing in it a reader can rely on to
# know what the rest means. Bumped when a key CHANGES MEANING or disappears --
# adding one does not, because a reader that ignores unknown keys is unaffected.
#
# 1 (v0.7.78): the first version that says so. The keys it covers had already
#     grown once without notice (`totals.cached` in v0.7.51) and nothing
#     downstream had any way to tell which shape it was reading.
# 2 (v0.7.79): `status` covers one more failure -- a unit whose outputs were
#     never built. `broken_units` being ADDED would not bump this; the verdict
#     changing meaning does, because a v1 run that said `complete` may have had
#     one and a v2 run that says `complete` cannot.
# 3 (v0.7.82): `status` covers one more failure -- a delivered archive that has
#     not finished arriving, so no phase opened it. Same reason as 2: a v2 run
#     that said `complete` may have left one waiting, a v3 run cannot.
SCHEMA_VERSION = 4


def _utc_z(when: datetime) -> str:
    """An instant as ISO-8601 UTC with the `Z` the format actually asks for.

    The human `generated` line says "UTC" in words, which a person reads and a
    parser cannot. Both are kept: this file is read by people AND by whatever runs
    after it.
    """
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_run_summary(root: Path, results: list[tuple[Machine, list[ParserRun]]],
                      incomplete: list[dict] | None = None,
                      started_at: datetime | None = None,
                      broken: list[dict] | None = None,
                      waiting: list[dict] | None = None,
                      damaged: list[dict] | None = None) -> dict:
    """Root-level rollup across every machine -> run-summary.{txt,json}.

    Saves the cross-machine view (per-machine ok/skip/err, slowest parser, and the
    full error list) that otherwise only lived scattered in each run.json.

    `incomplete` is the acquisitions that did not extract whole
    (`extractor.incomplete_acquisitions`). They belong in this file rather than
    only in the console: it is the artifact somebody reads days later, and a
    per-machine ok/skipped table without it is a table that cannot be read
    correctly -- "skipped 37" means one thing on a host that lacks the artifacts
    and another on an archive that was cut short.

    `damaged` is the acquisitions that came out WHOLE and hold a member whose
    bytes are not a faithful copy (`extractor.damaged_acquisitions`). A smaller
    claim than `incomplete`, kept out of it, and deliberately NOT part of the
    verdict: on three real cases it was eight of the eighteen acquisitions
    reported as not whole, almost all of them one file an endpoint agent held
    open. Reported all the same, because a hole is quiet and a damaged member is
    not -- the parser reads it and produces a table (v0.7.86).

    `broken` is the units whose OUTPUTS were never built (`cli._consolidate_all`):
    consolidation or report.txt raised, the parsers having run fine. Until v0.7.79
    that was a console line and nothing else, so a machine with no `.db` to query
    left the run reporting `errors: 0` and exiting 0 -- the summary sent a reader
    to a file that is not there.

    `waiting` is the delivered archives no phase touched (`arrival.not_arrived`):
    still being copied, or carrying a seal that does not match. They are neither
    hashed nor extracted, so the run has not seen them at all -- and a run that
    left an acquisition unopened has not triaged the case it was pointed at.

    This is also where the RUN'S VERDICT is decided: the returned `status` is what
    `cmd_run` turns into its exit code, so the two cannot disagree. See the
    comment on `status` below for what `complete` covers.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    per_machine, errors = [], []
    tot_ok = tot_cached = tot_skip = tot_err = 0
    for machine, runs in results:
        # A cached parser counts as done, because it IS done: its tables are on
        # disk and the marker carries the fingerprint that produced them. Kept in
        # its own column as well, so "what this run did" is still readable.
        cached = sum(1 for r in runs if r.status == "cached")
        ok = sum(1 for r in runs if r.status == "ok") + cached
        skip = sum(1 for r in runs if r.status == "skipped")
        err = sum(1 for r in runs if r.status == "error")
        tot_ok += ok
        tot_cached += cached
        tot_skip += skip
        tot_err += err
        slowest = max(runs, key=lambda r: r.duration_s, default=None)
        time_s = sum(r.duration_s for r in runs)
        for r in runs:
            if r.status == "error":
                errors.append({"machine": machine.display or machine.name,
                               "parser": r.parser_id, "detail": r.detail})
        per_machine.append({
            "machine": machine.display or machine.name, "os": machine.os,
            "collector": machine.collector, "ok": ok, "cached": cached,
            "skipped": skip, "errors": err,
            "time_s": round(time_s, 1),
            "slowest": (f"{slowest.parser_id} ({slowest.duration_s:.0f}s)" if slowest else "-"),
        })

    incomplete = list(incomplete or [])
    damaged = list(damaged or [])
    broken = list(broken or [])
    waiting = list(waiting or [])
    finished = datetime.now(timezone.utc)
    summary = {
        "schema_version": SCHEMA_VERSION,
        # What produced this, because a summary that cannot be pinned to a build
        # is a summary nobody can reproduce. No hostname: the analyst's machine
        # name is not a thing this file needs to carry.
        "engine": {"version": __version__,
                   "python": platform.python_version(),
                   "os": platform.system(),
                   "os_release": platform.release()},
        "generated": now,
        "finished_at": _utc_z(finished),
        "started_at": _utc_z(started_at) if started_at else "",
        "duration_seconds": (round((finished - started_at).total_seconds(), 1)
                             if started_at else None),
        # The one field a caller can branch on, and the exit code is DERIVED from
        # it rather than computed a second time next to it -- see `cmd_run`. Two
        # expressions of the same verdict are two expressions that can disagree.
        #
        #   complete    at least one machine was triaged, every parser that
        #               ran finished, every delivered acquisition arrived and
        #               extracted whole, and every unit produced its outputs.
        #               `damaged_acquisitions` may still hold entries: the tree
        #               IS the whole archive, which is what this field claims,
        #               and a run cannot be called incomplete for a lock file
        #               that was open while it was copied (v0.7.86)
        #   incomplete  a parser errored, an acquisition did not extract whole or
        #               has not finished arriving, a unit's .db/.xlsx/report.txt
        #               was never built, or NO machine was detected at all;
        #               `errors`, `incomplete_acquisitions`,
        #               `waiting_acquisitions`, `broken_units` and `machines`
        #               say which
        #
        # A run that detected nothing is the third case and not a clean one: it
        # triaged no host, which is what pointing at the wrong folder, or at an
        # acquisition whose layout no profile covers, looks like. `complete` there
        # would be a machine-readable all-clear over a case nobody parsed.
        #
        # A parser whose tool binary is missing is an `error` here
        # (`runner._run_command`), so it does make a run incomplete -- on this
        # tree that is the honest answer, because `aeng setup` is the fix and the
        # run genuinely did not produce what it was asked for.
        #
        # A unit whose outputs were never built counts too (v0.7.79): its
        # parsers may all have finished, and the machine still has no .db to
        # query, no .xlsx to open and no report.txt to read. The tables it would
        # have been built from are on disk, which is why this is `incomplete`
        # rather than an error -- the run can be repeated without re-parsing.
        # An archive still arriving counts too (v0.7.82): the run left it closed
        # on purpose, so whatever it holds was not triaged, and a later run is what
        # opens it. `complete` there would be an all-clear over evidence nobody
        # has read yet.
        "status": ("incomplete" if (tot_err or incomplete or broken or waiting
                                    or not results)
                   else "complete"),
        "machines": len(results),
        "totals": {"ok": tot_ok, "cached": tot_cached,
                   "skipped": tot_skip, "errors": tot_err},
        "broken_units": broken,
        "per_machine": per_machine,
        "errors": errors,
        "incomplete_acquisitions": incomplete,
        # Whole trees holding a member that is not a faithful copy. Next to the
        # list above and not inside it: one says the acquisition is short, this
        # one says a named file in it is wrong, and only the first changes the
        # verdict (core/extractor.py `damaged_acquisitions`).
        "damaged_acquisitions": damaged,
        # Delivered archives no phase has touched: still being copied, or a seal
        # that does not match (core/arrival.py). Not hashed, not extracted.
        "waiting_acquisitions": waiting,
    }

    # Column widths grow with the data so long machine names never collide with
    # the next column (a 2-space gutter always separates them).
    mw = max((len(m["machine"]) for m in per_machine), default=7)
    mw = max(mw, len("Machine"))
    ow = max((len(m["os"]) for m in per_machine), default=2)
    ow = max(ow, len("OS"))
    lines = [
        "Artifact Engine - Run summary",
        "=" * 64,
        f"Generated: {now}",
        f"Machines : {len(results)}  |  OK {tot_ok} | skipped {tot_skip} | errors {tot_err}",
        "",
        f"  {'Machine':<{mw}}  {'OS':<{ow}}  {'OK':>4}{'Sk':>4}{'Er':>4}  {'Time':>7}  Slowest",
    ]
    for m in per_machine:
        lines.append(
            f"  {m['machine']:<{mw}}  {m['os']:<{ow}}  "
            f"{m['ok']:>4}{m['skipped']:>4}{m['errors']:>4}  {m['time_s']:>6.1f}s  {m['slowest']}"
        )
    if errors:
        lines += ["", "Errors:"]
        lines += [f"  {e['machine']:<{mw}}  {e['parser']:<22}{e['detail']}" for e in errors]
    else:
        lines += ["", "Errors: none"]

    # Above the table would be better still, but this file is appended to by eye
    # and the totals line is what people read first. What matters is that it is
    # HERE at all: without it the ok/skipped counts describe a triage, and a
    # triage of half an archive looks exactly like a triage of a quiet host.
    if incomplete:
        lines += ["", f"Acquisitions that did NOT extract whole: {len(incomplete)}",
                  "  The parsers below them ran on part of an archive. What they did",
                  "  not report is not a finding about the machine."]
        for a in incomplete:
            detail = f"  -- {a['detail']}" if a.get("detail") else ""
            lines.append(f"  {a['archive']}: {a['status']}{detail}")
    else:
        lines += ["", "Acquisitions that did NOT extract whole: none"]

    # Under the block above, and never merged into it. The usual cause is a file
    # an agent held open, which is why this does not touch the verdict; the whole
    # point of printing it is the unusual cause, where a parser reads a member
    # whose bytes were already wrong and writes a table over them.
    if damaged:
        lines += ["", ("Acquisitions holding a member that is not a faithful copy: "
                       f"{len(damaged)}"),
                  "  These extracted WHOLE. One member in each was read past the size",
                  "  the archive declared for it, or failed its checksum: collected",
                  "  while it was being written (a lock file, a .LOG1, a write-ahead",
                  "  log), or damaged. A parser over such a member does not fail --",
                  "  it reports, and nothing in its table says the bytes were wrong."]
        for a in damaged:
            detail = f"  -- {a['detail']}" if a.get("detail") else ""
            lines.append(f"  {a['archive']}: {a['status']}{detail}")

    # A machine can parse perfectly and still leave nothing to open. Named here
    # for the same reason as the block above: the ok/skipped table describes the
    # PARSING, and says nothing about whether the outputs it feeds were built.
    if broken:
        # Units, not entries: one unit can fail consolidation AND its report, and
        # a reader counting machines would then be told about two.
        hurt = len({b["unit"] for b in broken})
        lines += ["", f"Units whose outputs were NOT built: {hurt}",
                  "  Their parsed CSVs are on disk; the .db/.xlsx/report.txt are not.",
                  "  Re-running rebuilds them without re-parsing."]
        for b in broken:
            lines.append(f"  {b['unit']}: {b['stage']} -- {b.get('detail', '')}")

    # Named even though nothing under them was parsed -- BECAUSE nothing under
    # them was parsed. This file is the record of what the run covered, and an
    # archive it did not open is the one thing a reader cannot see for themselves
    # from the table above.
    if waiting:
        # "this run did not open them", not "nothing has ever read them": the same
        # archive may have been opened by an EARLIER run and be held now because a
        # seal arrived afterwards and does not match. What that run recorded is in
        # traces.csv and under the destination, and it is exactly what a mismatch
        # calls into question.
        lines += ["", f"Acquisitions this run did NOT open: {len(waiting)}",
                  "  Not hashed, not extracted and not parsed BY THIS RUN: they have",
                  "  not finished arriving. The next run looks at them again. If an",
                  "  earlier run opened one, what it recorded describes that copy."]
        for a in waiting:
            detail = f"  -- {a['detail']}" if a.get("detail") else ""
            lines.append(f"  {a['archive']}: {a['status']}{detail}")

    try:
        (root / "run-summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        (root / "run-summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError as e:
        # The exit code is derived from THIS dict and the file is what somebody
        # reads days later -- so a summary that did not land breaks exactly the
        # agreement this file exists to make. What is on disk now is the PREVIOUS
        # run's verdict, or half of this one (the .txt is written first). A run
        # whose own summary could not be written is not a complete run, and the
        # caller is told so through the one channel that still works.
        log.warning(f"[!] could not write run summary: {e}")
        summary["status"] = "incomplete"
        summary["summary_write_error"] = str(e)[:200]
    return summary
