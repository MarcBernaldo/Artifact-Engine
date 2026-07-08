"""Phase 4 - Informative per-machine report (identity + execution).

Purely informative, no detections or severity. Includes the machine
identification and the detailed execution block: each parser with its status,
duration and, if it failed, the reason.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

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


def build(machine: Machine, runs: list[ParserRun]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    info = _machine_info(machine)
    os_str = " ".join(str(x) for x in (info.get("product_name"), info.get("build")) if x) or machine.os

    lines = [
        "Artifact Engine - Machine report",
        "=" * 60,
        f"Machine  : {info.get('machine_name') or machine.name}",
        f"OS       : {os_str}",
        f"Collector: {machine.collector}",
        f"Source   : {machine.source}",
        f"Volumes  : {', '.join(v.name for v in machine.volumes) or '-'}",
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
    skip = sum(1 for r in runs if r.status == "skipped")
    err = sum(1 for r in runs if r.status == "error")
    for r in runs:
        detail = f"  {r.detail}" if r.detail else ""
        lines.append(f"  {r.status.upper():8} {r.parser_id:<22} [{r.volume}] {r.duration_s:>6.1f}s{detail}")
    lines.append("")
    lines.append(f"Total: {len(runs)} parser(s) | OK {ok} | skipped {skip} | errors {err}")

    try:
        (machine.path / "report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as e:
        log.warning(f"[!] could not write report.txt for {machine.name}: {e}")


def build_run_summary(root: Path, results: list[tuple[Machine, list[ParserRun]]]) -> dict:
    """Root-level rollup across every machine -> run-summary.{txt,json}.

    Saves the cross-machine view (per-machine ok/skip/err, slowest parser, and the
    full error list) that otherwise only lived scattered in each run.json.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    per_machine, errors = [], []
    tot_ok = tot_skip = tot_err = 0
    for machine, runs in results:
        ok = sum(1 for r in runs if r.status == "ok")
        skip = sum(1 for r in runs if r.status == "skipped")
        err = sum(1 for r in runs if r.status == "error")
        tot_ok += ok
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
            "collector": machine.collector, "ok": ok, "skipped": skip, "errors": err,
            "time_s": round(time_s, 1),
            "slowest": (f"{slowest.parser_id} ({slowest.duration_s:.0f}s)" if slowest else "-"),
        })

    summary = {
        "generated": now,
        "machines": len(results),
        "totals": {"ok": tot_ok, "skipped": tot_skip, "errors": tot_err},
        "per_machine": per_machine,
        "errors": errors,
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

    try:
        (root / "run-summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        (root / "run-summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError as e:
        log.warning(f"[!] could not write run summary: {e}")
    return summary
