"""Handler: process-level rootkit / fileless anomalies. Output: proc_anomalies.csv

Hunt view over UAC's live_response/process (the `processes` parser is the
inventory). Only anomalies are emitted, FP-tuned against what real hosts show:

- exe symlink (running_processes_full_paths.txt): flags execution from memfd
  (fileless in-memory ELF) or from a world-writable temp dir. Excluded as
  benign: EDR memfd workers (Sophos), and the UAC collector's own files (it
  unpacks under /tmp/<tag>/uac-<ver>, the <tag> auto-detected per host). A
  deleted exe with a normal path is an in-place package update, not flagged.
- cwd (ls_-l_proc_pid_cwd.txt): a process whose working dir is /tmp, /var/tmp
  or /dev/shm (minus the collector's own tree).
- hidden PIDs (hidden_pids_for_ps_command.txt): UAC's raw list is noisy --
  short-lived workers (httpd/nginx prefork) race the ps snapshot and look
  "hidden". So it is not flagged on its own; instead a "[hidden from ps]" note
  enriches an exe anomaly when that PID is also hidden -- a process running from
  a suspicious location AND hidden is the strong, low-FP combination.
"""

from __future__ import annotations

import re

from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv

_PROC_PID = re.compile(r"/proc/(\d+)/(?:exe|cwd)")
# UAC unpacks to /tmp/<tag>/uac-<ver> (<tag> varies: incibe, gtic-336460, ...);
# treat the whole <tag> dir as collector space, not evidence.
_UAC_ROOT = re.compile(r"((?:/tmp|/var/tmp|/dev/shm)/[^/\s]+)/uac-\d")
_TMP = ("/tmp/", "/var/tmp/", "/dev/shm/")
_DELETED = " (deleted)"


def _link(line: str):
    """(pid, user, target) from an `ls -l` /proc/<pid>/{exe,cwd} symlink, or None
    (kernel threads have no '-> target')."""
    if " -> " not in line:
        return None
    left, _, target = line.partition(" -> ")
    m = _PROC_PID.search(left)
    if not m:
        return None
    parts = left.split()
    user = parts[2] if len(parts) > 2 else ""
    return m.group(1), user, target.strip()


def _clean(target: str) -> str:
    return target[: -len(_DELETED)].strip() if target.endswith(_DELETED) else target


def _is_edr_memfd(user: str, target: str) -> bool:
    # Sophos EDR runs its subprocesses from memfd -- legitimate, not an implant.
    return "sophos" in user.lower() or "sophos" in target.lower()


def _collector_roots(*line_lists) -> set:
    roots: set = set()
    for lines in line_lists:
        for ln in lines:
            m = _UAC_ROOT.search(ln)
            if m:
                roots.add(m.group(1))
    return roots


def _tmp_hit(path: str, roots: set) -> bool:
    return path.startswith(_TMP) and not any(path.startswith(r) for r in roots)


def _note(pid: str, hidden: set) -> str:
    return " [hidden from ps]" if pid in hidden else ""


def _exe(lines: list[str], rows: list[list], roots: set, hidden: set) -> None:
    for ln in lines:
        p = _link(ln)
        if not p:
            continue
        pid, user, target = p
        path = _clean(target)
        if "memfd:" in path and not _is_edr_memfd(user, target):
            rows.append(["exe_memfd", pid, user, target + _note(pid, hidden), "yes"])
        elif _tmp_hit(path, roots):
            rows.append(["exe_tmp", pid, user, target + _note(pid, hidden), "yes"])


def _cwd(lines: list[str], rows: list[list], roots: set) -> None:
    for ln in lines:
        p = _link(ln)
        if not p:
            continue
        pid, user, target = p
        if _tmp_hit(_clean(target), roots):
            rows.append(["cwd_tmp", pid, user, target, "yes"])


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    rows: list[list] = []
    if lr:
        proc = lr / "process"
        exe_lines = read_lines(proc / "running_processes_full_paths.txt")
        cwd_lines = read_lines(proc / "ls_-l_proc_pid_cwd.txt")
        hidden = {ln.strip() for ln in read_lines(proc / "hidden_pids_for_ps_command.txt")
                  if ln.strip().isdigit()}
        roots = _collector_roots(exe_lines, cwd_lines)
        _exe(exe_lines, rows, roots, hidden)
        _cwd(cwd_lines, rows, roots)
    rows.sort(key=lambda r: (r[0], int(r[1]) if r[1].isdigit() else 0))
    write_csv(ctx.out, "proc_anomalies.csv", ["kind", "pid", "user", "detail", "suspicious"], rows)
