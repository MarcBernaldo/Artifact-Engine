"""Handler: what containers wrote to stdout/stderr. Output: art_container_logs.csv

Two on-disk formats, every rotation:

  Kubernetes (CRI)   /var/log/pods/<namespace>_<pod>_<uid>/<container>/<n>.log[.<date>]
                     2026-10-11T14:32:52.123456789+02:00 stdout F the message
                     (`F` a full line, `P` a part of a longer one -- kept as written)
  Docker json-file   /var/lib/docker/containers/<id>/<id>-json.log[.<n>]
                     {"log":"the message\\n","stream":"stdout","time":"2026-10-11T12:32:52.1Z"}

/var/log/containers/*.log are links to the pod files; one that resolves to a
pod file already read is not read again. One row per line: time (UTC), stream,
partial, namespace, pod, container, message. No filtering, no flags.
"""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import iter_log_lines, root, sort_rotations

_HEADER = ["time_utc", "stream", "partial", "namespace", "pod", "container", "message", "source"]
_CRI = re.compile(r"^(\S+) (stdout|stderr) ([FP]) ?(.*)$")
_FRACTION = re.compile(r"(\.\d{1,6})\d*")


def _utc(ts: str) -> str:
    """RFC 3339 with any fraction (Docker trims zeros, the CRI writes nanoseconds)
    -> 'YYYY-MM-DD HH:MM:SS.ffffff' UTC, '' on a miss. The fraction is made six
    digits first: Python 3.10's fromisoformat takes only three or six."""
    t = _FRACTION.sub(lambda m: m.group(1).ljust(7, "0"), ts.replace("Z", "+00:00"), count=1)
    try:
        d = datetime.fromisoformat(t)
    except ValueError:
        return ""
    if d.tzinfo is None:
        return ""
    return d.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


_KUBELET = re.compile(r"^(\d+)\.log(?:\.(\d{8}-\d{6}))?")


def _pod_order(files):
    """kubelet names a container's log `<restart>.log` and rotates it to
    `<restart>.log.<YYYYMMDD-hhmmss>[.gz]`: restarts in order, and within one
    the rotations by their stamp before the file being written."""
    def key(f):
        m = _KUBELET.match(f.name)
        if not m:
            return (1 << 30, 1, f.name)
        return (int(m.group(1)), 0 if m.group(2) else 1, m.group(2) or "")
    return sorted(files, key=key)


def _resolved(f):
    try:
        return f.resolve()
    except OSError:
        return f


def _groups(evidence):
    """(kind, labels, files oldest-first) per log stream."""
    r = root(evidence)
    seen: set = set()
    pods = r / "var" / "log" / "pods"
    if pods.is_dir():
        for cdir in sorted(p for p in pods.glob("*/*") if p.is_dir()):
            ns, _, rest = cdir.parent.name.partition("_")
            pod = rest.rsplit("_", 1)[0]
            files = [f for f in cdir.iterdir() if f.is_file() and ".log" in f.name]
            seen.update(_resolved(f) for f in files)
            if files:
                yield "cri", (ns, pod, cdir.name), _pod_order(files)
    links = r / "var" / "log" / "containers"
    if links.is_dir():
        for f in sorted(links.glob("*.log*")):
            if f.is_file() and _resolved(f) not in seen:
                pod, ns, rest = (f.name.split("_", 2) + ["", ""])[:3]
                yield "cri", (ns, pod, rest.rsplit("-", 1)[0]), [f]
    docker = r / "var" / "lib" / "docker" / "containers"
    if docker.is_dir():
        for cdir in sorted(p for p in docker.iterdir() if p.is_dir()):
            files = [f for f in cdir.iterdir() if f.is_file() and "-json.log" in f.name]
            if files:
                yield "docker", ("", "", cdir.name), sort_rotations(files)


def _cri(line: str) -> tuple[str, str, str, str]:
    m = _CRI.match(line)
    if not m:
        return "", "", "", line
    return _utc(m.group(1)), m.group(2), "yes" if m.group(3) == "P" else "", m.group(4)


def _docker(line: str) -> tuple[str, str, str, str]:
    try:
        d = json.loads(line)
    except ValueError:
        return "", "", "", line
    if not isinstance(d, dict):
        return "", "", "", line
    msg = str(d.get("log", ""))
    partial = "" if msg.endswith("\n") else "yes"
    return _utc(str(d.get("time", ""))), str(d.get("stream", "")), partial, msg.rstrip("\r\n")


def run(ctx) -> None:
    groups = list(_groups(ctx.evidence))
    if not groups:
        raise HandlerSkip("no container logs")
    ctx.out.mkdir(parents=True, exist_ok=True)
    out = ctx.out / "art_container_logs.csv"
    rows = 0
    try:
        with open(out, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(_HEADER)
            for kind, (ns, pod, container), files in groups:
                parse = _cri if kind == "cri" else _docker
                for f in files:
                    src = str(f.relative_to(ctx.evidence))
                    for line in iter_log_lines(f):
                        if not line.strip():
                            continue
                        t, stream, partial, msg = parse(line.rstrip("\r"))
                        w.writerow([t, stream, partial, ns, pod, container, msg, src])
                        rows += 1
    except BaseException:
        out.unlink(missing_ok=True)
        raise
    if rows == 0:
        out.unlink(missing_ok=True)
    if ctx.log:
        ctx.log.debug(f"art_container_logs: {rows} line(s) from {len(groups)} stream(s)")
