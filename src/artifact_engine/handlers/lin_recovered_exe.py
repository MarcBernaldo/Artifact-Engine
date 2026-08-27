r"""Handler: the binaries UAC rescued out of /proc. Output: recovered_exe.csv

`live_response/process/proc/<pid>/recovered_exe` is the executable copied back
out of `/proc/<pid>/exe` while the process was running -- INCLUDING when the
file had already been unlinked from disk. For a payload that deletes itself
after execution, that copy is the only one that exists anywhere, and the engine
never opened it: `lin_hashes` reads the digests UAC precomputes for executables
ON DISK, and a deleted binary is by definition not in that list.

So this hashes them and says which process each belonged to. That is all it
does, and it is deliberately all it does: the row is an IOC with provenance,
not a verdict.

WHY THE SIZE IS A COLUMN AND NOT A DETAIL. Implants in a family are commonly
rebuilt per host -- same code, different padding, different hash. The digests
then agree with nothing and the size still does, so the size is the join that
survives repacking. Cross-host, that join is one command over the case:

    aeng sweep -p <case> -q <size>       # or -q <sha256>

which is why the grouping lives there and not here. A parser sees one machine;
what makes two hosts the same intrusion is a question about the case.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from artifact_engine.handlers._lincommon import live_response, read_text, write_csv
from artifact_engine.handlers.lin_proc_identity import (
    exe_by_pid,
    pid_dirs,
    read_argv,
    read_status,
)

_NAME = "recovered_exe"
_DELETED = " (deleted)"
_BUF = 1 << 20


def _digests(path: Path) -> tuple[str, str, int]:
    """(md5, sha256, size). MD5 because that is what most shared intel is still
    keyed by; SHA-256 because MD5 is not an identity. ('', '', 0) if unreadable.
    """
    md5, sha = hashlib.md5(), hashlib.sha256()
    size = 0
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(_BUF), b""):
                md5.update(chunk)
                sha.update(chunk)
                size += len(chunk)
    except OSError:
        return "", "", 0
    return md5.hexdigest(), sha.hexdigest(), size


def recovered_binaries(evidence: Path) -> list[tuple[str, Path]]:
    """(pid, path) for every rescued binary in the acquisition, PID order.

    Shared with `lin_yara`, which scans these files -- and only these. The rest
    of the per-PID tree is memory strings and maps: running malware rules over a
    dump of a process's memory matches whatever that process happened to be
    holding, which on an EDR agent is a signature database.
    """
    lr = live_response(evidence)
    if not lr:
        return []
    out = []
    for d in pid_dirs(lr / "process" / "proc"):
        f = d / _NAME
        if f.is_file():
            out.append((d.name, f))
    return out


def run(ctx) -> None:
    found = recovered_binaries(ctx.evidence)
    if not found:
        return
    lr = live_response(ctx.evidence)
    exes = exe_by_pid(lr) if lr else {}

    rows: list[list] = []
    for pid, f in found:
        d = f.parent
        argv = read_argv(d / "cmdline.txt")
        comm = read_text(d / "comm.txt").strip() or read_status(d / "status.txt").get("Name", "")
        raw_exe = exes.get(pid, "")
        md5, sha256, size = _digests(f)
        if not sha256:
            # The file is there and could not be read. Left in the CSV with empty
            # digests rather than dropped: a row with a hole in it can be chased,
            # and a rescued implant that silently never appeared cannot.
            ctx.log.warning(f"[!] recovered_exe: could not read {pid}/{_NAME}")
        rows.append([pid, comm, argv[0] if argv else "", raw_exe,
                     "yes" if raw_exe.endswith(_DELETED) else "",
                     size, md5, sha256])

    write_csv(ctx.out, "recovered_exe.csv",
              ["pid", "comm", "argv0", "exe", "exe_deleted", "size", "md5", "sha256"],
              rows)
