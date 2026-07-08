"""Handler: hashes of on-disk executables collected by UAC (Linux).
Output: executable_hashes.csv (path, md5, sha1) for IOC matching.

UAC writes hash_executables.md5 / .sha1 as "<hash>  <path>" lines; we join them
on the path so each binary is one row with both digests.
"""

from __future__ import annotations

from artifact_engine.handlers._lincommon import read_lines, write_csv


def _load(path) -> dict[str, str]:
    out: dict[str, str] = {}
    for ln in read_lines(path):
        h, sep, p = ln.partition("  ")
        if sep and h:
            out[p.strip()] = h.strip()
    return out


def run(ctx) -> None:
    base = ctx.evidence / "hash_executables"
    md5 = _load(base / "hash_executables.md5")
    sha1 = _load(base / "hash_executables.sha1")
    rows = [[p, md5.get(p, ""), sha1.get(p, "")] for p in sorted(md5 | sha1)]
    write_csv(ctx.out, "executable_hashes.csv", ["path", "md5", "sha1"], rows)
