"""Handler: installed packages and package integrity (Linux/UAC). Outputs:
  packages.csv        - installed package inventory (dpkg -l or rpm -qa)
  package_verify.csv  - files that differ from the package manifest (tampering)

dpkg verify flags: e.g. '??5??????' (md5 differs), 'missing'. rpm verify flags:
e.g. '.M.......' (mode), '..5......' (md5/size). Modified files of a packaged
binary are a classic backdoor/implant indicator.
"""

from __future__ import annotations

from artifact_engine.handlers._lincommon import live_response, read_lines, write_csv
from datetime import datetime, timezone


def _epoch(s: str) -> str:
    try:
        return datetime.fromtimestamp(int(s), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, OverflowError):
        return ""


def _dpkg_list(lines: list[str], rows: list[list]) -> None:
    for ln in lines:
        # "ii  name  version  arch  description"; status starting with 'i' = installed
        parts = ln.split(None, 4)
        if len(parts) >= 4 and len(parts[0]) in (2, 3) and parts[0][0] == "i":
            rows.append([parts[1], parts[2], parts[3], "dpkg", ""])


def _rpm_list(lines: list[str], rows: list[list]) -> None:
    for ln in lines:
        # "installtime~name~version-release"
        p = ln.split("~")
        if len(p) >= 3:
            rows.append([p[1], "~".join(p[2:]), "", "rpm", _epoch(p[0])])


def _verify(lines: list[str], source: str, rows: list[list]) -> None:
    for ln in lines:
        s = ln.rstrip()
        if not s:
            continue
        parts = s.split(None, 2)
        if parts[0] == "missing" and len(parts) >= 2:
            rows.append([source, "missing", "", parts[1]])
        elif len(parts) == 3 and len(parts[1]) == 1:   # flags, attr-tag (c/g/d..), path
            rows.append([source, parts[0], parts[1], parts[2]])
        elif len(parts) >= 2:                            # flags, path (no attr tag)
            rows.append([source, parts[0], "", parts[-1]])


def run(ctx) -> None:
    lr = live_response(ctx.evidence)
    pkgs: list[list] = []
    verify: list[list] = []
    if lr:
        pk = lr / "packages"
        rpm_q = pk / "rpm_-q_-a_--queryformat_installtime_name_version_release.txt"
        if (pk / "dpkg_-l.txt").is_file():
            _dpkg_list(read_lines(pk / "dpkg_-l.txt"), pkgs)
            _verify(read_lines(pk / "dpkg_-V.txt"), "dpkg", verify)
        elif rpm_q.is_file():
            _rpm_list(read_lines(rpm_q), pkgs)
            _verify(read_lines(pk / "rpm_-V_-a.txt"), "rpm", verify)
    write_csv(ctx.out, "packages.csv",
              ["name", "version", "arch", "source", "install_time_utc"], pkgs)
    write_csv(ctx.out, "package_verify.csv",
              ["source", "flags", "attr", "path"], verify)
