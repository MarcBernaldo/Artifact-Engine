"""Turn a LOL catalog's published JSON into a bundled asset (v0.7.100).

    python -m artifact_engine.core.lol_import rmm <rmm_tools.json> [--source-date YYYY-MM-DD]
    python -m artifact_engine.core.lol_import exfil <tools.json>     (LOLExfil, v0.7.101;
                                                                      see core/lol_exfil.py)

LOLRMM (https://lolrmm.io, Apache-2.0) publishes every remote-monitoring and
remote-access tool it documents at https://lolrmm.io/api/rmm_tools.json. This
reads that file and writes `data/assets/rmm_lolrmm.yaml` in the shape `win_rmm`
already reads (`files` = exact executable basenames, `paths` = install-folder
substrings), plus each tool's `domains` for the network side.

Kept deliberately narrow, because a name that matches everything is worse than
no name at all:
  - a file name two or more tools claim (`agent.exe`), or one in _GENERIC, is
    left out -- the install path still identifies the tool;
  - a path keeps only the folder right under a well-known root (`Program Files`,
    `ProgramData`, `AppData\\Local`...), up to its first wildcard, and only if
    what is left is distinctive (_MIN_PATH characters, not a shared vendor
    folder such as `Microsoft`).
The hand-curated `rmm_tools.yaml` stays and is read first.

An entry holding a term this repository's publication filter blocks
(`.claude/githooks/aeng_hooks.py`, when the checkout has it) is left out of the
generated file, and the header says how many were -- the same rule the bundled
Sigma rules follow.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.config import DATA_DIR
from artifact_engine.core import lol_exfil

ASSET = "rmm_lolrmm.yaml"
SOURCE_URL = "https://lolrmm.io/api/rmm_tools.json"

# Executable names too common to point at one tool on their own -- Windows's own
# binaries the catalog lists because a tool rides on them (svchost, mstsc, dwm),
# other software's (PowerToys, a screen reader), and plain words.
_GENERIC = {
    "svchost.exe", "dwm.exe", "mstsc.exe", "mousewithoutborders.exe", "nvda.exe",
    "plink.exe", "upload.exe", "autoupdate.exe", "selfupdater.exe", "update-shim.exe",
    "rmm.exe", "si.exe", "goto.exe", "level.exe", "amon.exe", "appcore.exe",
    "closeapp.exe", "cpuchk.exe", "httpget.exe", "httppush.exe", "recycler.exe",
    "regapps.exe", "prep64.exe", "pidupdater.exe", "notificationhelper.exe",
    "installcore.exe", "installshield setup.exe", "iprangecalculator.exe",
    "agent-installer-any.exe", "agent-windows-amd64.exe", "dashboard-windows-amd64.exe",
    "agent.exe", "setup.exe", "client.exe", "service.exe", "server.exe", "update.exe",
    "updater.exe", "launcher.exe", "installer.exe", "install.exe", "helper.exe",
    "host.exe", "viewer.exe", "remote.exe", "app.exe", "main.exe", "run.exe",
    "start.exe", "uninstall.exe", "uninst.exe", "unins000.exe", "support.exe",
    "connect.exe", "monitor.exe", "manager.exe", "console.exe", "tray.exe",
    "svc.exe", "srv.exe", "daemon.exe", "core.exe", "launch.exe",
    # measured on a real case (v0.7.103): any program's window
    "gui.exe",
}
# Folders under which an install folder is the tool's own.
_ROOTS = ("program files (x86)", "program files", "programdata", "appdata\\local",
          "appdata\\roaming", "appdata\\locallow", "windows\\temp", "users\\public")
# Vendor or system folders many unrelated tools share.
_SHARED = {"microsoft", "windows", "common files", "google", "temp", "system32",
           "syswow64", "packages", "programs",
           # measured in the catalog: folders other software also installs into
           "package cache", "microsoft garage", "yandex", "inventec", "sysprogs",
           "vector",
           # a vendor's folder holding many products, only one of them remote access
           # (measured on a real case once ShimCache was searched too, v0.7.103)
           "manageengine", "solarwinds"}
_MIN_PATH = 5
# Environment variables the catalog writes paths with, as the folders they name.
_ENV = {"%programfiles(x86)%": r"\program files (x86)", "%programfiles%": r"\program files",
        "%programdata%": r"\programdata", "%localappdata%": r"\appdata\local",
        "%appdata%": r"\appdata\roaming", "%public%": r"\users\public",
        "%userprofile%": "", "%systemdrive%": ""}


def _names(tool: dict) -> set[str]:
    meta = (tool.get("Details") or {}).get("PEMetadata") or []
    meta = meta if isinstance(meta, list) else [meta]
    out: set[str] = set()
    for m in meta:
        for key in ("Filename", "OriginalFileName"):
            v = str((m or {}).get(key) or "").strip().lower()
            v = v.replace("/", "\\").rsplit("\\", 1)[-1]
            if v.endswith(".exe") and "*" not in v and len(v) > 4:
                out.add(v)
    return out


def _path_key(raw: str) -> str:
    """The install folder as a match key, or "".

    `C:\\Program Files\\AnyDesk\\*` -> `\\anydesk\\` (the whole folder, so `\\level\\`
    never matches `\\levelup`); `...\\AnyDesk-*\\...` -> `\\anydesk-` (open only where
    the catalog itself says the name continues)."""
    p = str(raw or "").replace("/", "\\").lower()
    p = re.sub(r"^[a-z]:", "", p)
    for var, root in _ENV.items():                        # %programdata% -> its folder
        p = p.replace(var, root)
    p = re.sub(r"%[a-z_()0-9]+%", "", p)                 # any other variable
    p = re.sub(r"\\users\\[^\\]+\\", r"\\", p)            # a user's profile folder
    for root in _ROOTS:
        i = p.find("\\" + root + "\\")
        if i < 0:
            continue
        rest = p[i + len(root) + 2:]
        component = rest.split("\\", 1)[0]
        # a placeholder the catalog writes for an install-specific suffix
        cut = re.split(r"[*(<\[{]", component, maxsplit=1)
        folder = cut[0].strip()
        open_end = len(cut) > 1
        if len(folder) < _MIN_PATH or folder in _SHARED:
            return ""
        return "\\" + folder if open_end else "\\" + folder + "\\"
    return ""


def _domains(tool: dict) -> list[str]:
    out: list[str] = []
    for n in (tool.get("Artifacts") or {}).get("Network") or []:
        for d in (n or {}).get("Domains") or []:
            d = str(d).strip().lower()
            if d and d not in out:
                out.append(d)
    return out


def rmm(catalog: list[dict]) -> list[dict]:
    """The tools, in the shape `win_rmm` reads."""
    claims = Counter(n for t in catalog for n in _names(t))
    tools = []
    for t in catalog:
        files = sorted(n for n in _names(t) if claims[n] == 1 and n not in _GENERIC)
        paths = sorted({k for k in (_path_key(p) for p in
                                    (t.get("Details") or {}).get("InstallationPaths") or [])
                        if k})
        domains = _domains(t)
        if files or paths or domains:
            tools.append({"name": str(t.get("Name") or "?").strip(), "files": files,
                          "paths": paths, "domains": domains})
    tools.sort(key=lambda x: x["name"].lower())
    return tools


def _publication_filter():
    """The repository's blocklist matcher, or None outside a checkout."""
    hook = DATA_DIR.parents[2] / ".claude" / "githooks" / "aeng_hooks.py"
    if not hook.is_file():
        return None
    spec = importlib.util.spec_from_file_location("aeng_hooks", hook)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, "matching_lines", None)


def _yaml_list(items: list[str]) -> str:
    return "[" + ", ".join(json.dumps(i) for i in items) + "]"


def _entry(t: dict) -> list[str]:
    return [f"  - name: {json.dumps(t['name'])}",
            f"    files: {_yaml_list(t['files'])}",
            f"    paths: {_yaml_list(t['paths'])}",
            f"    domains: {_yaml_list(t['domains'])}"]


def render(tools: list[dict], source_date: str, blocked=None) -> str:
    entries = [_entry(t) for t in tools]
    kept = [e for e in entries if not (blocked and blocked("\n".join(e)))]
    left_out = len(entries) - len(kept)
    lines = [
        "# GENERATED by `python -m artifact_engine.core.lol_import rmm` -- do not edit;",
        "# add hand-picked entries to rmm_tools.yaml instead, which is read first.",
        f"# Source: LOLRMM, {SOURCE_URL} (retrieved {source_date}).",
        "# LOLRMM is licensed Apache-2.0 (https://github.com/magicsword-io/LOLRMM).",
        f"# {len(kept)} tools. files = exact executable basenames claimed by one tool",
        "# only; paths = install-folder substrings; domains = the tool's own endpoints.",
    ]
    if left_out:
        lines.append(f"# {left_out} catalog tool(s) left out: they hold a term this "
                     "repository's publication filter blocks.")
    lines.append("tools:")
    for e in kept:
        lines.extend(e)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="lol_import")
    ap.add_argument("catalog", choices=["rmm", "exfil"])
    ap.add_argument("json", type=Path)
    ap.add_argument("--source-date",
                    default=datetime.now(timezone.utc).date().isoformat())
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args(argv)
    data = json.loads(a.json.read_text(encoding="utf-8"))
    if a.catalog == "exfil":
        out = a.out or DATA_DIR / "assets" / lol_exfil.ASSET
        entries = lol_exfil.exfil(data)
        total = sum(len(t.get("endpoint_detection_patterns") or []) for t in data)
        text = lol_exfil.render(entries, a.source_date, total, _publication_filter())
        out.write_text(text, encoding="utf-8")
        print(f"{out}: {text.count(chr(10) + '  - tool: ')} of {total} patterns written")
        return 0
    a.out = a.out or DATA_DIR / "assets" / ASSET
    tools = rmm(data)
    text = render(tools, a.source_date, _publication_filter())
    a.out.write_text(text, encoding="utf-8")
    print(f"{a.out}: {text.count(chr(10) + '  - name: ')} of {len(tools)} tools written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
