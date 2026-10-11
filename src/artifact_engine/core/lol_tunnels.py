"""LOTTunnels -> a local tool list, fetched at setup and never bundled (v0.7.102).

LOTTunnels (https://lottunnels.github.io) documents the tunnelling services an
intruder uses to reach into a network or carry data out of it -- ngrok,
cloudflared, chisel, frp, Dev Tunnels... -- one Markdown page per tool, with the
commands that run it and the domains it talks to.

It is licensed GPL-3.0, so unlike LOLRMM (Apache-2.0) and LOLExfil (MIT) no copy
of it, or of anything generated from it, is committed to this repository or
shipped with the package. `aeng setup` / `aeng update` download the repository's
archive and write `assets/lottunnels/tunnels.yaml` on the analyst's machine, in
the shape `win_rmm` reads (`name`, `files`, `paths`, `domains`); `.gitignore`
keeps that folder out of the repository.

`files` are what the pages say runs: each command's program and each
`Full_Path` file name, as `<name>.exe`. A program that is not the tunnel itself
(`ssh`, `curl`, `python`, `docker`...) or that two tools claim is left out --
those tunnels are found by their domains instead. `paths` stay empty: the
pages describe paths in prose. `domains` are kept as the page writes them and
normalised where they are read (`handlers/_domains.py`).
"""

from __future__ import annotations

import re
import zipfile
from collections import defaultdict
from pathlib import Path

import yaml

ASSET = "lottunnels/tunnels.yaml"
SOURCE_URL = "https://codeload.github.com/LOTTunnels/LOTTunnels.github.io/zip/refs/heads/main"

# The pages, inside the archive.
_PAGE = re.compile(r"(?:^|/)_lottunnels/Binaries/[^/]+\.md$")
# A page larger than this is not one of the project's pages.
_MAX_PAGE = 256 * 1024
# Programs a tunnel is run THROUGH, not the tunnel: its name says nothing.
_CARRIERS = {
    "ssh", "autossh", "curl", "wget", "python", "python3", "ruby", "docker", "npm",
    "npx", "cargo", "go", "composer", "openvpn", "cat", "sudo", "bash", "sh", "node",
    "java", "git", "pip", "powershell", "cmd", "code",
    # page placeholders and verbs, not programs
    "agent", "proxy", "shell", "ctrl", "accessing", "listener_add",
}
_PROGRAM = re.compile(r"[a-z0-9][a-z0-9_-]*")          # no dot: a script is not a program
_MIN_NAME = 4


def _front_matter(text: str) -> dict:
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}
    try:
        data = yaml.safe_load(parts[1])
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _program(token: str) -> str:
    """`C:\\x\\cloudflared.exe` / `./chisel` -> `cloudflared.exe` / `chisel.exe`, or ""."""
    name = str(token or "").strip().strip("\"'").lower().replace("\\", "/").rsplit("/", 1)[-1]
    stem = name.removesuffix(".exe")
    if not _PROGRAM.fullmatch(stem) or len(stem) < _MIN_NAME or stem in _CARRIERS:
        return ""
    return stem + ".exe"


def _entry(page: dict) -> dict | None:
    name = str(page.get("Name") or "").strip()
    if not name:
        return None
    files: list[str] = []
    for c in page.get("Commands") or []:
        words = str((c or {}).get("Command") or "").split()
        if words:
            files.append(_program(words[0]))
    for f in page.get("Full_Path") or []:
        files.append(_program((f or {}).get("Filename") or ""))
    domains: list[str] = []
    for d in page.get("Detection") or []:
        v = str((d or {}).get("Domain") or "").strip().lower()
        if v and v not in domains:
            domains.append(v)
    return {"name": name, "files": sorted({f for f in files if f}), "paths": [],
            "domains": domains}


def tunnels(pages: list[str]) -> list[dict]:
    """One entry per page; a file name two tools claim is dropped from both."""
    entries = [e for e in (_entry(_front_matter(t)) for t in pages) if e]
    claims: dict[str, set] = defaultdict(set)
    for e in entries:
        for f in e["files"]:
            claims[f].add(e["name"])
    for e in entries:
        e["files"] = [f for f in e["files"] if len(claims[f]) == 1]
    entries.sort(key=lambda e: e["name"].lower())
    return [e for e in entries if e["files"] or e["domains"]]


def from_zip(archive: Path) -> list[dict]:
    """The entries of a downloaded repository archive."""
    pages = []
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            if _PAGE.search(info.filename) and info.file_size <= _MAX_PAGE:
                pages.append(z.read(info).decode("utf-8", errors="replace"))
    return tunnels(pages)


def _yaml_list(items) -> str:
    return "[" + ", ".join(yaml.safe_dump(str(i), default_style='"').strip() for i in items) + "]"


def render(entries: list[dict], source_date: str) -> str:
    out = [
        "# Written by `aeng setup` / `aeng update` from LOTTunnels -- do not edit, do not commit.",
        f"# Source: {SOURCE_URL} (retrieved {source_date}).",
        "# LOTTunnels is licensed GPL-3.0 (https://github.com/LOTTunnels/LOTTunnels.github.io):",
        "# this file stays on this machine and is never shipped with Artifact Engine.",
        f"# {len(entries)} tools. files = the programs the pages run; domains as the pages",
        "# write them.",
        "tools:",
    ]
    for e in entries:
        out += [f"  - name: {_yaml_list([e['name']])[1:-1]}",
                f"    files: {_yaml_list(e['files'])}",
                "    paths: []",
                f"    domains: {_yaml_list(e['domains'])}"]
    return "\n".join(out) + "\n"


def same_tools(old: str, new: str) -> bool:
    """True when two rendered lists differ at most in their comment header."""
    def body(text: str) -> list[str]:
        return [ln for ln in text.splitlines() if not ln.startswith("#")]
    return body(old) == body(new)
