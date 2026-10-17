"""Handler: what users did inside interactive tools other than the shell.
Output: app_history.csv

`shell_history` reads shell history. The shell is not the only prompt that remembers:
`.viminfo` names every file a user opened in vim, with its search terms and
`:` commands (an `:!` runs a shell command that bash never sees); `.lesshst`
keeps less's searches and its `!` shell commands; `.wget-hsts` lists every
HTTPS host wget fetched from, with when it was first seen; the REPLs and
database clients (python, mysql, psql, sqlite3, redis-cli, node) keep what was
typed into them -- including the query that dumped a table (backlog §43).

vim 8+ writes an epoch after each history entry and mark (`|2,...` / `|4,...`
lines), so most vim rows carry a time; wget's carries the HSTS creation time;
the plain histories carry none.

`flag` uses the same analyst-editable `assets/suspicious_tools.txt` labels as
`shell_history`, plus two of its own: `sensitive_file` (shadow, sudoers, SSH keys opened
in vim) and `log_edit` (a log or a shell history opened in vim -- reading a log
is what less is for; opening one in an editor is how lines disappear).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.handlers._indicators import load_indicators, match_labels
from artifact_engine.handlers._lincommon import read_lines, root, write_csv
from artifact_engine.handlers.lin_bash import _home_dirs

HEADER = ["id", "user", "tool", "kind", "value", "time_utc", "flag"]

# file name -> (tool, kind) for histories that are one entry per line
_PLAIN = {
    ".python_history": ("python", "command"),
    ".mysql_history": ("mysql", "query"),
    ".psql_history": ("psql", "query"),
    ".sqlite_history": ("sqlite3", "query"),
    ".rediscli_history": ("redis-cli", "command"),
    ".node_repl_history": ("node", "command"),
    ".dbshell": ("mongo", "command"),
}
_SENSITIVE = re.compile(r"(^|/)(shadow|gshadow|sudoers|sudoers\.d/.*|authorized_keys|"
                        r"id_(rsa|dsa|ecdsa|ed25519)|\.pgpass|\.my\.cnf|\.netrc)$")
_LOG_EDIT = re.compile(r"(^|/)var/log/|(^|/)\.(bash|zsh|sh|ash)_history$|(^|/)(wtmp|btmp|lastlog)$")
_FILE_MARK = re.compile(r"^'\S\s+\d+\s+\d+\s+(?P<path>.+)$")
_JUMP = re.compile(r"^-'\s+\d+\s+\d+\s+(?P<path>.+)$")


def _utc(epoch: str) -> str:
    try:
        n = int(epoch)
    except ValueError:
        return ""
    if n <= 0:
        return ""
    return datetime.fromtimestamp(n, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _viminfo(path: Path) -> list[tuple[str, str, str, str]]:
    """(tool, kind, value, time_utc). Sections by their `# ...` header; an entry's
    time is the epoch on the `|` line that follows it."""
    out: list[list[str]] = []
    section = ""
    last: list[str] | None = None
    for line in read_lines(path):
        if line.startswith("# "):
            section, last = line[2:].lower(), None
            continue
        if line.startswith("|"):
            parts = line[1:].split(",")
            if last is not None and not last[3]:
                if parts[0] == "2" and len(parts) > 2:        # history: |2,type,epoch,...
                    last[3] = _utc(parts[2])
                elif parts[0] == "4" and len(parts) > 4:      # mark: |4,mark,line,col,epoch,...
                    last[3] = _utc(parts[4])
            continue
        if last is not None and line.startswith("\t*\t"):     # mark history: \t*\t<epoch>\t0
            last[3] = last[3] or _utc(line.split("\t")[2])
            continue
        last = None
        if section.startswith("command line history") and line.startswith(":"):
            last = ["vim", "command", line[1:], ""]
        elif section.startswith("search string history") and line.startswith("?"):
            last = ["vim", "search", line[2:], ""]
        elif section.startswith("file marks"):
            m = _FILE_MARK.match(line)
            last = ["vim", "file", m["path"].strip(), ""] if m else None
        elif section.startswith("jumplist"):
            m = _JUMP.match(line)
            last = ["vim", "file", m["path"].strip(), ""] if m else None
        elif section.startswith("history of marks") and line.startswith("> "):
            last = ["vim", "file", line[2:].strip(), ""]
        if last is not None:
            out.append(last)
    # the same file appears in marks, jumplist and mark history: keep its newest time
    seen: dict[tuple[str, str], list[str]] = {}
    rows = []
    for r in out:
        if r[1] != "file":
            rows.append(r)
            continue
        prev = seen.get((r[1], r[2]))
        if prev is None:
            seen[(r[1], r[2])] = r
            rows.append(r)
        elif r[3] > prev[3]:
            prev[3] = r[3]
    return [tuple(r) for r in rows]


def _lesshst(path: Path) -> list[tuple[str, str, str, str]]:
    out = []
    section = ""
    for line in read_lines(path):
        if line.startswith("."):
            section = line[1:].strip().lower()
            continue
        if line.startswith('"') and section in ("search", "shell"):
            out.append(("less", "search" if section == "search" else "command", line[1:], ""))
        elif section == "mark" and line.startswith("m "):
            parts = line.split(None, 4)
            if len(parts) == 5:
                out.append(("less", "file", parts[4], ""))
    return out


def _wget_hsts(path: Path) -> list[tuple[str, str, str, str]]:
    """`host<TAB>port<TAB>include_subdomains<TAB>created<TAB>max_age`."""
    out = []
    for line in read_lines(path):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        host = parts[0] if parts[1] in ("0", "443") else f"{parts[0]}:{parts[1]}"
        out.append(("wget", "host", host, _utc(parts[3])))
    return out


def _plain(path: Path, tool: str, kind: str) -> list[tuple[str, str, str, str]]:
    out = []
    for line in read_lines(path):
        s = line.strip()
        if not s or s.startswith("_HiStOrY_V2_"):        # libedit's header (mysql, sqlite)
            continue
        if tool in ("mysql", "sqlite3"):
            s = s.replace("\\040", " ")                   # libedit escapes spaces
        out.append((tool, kind, s, ""))
    return out


def _entries(home: Path) -> list[tuple[str, str, str, str]]:
    rows: list[tuple[str, str, str, str]] = []
    if (home / ".viminfo").is_file():
        rows += _viminfo(home / ".viminfo")
    if (home / ".lesshst").is_file():
        rows += _lesshst(home / ".lesshst")
    if (home / ".wget-hsts").is_file():
        rows += _wget_hsts(home / ".wget-hsts")
    for name, (tool, kind) in _PLAIN.items():
        if (home / name).is_file():
            rows += _plain(home / name, tool, kind)
    return rows


def _flag(tools, tool: str, kind: str, value: str) -> str:
    labels = []
    if tools:            # a tool's name in a file path counts too
        labels += match_labels(tools, value)
    if tool == "vim" and kind == "file":
        if _SENSITIVE.search(value):
            labels.append("sensitive_file")
        if _LOG_EDIT.search(value):
            labels.append("log_edit")
    return "+".join(labels)


def run(ctx) -> None:
    tools = load_indicators(Path(ctx.assets) / "suspicious_tools.txt")
    rows = []
    seen: set[Path] = set()
    for user, home in _home_dirs(root(ctx.evidence)):
        rp = home.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        for seq, (tool, kind, value, when) in enumerate(_entries(home), 1):
            rows.append([seq, user, tool, kind, value, when, _flag(tools, tool, kind, value)])
    write_csv(ctx.out, "app_history.csv", HEADER, rows)
