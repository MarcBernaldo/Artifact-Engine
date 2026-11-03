"""One concept, one column name, in every table the engine writes (v0.7.185).

Before this, the time of an event was `time_utc` in one table, `timestamp` in the
next and `time` in a third; a remote address was `addr`, `address`, `client`, `ip`,
`srcip` or `source`; a command line `command`, `cmdline`, `cmd` or `command_line`.
An analyst who filters one table cannot reuse the filter on the next, and a SQL join
across tables has to know each table's dialect. The names now follow ECS (Elastic
Common Schema), flattened with `_` so SQLite and Excel take them unquoted, and the
vocabulary is ARCHITECTURE §5 "Field names".

The sweep reads the handlers' source with `ast`, not their output: every list or
tuple of strings assigned to a name containing `header` or `columns`, or passed
straight to `write_csv` / `stream_csv`, with `*NAME` spliced in from the same module.
The tables an external tool writes (EvtxECmd, MFTECmd, Volatility, ...) keep the
tool's own names and are not swept: no handler here declares their header.
"""

from __future__ import annotations

import ast
from pathlib import Path

HANDLERS = Path(__file__).resolve().parent.parent / "src" / "artifact_engine" / "handlers"

# a name that must not be a column -> the name the concept has (ARCHITECTURE §5)
RETIRED = {
    "time_utc": "timestamp_utc", "time_local": "timestamp_local", "time": "timestamp",
    "event_time_utc": "timestamp_utc", "time_kind": "timestamp_kind",
    "last_timestamp": "last_seen", "last_utc": "last_seen_utc",
    "start_time_utc": "start_utc", "end_time_utc": "end_utc",
    "started": "start", "started_utc": "start_utc", "started_local": "start_local",
    "create_time": "start", "exit_time": "end",
    "addr": "source_ip", "address": "destination_ip", "client": "source_ip",
    "local_addr": "local_ip", "remote_addr": "remote_ip",
    "srcip": "source_ip", "dstip": "destination_ip",
    "srcport": "source_port", "dstport": "destination_port", "port": "destination_port",
    "src": "source_ip", "dst": "destination_ip", "server": "destination_address",
    "computer": "host", "hostname": "host",
    "who": "user", "actor": "user", "account": "user / runas / target_user",
    "username": "user", "user_name": "user", "last_user_name": "user",
    "cmd": "command_line", "cmdline": "command_line", "command": "command_line",
    "parent_cmdline": "parent_command_line", "disk_command": "disk_command_line",
    "comm": "process", "process_name": "process",
    "exe": "path", "exe_deleted": "path_deleted", "image": "path", "parent_image": "parent_path",
    "executable_path": "path", "app_path": "path", "image_path": "path", "target_path": "path",
    "file": "path (the file a row is about) / source_file (the file it was read from)",
    "severity": "level", "list_severity": "list_level",
    "app_name": "process", "executable": "process", "dest": "path", "terminal": "tty",
    "run_time_local": "timestamp_local",
}


def _strings(node: ast.AST, consts: dict[str, list[str]]) -> list[str] | None:
    """The column names of a list/tuple literal, `*NAME` resolved; None if it is not one."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    out: list[str] = []
    for el in node.elts:
        if isinstance(el, ast.Constant) and isinstance(el.value, str):
            out.append(el.value)
        elif isinstance(el, ast.Starred) and isinstance(el.value, ast.Name) \
                and el.value.id in consts:
            out += consts[el.value.id]
        else:
            return None
    return out if len(out) >= 2 else None


def _headers(src: str) -> list[list[str]]:
    tree = ast.parse(src)
    consts: dict[str, list[str]] = {}
    for _ in range(2):          # twice: a constant may splice one defined after it
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                got = _strings(node.value, consts)
                if got is not None:
                    consts[node.targets[0].id] = got
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id.lower()
            if ("header" in name or "columns" in name) and node.targets[0].id in consts:
                found.append(consts[node.targets[0].id])
        elif isinstance(node, ast.Call):
            fn = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if fn in ("write_csv", "stream_csv") and len(node.args) >= 3:
                got = _strings(node.args[2], consts)
                if got is not None:
                    found.append(got)
    return found


def test_the_sweep_sees_the_tables():
    """A sweep that silently matched nothing would pass every check below."""
    seen = {c for f in HANDLERS.glob("*.py") for h in _headers(f.read_text(encoding="utf-8"))
            for c in h}
    assert {"timestamp_utc", "user", "source_ip", "command_line", "pid", "path", "level",
            "suspicious"} <= seen, sorted(seen)


def test_no_engine_table_uses_a_retired_column_name():
    bad = []
    for f in sorted(HANDLERS.glob("*.py")):
        for header in _headers(f.read_text(encoding="utf-8")):
            bad += [f"{f.name}: {c!r} -> {RETIRED[c]}" for c in header if c in RETIRED]
    assert not bad, "columns outside the vocabulary (ARCHITECTURE §5 Field names):\n" \
        + "\n".join(sorted(set(bad)))
