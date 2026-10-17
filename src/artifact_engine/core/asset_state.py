"""Which analyst-editable assets a parser reads, and whether they changed since it ran.

A parser's `.done` fingerprint covers its manifest and its code, not the lists
under the assets dir it reads at run time (`suspicious_tools.txt`,
`web_suspicious.txt`, the YARA rules, the LOL catalogs, ...). Editing one used
to reach a case already parsed only with `--force`, and nothing said so: the
tables kept matching the old list (v0.7.160).

What a parser reads is taken from the code the fingerprint already hashes: an
asset is read when its whole name (a file's with its extension) stands as a
string literal or a path component in the handler's import closure, or in a
command parser's command line. A name matched by accident only costs a re-run.
Not followed: the IP-origin databases and the Tor exit list, which `aeng update`
refreshes and which only add context to a row -- `Geo` sits in `_webcommon`, which
two dozen parsers import for other things, so following them would re-run those
on every update. The digest of the followed files' content, taken when the
parser is dispatched, goes in `.<id>.assets` after every `ok` run -- `-` for one
that reads none, so a list that appears later, or the last one it read being
deleted, is a change. Any other end puts back what the record held: a skip
leaves the old tables, whatever caused it. Beside the marker, not in it: the
marker's modification time is what orders a dependent against what it reads
(`scheduler._older_than_a_dependency`).

A parser that completed before this existed has a marker and no record. It
adopts the assets as they are now rather than re-running: a re-parse of every
case on upgrade, YARA included, to find out whether a list changed in between
is the cost this would otherwise add. One gap of the same shape is left: a
first run whose result never reached the parent (it crashed) on a category
folder that did not exist yet when it was dispatched -- `begin` creates no
folder -- leaves a marker and no record, and adopts too. Kept here, not in
`runner`, because every handler imports `runner`, so a change there re-parses
everything.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from artifact_engine.core import runner
from artifact_engine.models import ParserManifest

_TOKEN = re.compile(rb"""(?<=["'/])([\w.-]+)(?=["'/])""")
_NOT_FOLLOWED = re.compile(r"\.mmdb(\.ym)?$|^tor-exit-nodes\.txt$")
_TOKENS: dict[tuple, set[bytes]] = {}
NONE = "-"
# Written at dispatch, replaced when the result is in: a run whose result never
# reached the parent (it crashed, or was stopped) left a marker and this, which
# matches no state, so the next run runs it again instead of adopting.
RUNNING = "?"


def record_path(out_dir: Path, parser_id: str) -> Path:
    return Path(out_dir) / f".{parser_id}.assets"


def _entries(assets: Path) -> list[str]:
    """Listed each time, not kept: a list `aeng update` writes appears mid-session."""
    try:
        return sorted(p.name for p in Path(assets).iterdir())
    except OSError:
        return []


def _tokens(parser: ParserManifest) -> set[bytes]:
    key = (parser.handler, repr(parser.command))
    if key not in _TOKENS:
        text = runner._handler_closure(parser.handler) if parser.handler else b""
        text += repr(parser.command).encode("utf-8")
        _TOKENS[key] = set(_TOKEN.findall(text))
    return _TOKENS[key]


def used(parser: ParserManifest, assets: Path) -> list[str]:
    """The top-level entries of `assets` this parser reads."""
    tokens = _tokens(parser)
    return [n for n in _entries(assets)
            if n.encode("utf-8") in tokens and not _NOT_FOLLOWED.search(n)]


def _file_digest(f: Path) -> str:
    """Read every time, not kept by size and mtime: a same-size edit within one
    timestamp tick would read as unchanged. The YARA set, the largest, is ~70 ms."""
    h = hashlib.sha1()
    try:
        with open(f, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return "-"
    return h.hexdigest()


def digest(parser: ParserManifest, assets: Path) -> str:
    """Digest of the content of every asset the parser reads; `NONE` when it reads
    none -- a state of its own, so a list that appears later, or the last one it
    read being deleted, is a change too."""
    names = used(parser, assets)
    if not names:
        return NONE
    h = hashlib.sha1()
    for n in names:
        p = Path(assets) / n
        files = sorted(f for f in p.rglob("*") if f.is_file()) if p.is_dir() else [p]
        for f in files:
            h.update(f"{f.relative_to(assets).as_posix()}\0{_file_digest(f)}\n".encode())
    return h.hexdigest()[:16]


def unchanged(parser: ParserManifest, out_dir: Path, assets: Path) -> bool:
    """True when the assets the parser reads are what it last ran with. A parser
    with a marker and no record adopts them as they are (see the module doc):
    every run dispatched since v0.7.160 leaves one, so a marker from before has
    none (or the crashed first run the module doc names)."""
    now = digest(parser, assets)
    path = record_path(out_dir, parser.id)
    try:
        return path.read_text(encoding="utf-8").strip() == now
    except FileNotFoundError:
        record(out_dir, parser.id, now)
        return True
    except (OSError, ValueError):
        return False


def begin(out_dir: Path, parser_id: str) -> str | None:
    """At dispatch: mark the record `RUNNING` and return what it held (None: none)."""
    path = record_path(out_dir, parser_id)
    try:
        before = path.read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        before = None
    if Path(out_dir).is_dir():
        record(out_dir, parser_id, RUNNING)
    return before


def record(out_dir: Path, parser_id: str, value: str | None) -> None:
    """The state its assets were in when it was dispatched -- taken then, not at
    the end, so a list edited while it ran is a change next time -- after a run
    that ended `ok`; after any other end, what the record held before.
    None removes it."""
    path = record_path(out_dir, parser_id)
    try:
        if value is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(value, encoding="utf-8")
    except OSError:
        pass
