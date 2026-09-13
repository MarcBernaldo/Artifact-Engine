"""Logging setup: readable console + JSON log on disk (audit trail)."""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Where a record of every invocation lives, and what it is allowed to hold.
GLOBAL_LOG_ENV = "ARTIFACT_ENGINE_LOG_DIR"
GLOBAL_LOG_NAME = "aeng.log"
# Small on purpose. This file is an INDEX of invocations, not a second copy of the
# run log: one JSON line per start and per finish means 1 MiB is thousands of runs.
_GLOBAL_MAX_BYTES = 1024 * 1024
_GLOBAL_BACKUPS = 3
# Record attribute: "this line belongs in the global log". Handler attribute:
# "this handler is the per-case log". Both are read by the filter below.
_GLOBAL_MARK = "aeng_global"
_CASE_MARK = "aeng_case_log"

# Times the global log could not write. Counted rather than raised: see
# _QuietRotatingFileHandler.
_global_log_failures = 0


def _enable_windows_ansi() -> bool:
    """Turn on the console's virtual-terminal processing so ANSI colour codes are
    rendered instead of printed literally. The classic PowerShell/conhost window
    does NOT enable this by default, which is why colours showed up as raw
    `\\033[...m` garbage there. Returns True if colour output is safe to emit
    (always True off Windows); False if VT can't be enabled -> caller drops colour
    and prints clean plain text (never escape-code soup)."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)          # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False                             # not a real console (redirected)
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            return True
        return bool(kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    except Exception:  # noqa: BLE001 - any failure -> no colour, plain text
        return False

# ANSI colors for the console (disabled when stdout is not a TTY). Only the
# console formatter adds these; the on-disk log is JSON, so it stays clean.
# Razer brand palette: green #44D62C is the accent, gray for secondary detail,
# white text on the (black) terminal. Red/yellow are kept for error/warning
# semantics. Green uses 24-bit truecolor (supported by modern terminals).
RAZER_GREEN = "\033[38;2;68;214;44m"
_BOLD, _GRAY, _YELLOW, _RED, _MAGENTA, _RESET = (
    "\033[1m", "\033[90m", "\033[93m", "\033[91m", "\033[95m", "\033[0m")


class _ConsoleFormatter(logging.Formatter):
    def __init__(self, color: bool) -> None:
        super().__init__("%(message)s")
        self.color = color

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        if not self.color:
            return msg
        level = record.levelname
        if level == "WARNING":
            return f"{_YELLOW}{msg}{_RESET}"
        if level == "ERROR":
            return f"{_RED}{msg}{_RESET}"
        if level == "CRITICAL":
            return f"{_MAGENTA}{msg}{_RESET}"
        # INFO: visual hierarchy by prefix -- Razer-green phase headers, gray detail.
        if msg.startswith("[+]"):
            return f"{_BOLD}{RAZER_GREEN}{msg}{_RESET}"
        if msg.startswith(("[=]", "    ")):
            return f"{_GRAY}{msg}{_RESET}"
        return msg


# Count of benign unraisables dropped by the quiet hook. A plain int bumped under
# the GIL -- safe to touch from the GC context; reading it later (if ever) is
# best-effort. NOT logged from the hook (see _install_quiet_unraisablehook).
_suppressed_unraisables = 0


def _install_quiet_unraisablehook() -> None:
    """Silence a benign CPython artifact on Windows process pools.

    Under `ProcessPoolExecutor` on Windows/CPython 3.10 the interpreter prints
    `Exception ignored in tp_clear of: <class 'memoryview'>` / `BufferError:
    memoryview has N exported buffer(s)` to stderr during garbage collection: the
    cyclic GC clears a `memoryview` over an overlapped pipe-read buffer whose
    buffer the OS still has exported. It routes through `sys.unraisablehook`, is
    emitted from wherever the GC happened to fire (mp `_exhaustive_wait`, an
    `ExitStack` callback...), and is HARMLESS -- parser results are unaffected.

    Drop ONLY that exact case (BufferError about an exported buffer) and count it;
    everything else still goes to the default hook, so genuine unraisable
    exceptions are never hidden. Idempotent: safe to call from every
    `setup_logging`.

    CRITICAL: this hook runs from the cyclic GC, which can fire WHILE a thread is
    mid-write inside a logging handler's buffered stream. Calling `logging.*` here
    re-enters that same stream (whose buffer lock is not reentrant) and DEADLOCKS
    the whole run -- observed in the field: the on-disk log froze on this exact
    message while every parser worker sat idle. So the hook does NO I/O and NO
    logging: it just counts and returns. If a record is ever wanted, log the
    counter later from normal (non-GC) code.
    """
    hook = getattr(sys, "unraisablehook", None)
    if hook is None or getattr(hook, "_aeng_quiet", False):
        return
    original = hook

    # CPython words the same buffer-export conflict differently depending on which
    # object the GC reached, and the wording moved with the interpreter version:
    #   3.10, memoryview -> "memoryview has N exported buffer(s)"   (memoryobject.c)
    #   3.13, BytesIO    -> "Existing exports of data: object cannot be re-sized"
    # Matching only the first string meant the filter silently stopped working on
    # the migration to 3.13 -- observed in a real run, where raw tracebacks from
    # dataclasses.py, functools.py and textwrap.py landed in the middle of the
    # console output. Both phrases are CPython's own, both mean "a buffer is still
    # exported while the GC is clearing", and neither is a defect in this code.
    _EXPORT_CONFLICT = ("exported buffer", "existing exports of data")

    def _quiet(args):  # args: sys.UnraisableHookArgs
        exc = args.exc_value
        if isinstance(exc, BufferError) and any(
                s in str(exc).lower() for s in _EXPORT_CONFLICT):
            global _suppressed_unraisables
            _suppressed_unraisables += 1     # GIL-atomic; NEVER log/do I/O here
            return
        original(args)

    _quiet._aeng_quiet = True
    sys.unraisablehook = _quiet


class _JsonFormatter(logging.Formatter):
    """One JSON line per event, for audit/forensic reproducibility.

    `with_pid` is for the global log only, where the lines of concurrent runs on
    one host are interleaved and `started`/`finished` have to be pairable. The
    per-case log has one writer, so it does not need it.
    """

    def __init__(self, with_pid: bool = False) -> None:
        super().__init__()
        self.with_pid = with_pid

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if self.with_pid:
            payload["pid"] = record.process
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def user_log_dir() -> Path | None:
    r"""Where a record of every invocation lives, OUTSIDE any case.

    The per-case `aeng-run.log` is the one that belongs with the evidence, and it
    stays exactly where it is. It has one blind spot, and it is the one that
    matters when nobody is watching: a run that fails BEFORE a case root is known
    -- a mistyped path, a preflight abort, an argument the parser rejects -- has
    nowhere to write, so the only trace is stdout, and a scheduled task throws
    stdout away. An unattended failure that leaves no record reads exactly like a
    run that never started.

    Windows uses `%LOCALAPPDATA%\artifact-engine\logs` and not `%APPDATA%` (where
    the config lives) on purpose: a roaming profile copies APPDATA onto every
    machine the analyst signs into, and a record of what THIS host did is not
    something to spread across the others. Elsewhere it is `$XDG_STATE_HOME`,
    not the cache directory -- the spec says a cache may be deleted at any moment,
    and this file exists precisely to survive.

    `ARTIFACT_ENGINE_LOG_DIR` overrides it; set EMPTY it means "do not keep one",
    because an account with no writable profile is a real deployment, and so is an
    analyst who wants this on the evidence drive instead.
    """
    override = os.environ.get(GLOBAL_LOG_ENV)
    if override is not None:
        return Path(override) if override.strip() else None
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state")
    return Path(base) / "artifact-engine" / "logs"


def global_log_path() -> Path | None:
    """The file itself, or None when this machine keeps no global log."""
    directory = user_log_dir()
    return (directory / GLOBAL_LOG_NAME) if directory is not None else None


class _QuietRotatingFileHandler(RotatingFileHandler):
    """A log that never breaks the run it exists to record.

    `logging` reports a handler failure by printing to stderr, and a rollover is
    the one moment this handler touches a path another process may hold open: two
    runs on one host share this file, and on Windows the rename inside
    `doRollover` fails outright while a second process has it open. The record is
    worth having; it is not worth a traceback landing in the middle of the live
    progress bars, which repaint by counting lines and are corrupted by anything
    else that reaches the console.

    So a failure here is counted and dropped. The per-case log is unaffected: a
    different handler, on a path inside the case, that nothing else writes to.
    """

    def handleError(self, record: logging.LogRecord) -> None:
        global _global_log_failures
        _global_log_failures += 1


class _OnlyWhatNothingElseKeeps(logging.Filter):
    """What the global log takes -- and, more to the point, what it does not.

    Two things: the lifecycle records written by `log_globally`, and any warning
    or error raised while NO per-case log is attached yet. That second clause is
    the entire feature. It covers exactly the window in which nothing else is
    recording, and it closes the moment `aeng-run.log` opens.

    It deliberately does NOT mirror the run. Mirroring every warning of a real
    case would put hostnames, usernames and evidence paths into a file that lives
    outside the case directory and rotates out of the analyst's sight -- see "Case
    data never becomes text" in `CLAUDE.md`. What lands here is the case root the
    operator typed themselves, and the verdict.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, _GLOBAL_MARK, False):
            return True
        if record.levelno < logging.WARNING:
            return False
        return not any(getattr(h, _CASE_MARK, False)
                       for h in logging.getLogger("aeng").handlers)


def _attach_global_log(root: logging.Logger) -> None:
    """Best effort, and silent when it cannot: a missing global log must never be
    the reason a case does not get processed."""
    directory = user_log_dir()
    if directory is None:
        return
    try:
        directory.mkdir(parents=True, exist_ok=True)
        handler = _QuietRotatingFileHandler(
            directory / GLOBAL_LOG_NAME, maxBytes=_GLOBAL_MAX_BYTES,
            backupCount=_GLOBAL_BACKUPS, encoding="utf-8", delay=True)
    except OSError:
        return
    handler.setLevel(logging.DEBUG)
    handler.addFilter(_OnlyWhatNothingElseKeeps())
    handler.setFormatter(_JsonFormatter(with_pid=True))
    root.addHandler(handler)


def log_globally(msg: str, level: int = logging.INFO) -> None:
    """Write one lifecycle line to the global log and NOWHERE else.

    Handed straight to the handler rather than raised through the logger, for the
    same reason `log_file_only` does it: these lines are for the file, and an
    invocation banner repeated on the console is noise the operator did not ask
    for.
    """
    lg = logging.getLogger("aeng")
    rec = lg.makeRecord(lg.name, level, __name__, 0, msg, (), None)
    setattr(rec, _GLOBAL_MARK, True)
    for h in lg.handlers:
        if isinstance(h, _QuietRotatingFileHandler):
            h.handle(rec)


def console_supports_color() -> bool:
    """Whether ANSI is safe on this console: a real terminal, NO_COLOR unset, and
    VT actually enabled (on Windows this CALLS SetConsoleMode and checks it took).

    Exposed because the banner used to decide with `isatty()` alone. On a console
    that reports a TTY but cannot enable VT, that printed raw escape bytes for the
    banner and then correctly plain text for every log line after it -- the user
    sees the first few lines corrupted and the rest fine. It also meant NO_COLOR
    was honoured everywhere except the banner.
    """
    return (sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
            and _enable_windows_ansi())


def log_file_only(msg: str, logger: logging.Logger | None = None) -> None:
    """Emit a line ONLY to the on-disk log, never to the console.

    The live progress bars repaint by moving the cursor up over a known number of
    lines. Anything else writing to stdout in between lands inside that block and
    changes the line count without the painter knowing, so the anchor is off for
    every later repaint -- the bars stack and duplicate from that point on. The
    scheduler already routed its per-task tracing through here for exactly that
    reason; consolidation logged its per-unit failures straight to the console
    while its own bars were live.
    """
    lg = logger or logging.getLogger("aeng")
    rec = lg.makeRecord(lg.name, logging.DEBUG, __name__, 0, msg, (), None)
    for h in lg.handlers:
        if isinstance(h, logging.FileHandler):
            h.handle(rec)


def setup_logging(level: int = logging.INFO, log_file: Path | None = None) -> logging.Logger:
    # Force UTF-8 and immediate flushing so phase messages appear before their work
    # runs (avoids block-buffering that made output look out of order).
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace",
                               line_buffering=True, write_through=True)
    except Exception:  # noqa: BLE001
        pass

    _install_quiet_unraisablehook()

    root = logging.getLogger("aeng")
    root.setLevel(logging.DEBUG)
    # Closed, not just dropped. This is called twice per invocation now -- once in
    # `main` so the global log exists before the command runs, once by the command
    # with the case log it has by then found -- and a dropped FileHandler keeps its
    # descriptor open for the life of the process.
    for stale in root.handlers:
        if isinstance(stale, logging.FileHandler):
            stale.close()
    root.handlers.clear()

    color = console_supports_color()
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(_ConsoleFormatter(color))
    root.addHandler(console)

    _attach_global_log(root)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(_JsonFormatter())
        # Marked so the global log can tell that the evidence now has a log of its
        # own and stop duplicating warnings into a file outside the case.
        setattr(fh, _CASE_MARK, True)
        root.addHandler(fh)

    return root


def get_logger(name: str = "aeng") -> logging.Logger:
    return logging.getLogger(name)
