"""Logging setup: readable console + JSON log on disk (audit trail)."""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


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

    def _quiet(args):  # args: sys.UnraisableHookArgs
        exc = args.exc_value
        if isinstance(exc, BufferError) and "exported buffer" in str(exc):
            global _suppressed_unraisables
            _suppressed_unraisables += 1     # GIL-atomic; NEVER log/do I/O here
            return
        original(args)

    _quiet._aeng_quiet = True
    sys.unraisablehook = _quiet


class _JsonFormatter(logging.Formatter):
    """One JSON line per event, for audit/forensic reproducibility."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


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
    root.handlers.clear()

    # Colour only when writing to a real terminal, NO_COLOR isn't set, and the
    # console can render ANSI (enables VT on Windows; falls back to plain text).
    color = (sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
             and _enable_windows_ansi())
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(_ConsoleFormatter(color))
    root.addHandler(console)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(_JsonFormatter())
        root.addHandler(fh)

    return root


def get_logger(name: str = "aeng") -> logging.Logger:
    return logging.getLogger(name)
