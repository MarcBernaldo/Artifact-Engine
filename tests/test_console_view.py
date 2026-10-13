"""v0.7.121: the live bars survive log lines, narrow windows and their own end.

What Progress writes is played into a small terminal emulator, and the test
reads the SCREEN the analyst would see -- not the byte stream, where a repaint
that lands on the wrong rows looks just as correct as one that does not."""
from __future__ import annotations

import io
import logging
import os
import re
import sys

from artifact_engine.core import progress as pg
from artifact_engine.core.progress import Progress

_ESC = re.compile(r"\x1b\[(\d*)([A-Za-z])")


def _screen(stream: str) -> list[str]:
    """Rows of a terminal fed `stream`: text, newline, CR, cursor up (A),
    erase line (K), erase to end of screen (J); colour (m) is ignored."""
    rows, row, i = [""], 0, 0
    while i < len(stream):
        mo = _ESC.match(stream, i)
        if mo:
            n, op = int(mo.group(1) or 1), mo.group(2)
            if op == "A":
                row = max(0, row - n)
            elif op == "K":
                rows[row] = ""
            elif op == "J":
                rows[row] = ""
                del rows[row + 1:]
            i = mo.end()
            continue
        ch = stream[i]
        if ch == "\n":
            row += 1
            while len(rows) <= row:
                rows.append("")
        elif ch != "\r":
            rows[row] += ch
        i += 1
    while rows and not rows[-1].strip():
        rows.pop()
    return rows


class _Tty(io.StringIO):
    encoding = "utf-8"

    def isatty(self) -> bool:
        return True


def _window(monkeypatch, cols: int, lines: int) -> _Tty:
    tty = _Tty()
    monkeypatch.setattr(sys, "stdout", tty)
    monkeypatch.setattr(pg.shutil, "get_terminal_size",
                        lambda *_: os.terminal_size((cols, lines)))
    return tty


def test_a_log_line_lands_above_the_bars_and_each_bar_is_drawn_once(monkeypatch):
    """A parser's warning, replayed while the bars are live, went to the console
    handler's stdout INSIDE the painted block; the next repaint then started one
    row low, left a stale copy of the block above and overwrote the warning."""
    tty = _window(monkeypatch, 120, 40)
    log = logging.getLogger("aeng")
    handler = logging.StreamHandler(tty)
    log.addHandler(handler)
    try:
        p = Progress(["HOST-01", "HOST-02"], [3, 3])
        p.start()
        p.update(0, done=1)
        log.warning("[!] first warning")
        p.update(1, done=2)
        log.warning("[!] second warning")
        p.update(0, done=3, status="done")
        p.update(1, done=3, status="done")
        p.stop()
        assert handler.stream is tty, "stop() must give the handler its stream back"
    finally:
        log.removeHandler(handler)

    rows = _screen(tty.getvalue())
    for text in ("HOST-01", "HOST-02", "[!] first warning", "[!] second warning"):
        assert sum(text in r for r in rows) == 1, (text, rows)
    first = next(i for i, r in enumerate(rows) if "first warning" in r)
    bar = next(i for i, r in enumerate(rows) if "HOST-01" in r)
    assert first < bar, rows


def test_the_summary_line_fits_a_narrow_window(monkeypatch):
    """It was the one composed line never trimmed to the width; wrapped, it is two
    screen rows the painter counts as one."""
    _window(monkeypatch, 60, 24)
    p = Progress([f"HOST-{i:02d}" for i in range(38)], [120] * 38)
    line = re.sub(r"\x1b\[[0-9;]*m", "", p._summary_line())
    assert len(line) <= 59, line


def test_the_closing_view_leaves_no_column_of_blank_rows(monkeypatch):
    """The condensed view pads to a stable height while live; painted once more by
    stop(), that padding stayed on screen as ~20 empty rows before the next phase."""
    tty = _window(monkeypatch, 120, 24)
    p = Progress([f"HOST-{i:02d}" for i in range(38)], [2] * 38)
    p.start()
    for i in range(38):
        p.update(i, done=2, status="done")
    p.stop()
    tty.write("next phase\n")             # what the run prints after the bars
    rows = _screen(tty.getvalue())
    assert "" not in [r.strip() for r in rows], rows
    assert len(rows) == 2 and "38/38" in rows[0] and rows[1] == "next phase", rows


def test_counters_line_up_whatever_each_total_is(monkeypatch):
    _window(monkeypatch, 200, 24)
    p = Progress(["HOST-01", "HOST-02"], [98, 110])
    p._tty = False
    a, b = p._line(0), p._line(1)
    assert a.index("running") == b.index("running"), (a, b)
