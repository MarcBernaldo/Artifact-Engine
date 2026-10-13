"""Progress bars, one per line, refreshed live: one per host while parsing, one
per unit while consolidating (the caller passes the labels).

Designed for parallel execution: each thread calls `update(idx, ...)` and the
whole block is repainted under a lock. Draws live only if stdout is a TTY;
otherwise it prints the final state once.

Colour and Unicode block bars are used on a TTY (green = done, yellow = in
flight, dim = remaining/elapsed) and degrade to plain ASCII when stdout is
redirected or cannot encode the glyphs. Each line shows "running <elapsed>"
while a machine is in flight and freezes to "done <elapsed>" when it finishes;
a 1 Hz ticker keeps the clock moving during a long single parser.

A log line written while the bars are live goes ABOVE them (v0.7.121). The
console handler writes to stdout, and anything landing inside the painted block
shifts it under the cursor-up anchor: the next repaint starts on the wrong row
and the block is drawn twice. So while the bars are up the console handler's
stream is a proxy that clears the block, prints the line and repaints.
"""

from __future__ import annotations

import logging
import shutil
import sys
import threading
import time

from artifact_engine.logging_setup import RAZER_GREEN

_WHITE, _GRAY, _RESET = "\033[97m", "\033[90m", "\033[0m"


def _ellipsis() -> str:
    """`…` where the console can encode it, `~` where it cannot.

    The bar glyphs already probe for this; the ellipsis did not, and it is used
    from inside the repaint. A UnicodeEncodeError there is raised on the main
    thread inside progress.update(), where nothing catches it -- so a display
    detail would end the whole run."""
    try:
        "…".encode(sys.stdout.encoding or "utf-8")
        return "…"
    except (UnicodeEncodeError, LookupError, TypeError):
        return "~"


def _fit(text: str, width: int) -> str:
    """Trim `text` to `width`, marking the cut. Only ever called on plain strings
    (labels, the note) -- never on a composed line, which carries ANSI escapes
    that len() would count as visible characters."""
    if width <= 0 or len(text) <= width:
        return text
    return text[:width - 1] + _ellipsis() if width > 1 else text[:width]


def _bar_glyphs() -> tuple[str, str]:
    """Unicode block bar, with an ASCII fallback for consoles that cannot encode
    it. Resolved late (at Progress creation) so it sees the UTF-8 stdout that
    setup_logging reconfigures, not the encoding at import time."""
    try:
        "█░".encode(sys.stdout.encoding or "utf-8")
        return "█", "░"
    except (UnicodeEncodeError, LookupError, TypeError):
        return "#", "-"


class _AboveTheBars:
    """The console handler's stream while the bars are live: whole lines are
    handed to the Progress, which prints them above the block."""

    def __init__(self, progress: Progress, stream) -> None:
        self._progress = progress
        self._buf = ""
        self.encoding = getattr(stream, "encoding", None) or "utf-8"

    def write(self, text: str) -> int:
        self._buf += text
        if "\n" in self._buf:
            whole, _, self._buf = self._buf.rpartition("\n")
            self._progress.print_above(whole + "\n")
        return len(text)

    def flush(self) -> None:
        pass

    def drain(self) -> str:
        rest, self._buf = self._buf, ""
        return rest


class Progress:
    """A set of bars, one per label the caller passes. Stable index by insertion order."""

    def __init__(self, labels: list[str], totals: list[int],
                 title: str = "Parsing", noun: str = "machines") -> None:
        self.title, self.noun = title, noun   # the condensed roll-up's words
        self.labels = labels
        self.totals = totals
        self.done = [0] * len(labels)
        # The global pool starts every machine at once, so they begin "running";
        # a machine with no work is already "done".
        self.status = ["done" if t <= 0 else "running" for t in totals]
        self.elapsed = [0.0] * len(labels)   # frozen wall time once not running
        self._note = ""                       # diagnostics footer (slowest in-flight parser)
        self._final = False                   # stop() paints the closing view
        self._swapped: list[tuple[logging.StreamHandler, object]] = []
        self._proxy: _AboveTheBars | None = None
        self._lock = threading.RLock()
        self._tty = sys.stdout.isatty()
        self._painted = 0
        self._width = max((len(x) for x in labels), default=0)   # capped at paint time
        self._t0 = time.monotonic()
        self._full, self._empty = _bar_glyphs()
        self._stop_tick = threading.Event()
        self._ticker: threading.Thread | None = None

    def _secs(self, i: int) -> float:
        return self.elapsed[i] if self.status[i] != "running" else (time.monotonic() - self._t0)

    def _bar(self, i: int, width: int = 20) -> str:
        done, total = self.done[i], self.totals[i]
        filled = width if total <= 0 else int(width * done / total)
        if self._tty:
            body = f"{RAZER_GREEN}{self._full * filled}{_GRAY}{self._empty * (width - filled)}{_RESET}"
        else:
            body = self._full * filled + self._empty * (width - filled)
        # Padded to the widest total of ALL bars, so the columns after the
        # counter line up whatever each machine's own total is.
        tw = len(str(max(self.totals, default=0)))
        return f"{body} {done:>{tw}}/{total:<{tw}}"

    def _line(self, i: int) -> str:
        st, secs = self.status[i], f"{self._secs(i):5.1f}s"
        if self._tty:
            col = RAZER_GREEN if st == "done" else _WHITE if st == "running" else _GRAY
            st = f"{col}{st:<7}{_RESET}"
            secs = f"{_GRAY}{secs}{_RESET}"
        else:
            st = f"{st:<7}"
        w = self._label_width()
        return f"  {_fit(self.labels[i], w):<{w}}  {self._bar(i)}  {st} {secs}"

    def _label_width(self) -> int:
        """Label column, capped so a composed line fits the window.

        Height was already respected; width never was -- `get_terminal_size()` was
        read for `.lines` and never `.columns`. A line longer than the window is
        wrapped by the terminal into TWO screen rows while `_painted` still counts
        it as one, so the next `\\033[{n}A` undershoots by a row per wrapped line
        and the redraw lands on the wrong ones. Long machine labels (a host with a
        VSS suffix and a source-archive qualifier) reach that easily on the 80-col
        default of the legacy console, or in a narrow RDP session to a forensic
        workstation.
        """
        # Everything to the right of the label, measured rather than guessed: the
        # bar's counter grows with the digit count, so a fixed constant is right
        # for 10 tasks and wrong for 1400.
        tw = len(str(max(self.totals, default=0)))
        bar = 20 + 1 + tw + 1 + tw               # glyphs + " " + done + "/" + total
        fixed = 2 + bar + 2 + 7 + 1 + 6 + 2      # lead + seps + status + secs
        cols = shutil.get_terminal_size((80, 24)).columns
        return max(8, min(self._width, cols - fixed))

    def _note_line(self) -> str:
        if not self._note:
            return ""
        # the note concatenates in-flight parser ids and is otherwise unbounded
        note = _fit(self._note, max(20, shutil.get_terminal_size((80, 24)).columns - 2))
        return f"{_GRAY}{note}{_RESET}" if self._tty else note

    def _summary_line(self) -> str:
        """One-line roll-up for the condensed view: overall task bar + machine
        count + elapsed. Its own compact format (not aligned to the label column)."""
        done_m = sum(1 for s in self.status if s == "done")
        tdone, ttot = sum(self.done), sum(self.totals)
        width = 20
        filled = width if ttot <= 0 else int(width * tdone / ttot)
        plain = (f"  {self.title}  {self._full * filled}{self._empty * (width - filled)}  "
                 f"{done_m}/{len(self.labels)} {self.noun}  "
                 f"{tdone}/{ttot} tasks · {self._secs_run():5.1f}s")
        cols = shutil.get_terminal_size((80, 24)).columns
        if len(plain) > cols - 1:
            # Wider than the window: the terminal would wrap it onto a second row
            # the painter does not count. Cut, without colour (len() of a
            # coloured line counts its escapes).
            return _fit(plain, cols - 1)
        if self._tty:
            bar = f"{RAZER_GREEN}{self._full * filled}{_GRAY}{self._empty * (width - filled)}{_RESET}"
            lead = f"{_WHITE}{self.title}{_RESET}"
            tail = f"{_GRAY}{tdone}/{ttot} tasks · {self._secs_run():5.1f}s{_RESET}"
        else:
            bar = self._full * filled + self._empty * (width - filled)
            lead, tail = self.title, f"{tdone}/{ttot} tasks · {self._secs_run():5.1f}s"
        return f"  {lead}  {bar}  {done_m}/{len(self.labels)} {self.noun}  {tail}"

    def _secs_run(self) -> float:
        return time.monotonic() - self._t0

    def _compose_lines(self) -> list[str]:
        """The lines to paint, capped to the window height. Painting more lines
        than the terminal has rows makes it scroll, which breaks the cursor-up
        anchor and turns every repaint into a garbled "reload". So when there are
        more machines than fit, switch to a fixed-height condensed view: an overall
        bar + the machines still running (what is actually live) + the footer."""
        n = len(self.labels)
        note = self._note_line()
        budget = max(4, shutil.get_terminal_size((80, 24)).lines - 1)
        if self._final:
            # The closing view: every machine when they fit, else the roll-up --
            # no reserved footer, no padding left as a column of blank rows.
            if n + 1 <= budget:
                return [self._line(i) for i in range(n)]
            return [self._summary_line()]
        if n + 1 <= budget:
            return [self._line(i) for i in range(n)] + [note]   # full view (n+1 lines)
        slots = max(1, budget - 2)                              # reserve summary + note
        running = [i for i in range(n) if self.status[i] == "running"]
        if len(running) <= slots:
            body = [self._line(i) for i in running]
        else:
            body = [self._line(i) for i in running[:slots - 1]]
            more = len(running) - (slots - 1)
            txt = f"    {_ellipsis()} +{more} more running"
            body.append(f"{_GRAY}{txt}{_RESET}" if self._tty else txt)
        lines = [self._summary_line(), *body]
        # Pad to a STABLE height so a shrinking running-set never leaves stale bars
        # on screen (the note stays last).
        lines += [""] * (budget - 1 - len(lines))
        lines.append(note)
        return lines

    def set_note(self, text: str) -> None:
        """Set the diagnostics footer under the bars (e.g. the slowest in-flight
        parser). Repainted in place under the lock, so it never corrupts the bars
        -- unlike logging a raw line to stdout while they are live."""
        with self._lock:
            if text == self._note:
                return
            self._note = text
            self._repaint()

    def _repaint(self) -> None:
        if not self._tty:
            return
        if self._painted:
            sys.stdout.write(f"\033[{self._painted}A")
        # Bars (or a condensed roll-up when they don't fit) plus one reserved footer
        # line (blank when idle) so the painted line count stays constant: the
        # cursor-up math never has to account for a vanishing note or overflow.
        lines = self._compose_lines()
        for ln in lines:
            sys.stdout.write("\033[K" + ln + "\n")
        # A view shorter than the last one leaves its tail on screen: clear it.
        sys.stdout.write("\033[J")
        sys.stdout.flush()
        self._painted = len(lines)

    def print_above(self, text: str) -> None:
        """Print `text` above the live bars: clear the block, write, repaint."""
        with self._lock:
            if self._tty and self._painted:
                sys.stdout.write(f"\033[{self._painted}A\r\033[J")
                self._painted = 0
            sys.stdout.write(text)
            self._repaint()

    def _divert_console(self) -> None:
        """Point the console handler(s) of the `aeng` logger at the proxy."""
        self._proxy = _AboveTheBars(self, sys.stdout)
        for h in logging.getLogger("aeng").handlers:
            if (type(h) is logging.StreamHandler
                    and getattr(h, "stream", None) is sys.stdout):
                self._swapped.append((h, h.setStream(self._proxy)))

    def _restore_console(self) -> None:
        for h, stream in self._swapped:
            h.setStream(stream)
        self._swapped.clear()
        if self._proxy is not None:
            rest = self._proxy.drain()          # a line without its newline yet
            self._proxy = None
            if rest:
                sys.stdout.write(rest + "\n")

    def _tick(self) -> None:
        while not self._stop_tick.wait(1.0):
            with self._lock:
                self._repaint()

    def start(self) -> None:
        with self._lock:
            self._t0 = time.monotonic()
            if self._tty:
                self._divert_console()
            self._repaint()
        if self._tty:
            self._ticker = threading.Thread(target=self._tick, daemon=True)
            self._ticker.start()

    def update(self, idx: int, done: int | None = None, status: str | None = None) -> None:
        with self._lock:
            if done is not None:
                self.done[idx] = done
            # Freeze the clock the moment a machine leaves the running state.
            if status is not None and status != "running" and self.status[idx] == "running":
                self.elapsed[idx] = time.monotonic() - self._t0
            if status is not None:
                self.status[idx] = status
            self._repaint()

    def stop(self) -> None:
        """Paint the final state (needed when there is no TTY)."""
        self._stop_tick.set()
        if self._ticker is not None:
            self._ticker.join(timeout=2)
        with self._lock:
            if not self._tty:
                for i in range(len(self.labels)):
                    print(self._line(i))
            else:
                self._final = True
                self._repaint()
                self._restore_console()
