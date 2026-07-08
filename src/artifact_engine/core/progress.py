"""Per-machine progress bars, one per line, refreshed live.

Designed for parallel execution: each thread calls `update(idx, ...)` and the
whole block is repainted under a lock. Draws live only if stdout is a TTY;
otherwise it prints the final state once.

Colour and Unicode block bars are used on a TTY (green = done, yellow = in
flight, dim = remaining/elapsed) and degrade to plain ASCII when stdout is
redirected or cannot encode the glyphs. Each line shows "running <elapsed>"
while a machine is in flight and freezes to "done <elapsed>" when it finishes;
a 1 Hz ticker keeps the clock moving during a long single parser.
"""

from __future__ import annotations

import shutil
import sys
import threading
import time

from artifact_engine.logging_setup import RAZER_GREEN

_WHITE, _GRAY, _RESET = "\033[97m", "\033[90m", "\033[0m"


def _bar_glyphs() -> tuple[str, str]:
    """Unicode block bar, with an ASCII fallback for consoles that cannot encode
    it. Resolved late (at Progress creation) so it sees the UTF-8 stdout that
    setup_logging reconfigures, not the encoding at import time."""
    try:
        "█░".encode(sys.stdout.encoding or "utf-8")
        return "█", "░"
    except (UnicodeEncodeError, LookupError, TypeError):
        return "#", "-"


class Progress:
    """A set of bars (one per machine). Stable index by insertion order."""

    def __init__(self, labels: list[str], totals: list[int]) -> None:
        self.labels = labels
        self.totals = totals
        self.done = [0] * len(labels)
        # The global pool starts every machine at once, so they begin "running";
        # a machine with no work is already "done".
        self.status = ["done" if t <= 0 else "running" for t in totals]
        self.elapsed = [0.0] * len(labels)   # frozen wall time once not running
        self._note = ""                       # diagnostics footer (slowest in-flight parser)
        self._lock = threading.Lock()
        self._tty = sys.stdout.isatty()
        self._painted = 0
        self._width = max((len(x) for x in labels), default=0)
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
        tw = len(str(total))
        return f"{body} {done:>{tw}}/{total}"

    def _line(self, i: int) -> str:
        st, secs = self.status[i], f"{self._secs(i):5.1f}s"
        if self._tty:
            col = RAZER_GREEN if st == "done" else _WHITE if st == "running" else _GRAY
            st = f"{col}{st:<7}{_RESET}"
            secs = f"{_GRAY}{secs}{_RESET}"
        else:
            st = f"{st:<7}"
        return f"  {self.labels[i]:<{self._width}}  {self._bar(i)}  {st} {secs}"

    def _note_line(self) -> str:
        if not self._note:
            return ""
        return f"{_GRAY}{self._note}{_RESET}" if self._tty else self._note

    def _summary_line(self) -> str:
        """One-line roll-up for the condensed view: overall task bar + machine
        count + elapsed. Its own compact format (not aligned to the label column)."""
        done_m = sum(1 for s in self.status if s == "done")
        tdone, ttot = sum(self.done), sum(self.totals)
        width = 20
        filled = width if ttot <= 0 else int(width * tdone / ttot)
        if self._tty:
            bar = f"{RAZER_GREEN}{self._full * filled}{_GRAY}{self._empty * (width - filled)}{_RESET}"
            lead, tail = f"{_WHITE}Parsing{_RESET}", f"{_GRAY}{tdone}/{ttot} tasks · {self._secs_run():5.1f}s{_RESET}"
        else:
            bar = self._full * filled + self._empty * (width - filled)
            lead, tail = "Parsing", f"{tdone}/{ttot} tasks · {self._secs_run():5.1f}s"
        return f"  {lead}  {bar}  {done_m}/{len(self.labels)} machines  {tail}"

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
        if n + 1 <= budget:
            return [self._line(i) for i in range(n)] + [note]   # full view (n+1 lines)
        slots = max(1, budget - 2)                              # reserve summary + note
        running = [i for i in range(n) if self.status[i] == "running"]
        if len(running) <= slots:
            body = [self._line(i) for i in running]
        else:
            body = [self._line(i) for i in running[:slots - 1]]
            more = len(running) - (slots - 1)
            txt = f"    … +{more} more running"
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
        sys.stdout.flush()
        self._painted = len(lines)

    def _tick(self) -> None:
        while not self._stop_tick.wait(1.0):
            with self._lock:
                self._repaint()

    def start(self) -> None:
        with self._lock:
            self._t0 = time.monotonic()
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
        with self._lock:
            if not self._tty:
                for i in range(len(self.labels)):
                    print(self._line(i))
            else:
                self._repaint()
