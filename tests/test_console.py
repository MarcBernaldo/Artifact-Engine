import os
from pathlib import Path

from artifact_engine.core import progress as pg
from artifact_engine.core.detector import Machine, assign_display_names
from artifact_engine.core.progress import Progress


def test_a_long_label_is_trimmed_to_the_window(monkeypatch):
    """Height was respected and width never was: get_terminal_size() was read for
    .lines and never .columns. A line wider than the window is wrapped by the
    terminal into TWO screen rows while _painted counts it as one, so the next
    cursor-up undershoots and every later repaint lands on the wrong rows."""
    monkeypatch.setattr(pg.shutil, "get_terminal_size",
                        lambda *_: os.terminal_size((80, 24)))
    long_label = "HOST-01-VSS12 (HOST-01_kape_2026-05-04T110646) and more padding"
    p = Progress([long_label], [10])
    p._tty = False
    line = p._line(0)

    assert len(line) <= 80, f"composed line is {len(line)} cols on an 80-col window"
    assert line.strip().startswith("HOST-01-VSS12"), "trimmed from the wrong end"


def test_a_short_label_is_left_alone(monkeypatch):
    monkeypatch.setattr(pg.shutil, "get_terminal_size",
                        lambda *_: os.terminal_size((200, 24)))
    p = Progress(["HOST-01"], [10])
    p._tty = False
    assert "HOST-01" in p._line(0) and "…" not in p._line(0)


def test_the_ellipsis_falls_back_when_the_console_cannot_encode_it(monkeypatch):
    """The bar glyphs probed for this and the ellipsis did not. It is used from
    inside the repaint, on the main thread, where nothing catches the
    UnicodeEncodeError -- so a display detail would end the whole run."""
    class _Cp850:
        encoding = "cp850"

    monkeypatch.setattr(pg.sys, "stdout", _Cp850())
    assert pg._ellipsis() == "~"
    assert pg._fit("abcdefghij", 5) == "abcd~"


def _m(name: str, source: str) -> Machine:
    return Machine(name=name, os="linux", collector="uac", profile_id="uac",
                   path=Path("."), source=source)


def test_display_names_disambiguate_collisions():
    a = _m("web01_uac", "uac-web01-linux-20260331164325")
    b = _m("web01_uac", "uac-web01-linux-20260416140714")
    c = _m("app01_uac", "uac-app01-linux-20260526160754")
    assign_display_names([a, b, c])
    assert a.display == "web01_uac [2026-03-31]"            # collision -> date tag
    assert b.display == "web01_uac [2026-04-16]"
    assert a.display != b.display                            # never identical
    assert c.display == "app01_uac"                          # unique name kept as-is


def test_display_names_same_date_gets_ordinal():
    a = _m("x_uac", "uac-x-linux-20260101000000")
    b = _m("x_uac", "uac-x-linux-20260101000000")            # same date too
    assign_display_names([a, b])
    assert a.display != b.display
    assert b.display.endswith("#2")


def test_display_names_provenance_tags():
    """Labels encode provenance: -VSS<n> for snapshots, -LR when the host also
    has Velociraptor LiveResponse, so a hostname is never shown bare-and-repeated."""
    live = Machine(name="WKSTN07", os="windows", collector="kape",
                   profile_id="windows_kape", path=Path("."), has_lr=True)
    vss1 = Machine(name="WKSTN07_VSS1", os="windows", collector="kape",
                   profile_id="windows_kape", path=Path("."), is_vss=True)
    vss2 = Machine(name="WKSTN07_VSS2", os="windows", collector="kape",
                   profile_id="windows_kape", path=Path("."), is_vss=True)
    plain = Machine(name="DC01", os="windows", collector="kape",
                    profile_id="windows_kape", path=Path("."))
    assign_display_names([live, vss1, vss2, plain])
    assert live.display == "WKSTN07-LR"                      # disk + live-state
    assert vss1.display == "WKSTN07-VSS1"                    # snapshot, no LR tag
    assert vss2.display == "WKSTN07-VSS2"
    assert plain.display == "DC01"                           # disk only, unique -> bare


def test_progress_non_tty_prints_final_with_time(capsys):
    p = Progress(["m1 (linux/uac)", "m2 (linux/uac)"], [2, 1])
    p.start()
    p.update(0, done=2, status="done")
    p.update(1, done=1, status="done")
    p.stop()
    out = capsys.readouterr().out
    assert "m1 (linux/uac)" in out
    assert "done" in out
    assert "2/2" in out
    assert ("█" * 20 in out) or ("#" * 20 in out)            # full bar (Unicode or ASCII fallback)
    assert "s" in out                                        # elapsed seconds rendered


def test_progress_caps_lines_to_window_height(monkeypatch):
    """More machines than the terminal has rows must NOT paint one line each
    (that scrolls the window and garbles every repaint). It condenses to a
    fixed-height roll-up that fits; a tall window shows every machine."""
    import os as _os

    from artifact_engine.core import progress as progmod

    p = Progress([f"M{i:02d}" for i in range(38)], [10] * 38)
    p._tty = True
    for i in range(12):                    # a mix of done + running
        p.status[i] = "done"
        p.done[i] = 10

    monkeypatch.setattr(progmod.shutil, "get_terminal_size",
                        lambda fb=(80, 24): _os.terminal_size((120, 24)))
    lines = p._compose_lines()
    assert len(lines) <= 23                # budget = rows - 1, never scrolls
    assert "machines" in lines[0]          # condensed summary header

    monkeypatch.setattr(progmod.shutil, "get_terminal_size",
                        lambda fb=(80, 24): _os.terminal_size((120, 60)))
    assert len(p._compose_lines()) == 39   # tall window -> one line per machine + note
