"""Linux memory images (v0.7.113): which kernel an image holds, the profile and
parsers that follow from it, and Volatility's Linux plugins. No real image: an
"image" is a few KB holding the strings a kernel leaves; Volatility is a script.
Host names are invented."""
from __future__ import annotations

import csv
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from artifact_engine.config import DATA_DIR
from artifact_engine.core import detector, memory, memory_os, pipeline, scheduler
from artifact_engine.core.runner import HandlerSkip, ParserContext
from artifact_engine.handlers import mem_linux as L
from artifact_engine.handlers import mem_volatility as V
from artifact_engine.registry import load_parsers, load_profiles

_SMALL = 1024
_BANNER = (b"Linux version 6.1.0-9-amd64 (builder@example.local) (gcc-12 (Debian 12.2.0-14) "
           b"12.2.0, GNU ld 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.27-1 (2023-05-08)")


@pytest.fixture(autouse=True)
def _small_images(monkeypatch):
    monkeypatch.setattr(memory, "MIN_IMAGE_BYTES", _SMALL)


def _image(path: Path, *parts: bytes, size: int = 4 * _SMALL) -> Path:
    """An image of `size` bytes with `parts` spread through it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = bytearray(size)
    step = size // (len(parts) + 1) if parts else 0
    for i, p in enumerate(parts, 1):
        data[i * step:i * step + len(p)] = p
    path.write_bytes(bytes(data))
    return path


# --- which kernel ---------------------------------------------------------------

def test_a_banner_and_no_windows_kernel_is_linux(tmp_path):
    windows, banner = memory_os.scan(_image(tmp_path / "a.mem", b"\0" + _BANNER + b"\n"))
    assert windows == "" and banner == _BANNER.decode()


def test_both_kernels_go_windows_and_say_how_to_overrule_it(tmp_path, caplog):
    """A Windows host running WSL2 holds a banner; a Linux hypervisor with Windows
    guests holds a Windows kernel's name. The scan sees both, wherever they lie."""
    _image(tmp_path / "HOST-01.mem", b"RSDS....ntkrnlmp.pdb\0", _BANNER + b"\0")
    unit = memory.stage_images(tmp_path)[0]
    assert memory_os.scan(memory.image_of(unit)) == ("ntkrnlmp.pdb", _BANNER.decode())
    with caplog.at_level(logging.WARNING, logger="aeng"):
        assert memory_os.classify(unit) == "windows"
    assert "AND a Linux banner" in caplog.text and "rename memory.windows" in caplog.text


def test_neither_is_unknown(tmp_path):
    assert memory_os.scan(_image(tmp_path / "a.mem", b"Linux version of nothing")) == ("", "")


@pytest.mark.parametrize("chunk", [600, 700, 1000, 1500])
def test_a_banner_across_a_block_boundary_is_counted_once_and_whole(tmp_path, monkeypatch,
                                                                    chunk):
    monkeypatch.setattr(memory_os, "CHUNK", chunk)
    other = _BANNER.replace(b"6.1.0-9", b"5.10.0-2")
    img = _image(tmp_path / "a.mem", _BANNER + b"\0", other + b"\0", _BANNER + b"\0",
                 size=6000)
    found = []
    real = memory_os.Counter

    class Spy(real):
        def __setitem__(self, k, v):
            found.append(k)
            super().__setitem__(k, v)
    monkeypatch.setattr(memory_os, "Counter", Spy)
    windows, banner = memory_os.scan(img)
    assert windows == "" and banner == _BANNER.decode()
    assert sorted(found) == sorted([_BANNER, other, _BANNER])


def test_the_answer_is_recorded_once_and_the_analyst_can_overrule_it(tmp_path, monkeypatch):
    _image(tmp_path / "HOST-01.mem", _BANNER + b"\0")
    unit = memory.stage_images(tmp_path)[0]
    assert memory_os.classify(unit) == "linux"
    assert (unit / memory_os.LINUX).read_text(encoding="utf-8").strip() == _BANNER.decode()
    monkeypatch.setattr(memory_os, "scan", lambda image: pytest.fail("scanned twice"))
    assert memory_os.classify(unit) == "linux"
    (unit / memory_os.LINUX).rename(unit / memory_os.WINDOWS)
    assert memory_os.classify(unit) == "windows"


# --- profile and parsers --------------------------------------------------------

def _staged(tmp_path, *parts, name="HOST-01.mem"):
    _image(tmp_path / name, *parts)
    memory_os.classify_units(memory.stage_images(tmp_path))
    return detector.detect_machines(tmp_path, load_profiles([DATA_DIR / "profiles"]))


def test_a_linux_image_is_a_linux_memory_machine(tmp_path):
    [m] = _staged(tmp_path, _BANNER + b"\0")
    assert (m.os, m.collector, m.profile_id) == ("linux", "memory", "linux_memory")


def test_a_full_run_stages_and_classifies_before_it_detects(tmp_path):
    _image(tmp_path / "HOST-01.mem", _BANNER + b"\0")

    class _Cfg:
        avoid_vss = True
    [m] = pipeline.detect(tmp_path, _Cfg(), load_profiles([DATA_DIR / "profiles"]),
                          stage_drops=True)
    assert m.profile_id == "linux_memory"


def test_a_windows_image_stays_a_windows_memory_machine(tmp_path):
    [m] = _staged(tmp_path, b"ntkrnlmp.pdb\0")
    assert (m.os, m.profile_id) == ("windows", "windows_memory")
    assert (m.path / memory_os.WINDOWS).is_file()


def test_each_unit_queues_only_its_own_kernels_plugins(tmp_path):
    parsers = load_parsers([DATA_DIR / "parsers"])
    [lin] = _staged(tmp_path / "l", _BANNER + b"\0")
    [win] = _staged(tmp_path / "w", b"ntoskrnl.pdb\0")
    q_lin = {p.id for p in scheduler._applicable(lin, parsers)}
    q_win = {p.id for p in scheduler._applicable(win, parsers)}
    assert q_lin and all(i.startswith("linmem_") for i in q_lin)
    assert q_win and all(i.startswith("mem_") for i in q_win)
    by_id = {p.id: p for p in parsers}
    plugins = [i for i in q_lin if by_id[i].handler.startswith(_PLUGIN_MODULE)]
    assert all(by_id[i].depends_on == ["linmem_info"] for i in plugins if i != "linmem_info")


_PLUGIN_MODULE = "artifact_engine.handlers.mem_linux:"
# Built from the plugins' tables, not a plugin (v0.7.116).
_FROM_TABLES = {"linmem_process_network"}


def test_every_linux_memory_parser_names_a_handler_that_exists():
    for p in load_parsers([DATA_DIR / "parsers"]):
        if p.id.startswith("linmem_") and p.id not in _FROM_TABLES:
            mod, func = p.handler.split(":")
            assert mod == "artifact_engine.handlers.mem_linux" and callable(getattr(L, func))


def _envars(unit: Path, rows) -> None:
    d = unit / "CSVs" / "Memory"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "linmem_envars.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["TreeDepth", "PID", "PPID", "COMM", "KEY", "VALUE"])
        for k, v in rows:
            w.writerow([0, 100, 1, "bash", k, v])


def test_a_linux_unit_is_named_after_its_session_never_a_containers_hostname(tmp_path):
    [m] = _staged(tmp_path, _BANNER + b"\0", name="acquired-by-hand.mem")
    _envars(m.path, [("SESSION_MANAGER", "local/HOST-01:@/tmp/.ICE-unix/1234,unix/HOST-01:/tmp/x"),
                     ("HOME", "/home/jdoe")])
    assert pipeline.rename_parsed_drops([m]) is True and m.name == "HOST-01"
    # every process of every container carries HOSTNAME=<container id>
    _envars(m.path, [("SESSION_MANAGER", "local/HOST-01:@/tmp/.ICE-unix/1")]
            + [("HOSTNAME", "3f2a9c1b7d4e")] * 5)
    assert pipeline.rename_parsed_drops([m]) is False and m.name == "HOST-01"


def test_gnomes_literal_unix_is_not_a_host(tmp_path):
    """RHEL/CentOS 7 sessions say `local/unix:` whatever the host is called."""
    [m] = _staged(tmp_path, _BANNER + b"\0", name="acquired-by-hand.mem")
    _envars(m.path, [("SESSION_MANAGER", "local/unix:@/tmp/.ICE-unix/2310,unix/unix:/tmp/x")]
            * 3)
    assert pipeline.rename_parsed_drops([m]) is False and m.name == "acquired-by-hand"


def test_a_linux_unit_a_windows_profile_takes_is_reported(tmp_path, caplog):
    """An older copy of windows_memory.yaml in a profile folder searched before the
    built-in one matches the pointer alone, and is checked first."""
    override = tmp_path / "profiles"
    override.mkdir()
    old = (DATA_DIR / "profiles" / "windows_memory.yaml").read_text(encoding="utf-8")
    (override / "windows_memory.yaml").write_text(old, encoding="utf-8")
    case = tmp_path / "case"
    _image(case / "HOST-01.mem", _BANNER + b"\0")

    class _Cfg:
        avoid_vss = True
    with caplog.at_level(logging.WARNING, logger="aeng"):
        [m] = pipeline.detect(case, _Cfg(), load_profiles([override, DATA_DIR / "profiles"]),
                              stage_drops=True)
    assert m.profile_id == "windows_memory"
    assert "holds a Linux kernel but was detected by profile windows_memory" in caplog.text


# --- the plugins ----------------------------------------------------------------

_FAKE = '''
import sys
a = sys.argv
assert a[a.index("--remote-isf-url") + 1].endswith("banners.json"), a
mode = a[a.index("-f") + 2]
print("TreeDepth,PID,COMM")
if mode == "nokernel":
    sys.stderr.write("Unable to validate the plugin requirements: ['plugins.PsList.kernel']\\n")
    sys.exit(1)
print("0,1,systemd")
'''


@pytest.fixture
def unit(tmp_path, monkeypatch):
    script = tmp_path / "fakevol.py"
    script.write_text(_FAKE, encoding="utf-8")
    monkeypatch.setattr(L, "vol_command", lambda: [sys.executable, str(script)])
    _image(tmp_path / "case" / "HOST-01.mem", _BANNER + b"\0")
    u = memory.stage_images(tmp_path / "case")[0]
    memory_os.classify(u)
    return u


def _ctx(unit: Path, out: Path) -> ParserContext:
    return ParserContext(evidence=unit, out=out, tools=unit, assets=unit,
                         machine_name="HOST-01", volume=unit.name,
                         log=logging.getLogger("aeng.test"))


def _info_done(unit: Path) -> None:
    d = unit / "CSVs" / "Memory"
    d.mkdir(parents=True, exist_ok=True)
    (d / ".linmem_info.done").write_text("x", encoding="utf-8")


def test_info_reads_the_kernel_and_says_which(unit, tmp_path):
    L.info(_ctx(unit, tmp_path / "out"))
    rows = list(csv.reader((tmp_path / "out" / "linmem_info.csv").open(encoding="utf-8")))
    assert ["0", "Kernel banner", _BANNER.decode()] in rows


def test_no_symbols_for_the_kernel_is_said_in_words(unit, tmp_path):
    with pytest.raises(RuntimeError, match="no symbols for this Linux kernel .*6.1.0-9-amd64"):
        L.run_plugin(_ctx(unit, tmp_path / "out"), "nokernel", "linmem_info")


def test_without_info_the_plugins_skip_naming_it(unit, tmp_path):
    with pytest.raises(HandlerSkip, match="linmem_info did not succeed"):
        L.run_plugin(_ctx(unit, tmp_path / "out"), "ok", "linmem_pslist")


_RAISES = '''
import sys
a = sys.argv
mode = a[a.index("-f") + 2]
print("TreeDepth,TID")
sys.stderr.write("\\nVolatility encountered an unexpected situation.\\n")
if mode == "unreadable":
    sys.stderr.write("WARNING  volatility3.framework.plugins: Automagic exception occurred: "
                     "MemoryError\\n")
    sys.stderr.write("Unable to validate the plugin requirements: ['plugins.X.kernel']\\n")
    sys.exit(1)
if mode != "silent":
    sys.stderr.write("AENG-VOLATILITY-REASON: VolatilityException: " + {
        "old": "Unsupported kthread implementation. This plugin only works with kernels >= 5.8",
        "bug": "list index out of range"}[mode] + "\\n")
sys.stderr.write("No further results will be produced\\n")
sys.exit(1)
'''


def test_a_plugin_that_says_this_kernel_is_unsupported_is_a_skip(unit, tmp_path, monkeypatch):
    """Volatility 2.28's kthreads, capabilities and ebpf raise on older kernels
    with "unexpected situation", their reason kept for -vvv (v0.7.114)."""
    script = tmp_path / "raises.py"
    script.write_text(_RAISES, encoding="utf-8")
    monkeypatch.setattr(L, "vol_command", lambda: [sys.executable, str(script)])
    _info_done(unit)
    with pytest.raises(HandlerSkip, match="cannot run on this kernel .*>= 5.8"):
        L.run_plugin(_ctx(unit, tmp_path / "out"), "old", "linmem_kthreads")
    with pytest.raises(RuntimeError, match="exited 1: VolatilityException: list index"):
        L.run_plugin(_ctx(unit, tmp_path / "out"), "bug", "linmem_lsof")
    with pytest.raises(RuntimeError, match="No further results"):
        L.run_plugin(_ctx(unit, tmp_path / "out"), "silent", "linmem_lsof")
    with pytest.raises(RuntimeError, match="could not read the image .*MemoryError"):
        L.run_plugin(_ctx(unit, tmp_path / "out"), "unreadable", "linmem_lsof")


def test_on_info_an_unsupported_kernel_is_still_an_error(unit, tmp_path, monkeypatch):
    script = tmp_path / "raises.py"
    script.write_text(_RAISES, encoding="utf-8")
    monkeypatch.setattr(L, "vol_command", lambda: [sys.executable, str(script)])
    with pytest.raises(RuntimeError, match="Unsupported kthread"):
        L.run_plugin(_ctx(unit, tmp_path / "out"), "old", "linmem_info")


_FAKE_CLI = '''
import sys


class CommandLine:
    def process_exceptions(self, excp):
        sys.stderr.write("Volatility encountered an unexpected situation.\\n")
        sys.exit(1)


def main():
    CommandLine().process_exceptions(ValueError("the reason, in words"))
'''


def test_the_launcher_writes_volatilitys_reason(tmp_path, monkeypatch):
    """The launcher itself, against a stand-in `volatility3.cli` with the same
    hook: the reason reaches stderr, marked, before Volatility's own lines."""
    pkg = tmp_path / "volatility3" / "cli"
    pkg.mkdir(parents=True)
    (tmp_path / "volatility3" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "__init__.py").write_text(_FAKE_CLI, encoding="utf-8")
    cmd = [sys.executable, "-c", V._LAUNCH]
    r = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True, check=False,
                       env={**os.environ, "PYTHONPATH": str(tmp_path)})
    assert r.returncode == 1
    assert V._reason(r.stderr) == "ValueError: the reason, in words"


def test_a_plugin_the_kernel_cannot_run_after_info_is_a_skip(unit, tmp_path):
    _info_done(unit)
    with pytest.raises(HandlerSkip, match="cannot run on this kernel"):
        L.run_plugin(_ctx(unit, tmp_path / "out"), "nokernel", "linmem_ebpf")
    assert L.run_plugin(_ctx(unit, tmp_path / "out"), "ok", "linmem_pslist").is_file()
