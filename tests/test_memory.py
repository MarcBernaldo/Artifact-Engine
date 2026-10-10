"""Memory images as units of their own, and Volatility 3 run one plugin per parser.

No real image is used: an "image" here is a file of the right name and size, and
Volatility is stood in for by a small script that prints a table the way
Volatility does. Host and user names are invented.
"""
from __future__ import annotations

import csv
import logging
import sys
from pathlib import Path

import pytest

from artifact_engine.config import DATA_DIR
from artifact_engine.core import consolidate, detector, hashing, memory, pipeline, procs
from artifact_engine.core.detector import Machine, Volume
from artifact_engine.core.runner import HandlerSkip, ParserContext
from artifact_engine.handlers import mem_volatility as V
from artifact_engine.registry import load_parsers, load_profiles

_SMALL = 1024     # the size threshold, lowered so a test image is a few KB


@pytest.fixture(autouse=True)
def _small_images(monkeypatch):
    monkeypatch.setattr(memory, "MIN_IMAGE_BYTES", _SMALL)


def _image(path: Path, size: int = _SMALL * 2) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\0" * size)
    return path


def _ctx(unit: Path, out: Path) -> ParserContext:
    return ParserContext(evidence=unit, out=out, tools=unit, assets=unit,
                         machine_name="HOST-01", volume=unit.name,
                         log=logging.getLogger("aeng.test"))


# --- which files are images -----------------------------------------------------

def test_an_image_at_the_case_root_gets_a_unit_beside_it(tmp_path):
    img = _image(tmp_path / "HOST-01.raw")
    before = img.read_bytes()
    units = memory.stage_images(tmp_path)
    unit = tmp_path / "HOST-01_memory"
    assert units == [unit]
    assert (unit / memory.POINTER).read_text(encoding="utf-8").strip() == "HOST-01.raw"
    assert (unit / memory.NAME_FILE).read_text(encoding="utf-8").strip() == "HOST-01"
    assert memory.image_of(unit) == img
    # the image is neither moved nor copied nor changed
    assert img.read_bytes() == before
    assert [p.name for p in unit.iterdir()] and not any(
        p.suffix == ".raw" for p in unit.iterdir())


def test_staging_twice_changes_nothing(tmp_path):
    _image(tmp_path / "HOST-01.mem")
    memory.stage_images(tmp_path)
    unit = tmp_path / "HOST-01_memory"
    (unit / memory.NAME_FILE).write_text("RENAMED\n", encoding="utf-8")
    assert memory.stage_images(tmp_path) == [unit]
    assert (unit / memory.NAME_FILE).read_text(encoding="utf-8").strip() == "RENAMED"


def test_a_minidump_is_not_a_memory_image(tmp_path):
    """`.dmp` is also a process minidump: below the size threshold it is not taken."""
    _image(tmp_path / "app.dmp", size=_SMALL - 1)
    assert memory.stage_images(tmp_path) == []
    assert not (tmp_path / "app_memory").exists()


def test_a_name_that_does_not_say_memory_is_not_taken(tmp_path):
    """`.img` and `.bin` are as often disk images."""
    _image(tmp_path / "disk.img")
    _image(tmp_path / "dump.bin")
    assert memory.stage_images(tmp_path) == []


def test_an_image_inside_an_extracted_tree_is_not_taken(tmp_path):
    """A crash dump deep inside a Windows tree is not the acquisition."""
    _image(tmp_path / "acq" / "C" / "Windows" / "MEMORY.DMP")
    assert memory.stage_images(tmp_path) == []


def test_an_image_one_folder_down_is_taken(tmp_path):
    _image(tmp_path / "acq" / "HOST-01.vmem")
    assert memory.stage_images(tmp_path) == [tmp_path / "acq" / "HOST-01_memory"]


def test_two_images_with_one_stem_do_not_share_a_unit(tmp_path):
    _image(tmp_path / "HOST-01.raw")
    _image(tmp_path / "HOST-01.mem")
    units = memory.stage_images(tmp_path)
    assert len(units) == 1
    unit = units[0]
    # the pointer keeps naming the first image; the second is not silently
    # analysed under the first one's name
    assert memory.image_of(unit).name == "HOST-01.mem"   # sorted: .mem before .raw


def test_a_pointer_cannot_reach_outside_the_folder(tmp_path):
    unit = tmp_path / "x_memory"
    unit.mkdir()
    (unit / memory.POINTER).write_text("..\\elsewhere.raw\n", encoding="utf-8")
    assert memory.image_of(unit) is None


# --- detection, naming, custody, consolidation -----------------------------------

def _profiles():
    return load_profiles([DATA_DIR / "profiles"])


def test_the_unit_is_detected_as_a_windows_memory_machine(tmp_path):
    _image(tmp_path / "HOST-01.raw")
    memory.stage_images(tmp_path)
    ms = detector.detect_machines(tmp_path, _profiles())
    assert [(m.name, m.collector, m.profile_id, m.path.name) for m in ms] == [
        ("HOST-01", "memory", "windows_memory", "HOST-01_memory")]


def test_only_the_memory_parsers_apply_to_a_unit(tmp_path):
    _image(tmp_path / "HOST-01.raw")
    memory.stage_images(tmp_path)
    m = detector.detect_machines(tmp_path, _profiles())[0]
    parsers = load_parsers([DATA_DIR / "parsers"])
    applied = {p.id for p in detector.parsers_for(m, parsers) if p.requires}
    assert applied and all(i.startswith("mem_") for i in applied)
    # and every memory parser waits for the one that resolves the symbols
    mem = [p for p in parsers if p.id.startswith("mem_")]
    assert all(p.depends_on == ["mem_info"] for p in mem if p.id != "mem_info")


def test_every_memory_parser_names_a_handler_that_exists():
    for p in load_parsers([DATA_DIR / "parsers"]):
        if p.id.startswith("mem_"):
            _mod, func = p.handler.split(":")
            assert callable(getattr(V, func)), p.id


def _envars(unit: Path, rows: list[tuple[str, str]]) -> None:
    d = unit / "CSVs" / "Memory"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "mem_envars.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["TreeDepth", "PID", "Process", "Block", "Variable", "Value"])
        for var, val in rows:
            w.writerow([0, 4, "x.exe", "0x1", var, val])


def test_a_unit_is_named_after_the_host_its_processes_name(tmp_path):
    _image(tmp_path / "acquired-by-hand.raw")
    memory.stage_images(tmp_path)
    ms = detector.detect_machines(tmp_path, _profiles())
    _envars(ms[0].path, [("COMPUTERNAME", "HOST-01"), ("USERNAME", "jdoe"),
                         ("COMPUTERNAME", "HOST-01"), ("COMPUTERNAME", "OTHER")])
    assert pipeline.rename_parsed_drops(ms) is True
    assert ms[0].name == "HOST-01"
    assert pipeline.rename_parsed_drops(ms) is False      # idempotent


def test_custody_hashes_the_image_and_not_the_unit(tmp_path):
    _image(tmp_path / "HOST-01.raw")
    memory.stage_images(tmp_path)
    (tmp_path / "HOST-01_memory" / "HOST-01.db").write_bytes(b"derived")
    found = {p.relative_to(tmp_path).as_posix()
             for p in hashing._iter_original_files(tmp_path)}
    assert found == {"HOST-01.raw"}


def test_a_memory_unit_is_never_folded_into_a_disk_and_its_snapshots(tmp_path):
    coll = tmp_path / "acq"
    live = Machine("HOST-01", "windows", "kape", "windows_kape", coll / "C", "acq",
                   [Volume("C", coll / "C", True)])
    vss = Machine("HOST-01_VSS1", "windows", "kape", "windows_kape", coll / "VSS1", "acq",
                  [Volume("VSS1", coll / "VSS1", False)], is_vss=True)
    mem = Machine("HOST-01", "windows", "memory", "windows_memory",
                  coll / "HOST-01_memory", "acq",
                  [Volume("HOST-01_memory", coll / "HOST-01_memory", True)])
    for order in ([mem, live, vss], [live, mem, vss]):
        units = consolidate.plan_units([(m, []) for m in order])
        merged = [u for u, _ in units if u.merged]
        assert len(merged) == 1
        assert [m.collector for m in merged[0].members] == ["kape", "kape"]
        assert any(u.members == [mem] for u, _ in units)


# --- running a plugin -------------------------------------------------------------

_FAKE = '''
import sys
mode = sys.argv[sys.argv.index("-f") + 2]
print("TreeDepth,PID,ImageFileName")
if mode == "empty":
    sys.exit(0)
print("0,4,System")
if mode == "unicode":
    print("0,8,\\u1168\\u2001name.exe")       # not encodable in a Windows ANSI page
if mode == "paths":
    import csv
    w = csv.writer(sys.stdout, lineterminator="\\n", escapechar="\\\\")
    w.writerow([0, 8, "C:\\\\Windows\\\\system32\\\\svchost.exe -k netsvcs"])
    w.writerow([0, 9, "\\\\\\\\srv\\\\share\\\\tool.exe \\"quoted, arg\\" end\\\\"])
    sys.stdout.write("\\n")                        # the renderer's trailing blank line
if mode == "unsupported":
    sys.stderr.write("NotImplementedError: This version of Windows is not supported: 6.1 15.7601!\\n")
    sys.exit(1)
if mode == "nokernel":
    sys.stderr.write("Unable to validate the plugin requirements: ['plugins.Info.kernel']\\n")
    sys.exit(1)
if mode == "dies":
    print("0,8,half")
    sys.stderr.write("Volatility was unable to read a requested page\\n")
    sys.exit(1)
'''


@pytest.fixture
def fake_vol(tmp_path, monkeypatch):
    script = tmp_path / "fakevol.py"
    script.write_text(_FAKE, encoding="utf-8")
    monkeypatch.setattr(V, "vol_command", lambda: [sys.executable, str(script)])
    _image(tmp_path / "case" / "HOST-01.raw")
    memory.stage_images(tmp_path / "case")
    unit = tmp_path / "case" / "HOST-01_memory"
    _kernel_found(unit)
    return unit


def _kernel_found(unit: Path) -> None:
    """What a successful mem_info leaves: its marker in the category folder."""
    d = unit / "CSVs" / "Memory"
    d.mkdir(parents=True, exist_ok=True)
    (d / ".mem_info.done").write_text("x", encoding="utf-8")


def test_a_plugin_table_is_kept_whole(fake_vol, tmp_path):
    out = tmp_path / "out"
    path = V.run_plugin(_ctx(fake_vol, out), "ok", "mem_t")
    assert path == out / "mem_t.csv"
    assert path.read_text(encoding="utf-8").splitlines() == [
        "TreeDepth,PID,ImageFileName", "0,4,System"]


def test_a_name_the_console_page_cannot_encode_does_not_cut_the_table(fake_vol, tmp_path):
    """The child prints to a FILE; without UTF-8 forced it dies at that row."""
    out = tmp_path / "out"
    path = V.run_plugin(_ctx(fake_vol, out), "unicode", "mem_t")
    rows = path.read_text(encoding="utf-8").splitlines()
    assert rows[-1] == "0,8,ᅨ name.exe"


def test_a_plugin_that_dies_leaves_no_table(fake_vol, tmp_path):
    out = tmp_path / "out"
    with pytest.raises(RuntimeError, match="unable to read a requested page"):
        V.run_plugin(_ctx(fake_vol, out), "dies", "mem_t")
    assert not any(out.iterdir())          # neither the prefix nor the scratch file


def test_a_plugin_that_finds_nothing_writes_nothing(fake_vol, tmp_path):
    out = tmp_path / "out"
    assert V.run_plugin(_ctx(fake_vol, out), "empty", "mem_t") is None
    assert not any(out.iterdir())


def test_no_volatility_is_a_skip_that_says_how_to_get_it(fake_vol, tmp_path, monkeypatch):
    monkeypatch.setattr(V, "vol_command", lambda: None)
    with pytest.raises(HandlerSkip, match="Volatility 3 is not installed"):
        V.run_plugin(_ctx(fake_vol, tmp_path / "out"), "ok", "mem_t")


def test_a_folder_that_is_not_a_unit_is_skipped(tmp_path):
    with pytest.raises(HandlerSkip, match="not a memory unit"):
        V.run_plugin(_ctx(tmp_path, tmp_path / "out"), "ok", "mem_t")


def test_a_table_longer_than_a_diagnostic_is_kept_whole(tmp_path):
    big = procs._MAX_CAPTURE * 2
    dst = tmp_path / "o.txt"
    rc, _err = V._run_to_file([sys.executable, "-c", f"print('x' * {big})"], dst, 60)
    assert rc == 0
    assert dst.stat().st_size >= big
    assert not procs._active                 # deregistered once it has exited


def test_the_launcher_does_not_hand_volatility_its_own_dash_c(tmp_path, monkeypatch):
    """`python -c` puts "-c" in argv[0]; Volatility parses it as `--config`."""
    pkg = tmp_path / "site" / "volatility3" / "cli"
    pkg.mkdir(parents=True)
    (pkg.parent / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "__init__.py").write_text(
        "import sys\ndef main():\n    print(repr(sys.argv))\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "site"))
    rc, out, err = procs.run([sys.executable, "-c", V._LAUNCH, "-q", "plugin"])
    assert rc == 0, err
    assert out.strip() == repr(["vol", "-q", "plugin"])


def test_a_unit_queues_the_memory_parsers_and_nothing_else(tmp_path):
    from artifact_engine.core import scheduler
    _image(tmp_path / "HOST-01.raw")
    memory.stage_images(tmp_path)
    m = detector.detect_machines(tmp_path, _profiles())[0]
    queued = {p.id for p in scheduler._applicable(m, load_parsers([DATA_DIR / "parsers"]))}
    assert queued and all(i.startswith("mem_") for i in queued)


# --- found by review ----------------------------------------------------------------

def test_an_image_in_a_folder_named_like_a_unit_is_still_found(tmp_path):
    """`HOST-01_memory.zip` extracts to `HOST-01_memory/`: only a POINTER marks a unit."""
    img = _image(tmp_path / "HOST-01_memory" / "HOST-01.raw")
    assert memory.find_images(tmp_path) == [img]


def test_an_image_inside_a_disk_tree_gets_no_unit_and_is_reported(tmp_path, caplog):
    vol = tmp_path / "HOST-02"
    (vol / "Windows" / "System32").mkdir(parents=True)
    _image(vol / "mem.raw")
    _image(vol / "Windows" / "MEMORY.DMP")
    with caplog.at_level(logging.WARNING, logger="aeng"):
        assert memory.stage_images(tmp_path) == []
    assert not (vol / "mem_memory").exists()                # nothing written into it
    assert "inside a disk acquisition" in caplog.text


def test_an_existing_folder_of_the_units_name_is_never_adopted(tmp_path, caplog):
    """It may hold originals; a pointer would prune them from custody."""
    _image(tmp_path / "HOST-01.raw")
    theirs = tmp_path / "HOST-01_memory"
    theirs.mkdir()
    (theirs / "acquisition.log").write_text("x", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="aeng"):
        assert memory.stage_images(tmp_path) == []
    assert not (theirs / memory.POINTER).exists()
    found = {p.name for p in hashing._iter_original_files(tmp_path)}
    assert "acquisition.log" in found
    assert "is not a memory unit" in caplog.text


def test_a_unit_detection_does_not_reach_is_reported(tmp_path, monkeypatch, caplog):
    _image(tmp_path / "HOST-01.raw")

    class _Cfg:
        avoid_vss = True
    monkeypatch.setattr(detector, "detect_machines", lambda *a, **k: [])
    with caplog.at_level(logging.WARNING, logger="aeng"):
        pipeline.detect(tmp_path, _Cfg(), [], stage_drops=True)
    assert "was not detected as a machine" in caplog.text


# --- v0.7.89: the unit's .db/.xlsx lie beside the image ------------------------------

def _unit_with_tables(tmp_path):
    _image(tmp_path / "HOST-01.raw")
    memory.stage_images(tmp_path)
    m = detector.detect_machines(tmp_path, _profiles())[0]
    d = m.path / "CSVs" / "Memory"
    d.mkdir(parents=True)
    (d / "mem_pslist.csv").write_text("PID,ImageFileName\n4,System\n", encoding="utf-8")
    return m


def test_a_memory_units_database_is_written_beside_the_image(tmp_path):
    m = _unit_with_tables(tmp_path)
    units = consolidate.plan_units([(m, [])])
    st = consolidate.build_unit(units[0][0], emit_db=True, emit_xlsx=True)
    assert not st["not_built"]
    assert (tmp_path / "HOST-01_memory.db").is_file()
    assert (tmp_path / "HOST-01_memory.xlsx").is_file()
    assert not list(m.path.glob("*.db")) and not list(m.path.glob("*.xlsx"))
    # and the cache sees it there: a second build is skipped, not rebuilt
    again = consolidate.build_unit(consolidate.plan_units([(m, [])])[0][0])
    assert again.get("cached")


def test_the_database_beside_a_unit_is_not_an_original(tmp_path):
    m = _unit_with_tables(tmp_path)
    consolidate.build_unit(consolidate.plan_units([(m, [])])[0][0])
    found = {p.name for p in hashing._iter_original_files(tmp_path)}
    assert found == {"HOST-01.raw"}


def test_search_finds_the_database_beside_a_unit_at_the_case_root(tmp_path):
    from artifact_engine.core import sweep
    m = _unit_with_tables(tmp_path)
    consolidate.build_unit(consolidate.plan_units([(m, [])])[0][0], emit_xlsx=False)
    (tmp_path / "case.db").write_bytes(b"")
    (tmp_path / "other.db").write_bytes(b"")          # not beside a unit: case state
    assert [label for label, _ in sweep.find_case_databases(tmp_path)] == ["HOST-01_memory"]


def test_a_disk_machine_keeps_its_database_in_its_own_folder(tmp_path):
    m = Machine("HOST-01", "windows", "kape", "windows_kape", tmp_path / "C", "acq",
                [Volume("C", tmp_path / "C", True)])
    unit = consolidate.plan_units([(m, [])])[0][0]
    assert unit.output(".db") == tmp_path / "C" / "HOST-01.db"


def test_excels_owner_file_beside_a_unit_is_not_an_original(tmp_path):
    m = _unit_with_tables(tmp_path)
    consolidate.build_unit(consolidate.plan_units([(m, [])])[0][0])
    (tmp_path / "~$HOST-01_memory.xlsx").write_bytes(b"owner")
    found = {p.name for p in hashing._iter_original_files(tmp_path)}
    assert found == {"HOST-01.raw"}


def test_the_database_an_older_run_left_inside_the_unit_is_reported_and_not_searched(tmp_path):
    from artifact_engine.core import sweep
    m = _unit_with_tables(tmp_path)
    old = m.path / f"{m.name}.db"
    old.write_bytes(b"")
    unit = consolidate.plan_units([(m, [])])[0][0]
    consolidate.build_unit(unit, emit_xlsx=False)
    assert consolidate.stale_outputs(unit) == [old]
    assert old.is_file()                                   # reported, never deleted
    assert [label for label, _ in sweep.find_case_databases(tmp_path)] == ["HOST-01_memory"]


def test_a_path_reads_back_as_windows_wrote_it(fake_vol, tmp_path):
    """Volatility's CSV doubles every backslash; the table must not (v0.7.90)."""
    out = tmp_path / "out"
    path = V.run_plugin(_ctx(fake_vol, out), "paths", "mem_t")
    with path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.reader(fh))           # read plainly, as consolidation does
    assert rows[-2][2] == "C:\\Windows\\system32\\svchost.exe -k netsvcs"
    assert rows[-1][2] == '\\\\srv\\share\\tool.exe "quoted, arg" end\\'
    assert len(rows) == 4                     # header, System, two paths; no blank row


# --- v0.7.91: one error when there is no kernel, not one per plugin ----------------

def test_without_a_kernel_the_plugins_skip_naming_mem_info(fake_vol, tmp_path):
    (fake_vol / "CSVs" / "Memory" / ".mem_info.done").unlink()
    with pytest.raises(HandlerSkip, match="mem_info did not succeed"):
        V.run_plugin(_ctx(fake_vol, tmp_path / "out"), "ok", "mem_pslist")


def test_mem_info_itself_runs_without_its_own_marker(fake_vol, tmp_path):
    (fake_vol / "CSVs" / "Memory" / ".mem_info.done").unlink()
    assert V.run_plugin(_ctx(fake_vol, tmp_path / "out"), "ok", "mem_info") is not None


def test_no_kernel_is_said_in_words(fake_vol, tmp_path):
    with pytest.raises(RuntimeError, match="no Windows kernel it can read"):
        V.run_plugin(_ctx(fake_vol, tmp_path / "out"), "nokernel", "mem_info")


def test_a_plugin_that_declines_the_windows_version_is_a_skip_not_an_error(fake_vol, tmp_path):
    with pytest.raises(HandlerSkip, match="does not support this Windows version"):
        V.run_plugin(_ctx(fake_vol, tmp_path / "out"), "unsupported", "mem_cmdscan")
