r"""Where the settings came from, which is a different question from what they are.

`config.yaml` sits at the root of the source tree, so copying the tool to another
machine carries the previous machine's tuning across with it. MEASURED: a 24-core
Linux host was observed running at `max_workers: 32` with the spreadsheet output
off, both inherited in a folder copy, neither chosen for it, and nothing anywhere
saying so. `install_dir()` is also None for a non-editable install, so a wheel had
no baseline location at all and the settings depended on where the analyst
happened to be standing when they launched it.
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

from artifact_engine import cli, config


def _write(path: Path, **values) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(f"{k}: {v}" for k, v in values.items()) + "\n",
                    encoding="utf-8")
    return path


def _isolate(monkeypatch, tmp_path: Path) -> Path:
    """A machine with no config anywhere but where this test puts one.

    `install_dir()` is stubbed out as well: the suite runs FROM the checkout, so
    without this every one of these tests would silently read the developer's own
    `config.yaml` and assert against whatever happens to be in it.
    """
    home = tmp_path / "userconf"
    monkeypatch.setattr(config, "user_config_dir", lambda: home)
    monkeypatch.setattr(config, "install_dir", lambda: None)
    monkeypatch.delenv(config.CONFIG_ENV, raising=False)
    return home


# --------------------------------------------------------------------------- #
# Where a setting may come from
# --------------------------------------------------------------------------- #
def test_the_machines_own_config_is_looked_for_outside_the_checkout(monkeypatch, tmp_path):
    home = _isolate(monkeypatch, tmp_path)
    assert home / "config.yaml" in config.config_candidates()


def test_the_user_config_beats_the_one_shipped_beside_the_tool(monkeypatch, tmp_path):
    """The install is the baseline the tool ships with; this is what the MACHINE
    was set up with. Specific beats general."""
    home = _isolate(monkeypatch, tmp_path)
    _write(home / "config.yaml", max_workers=7)
    monkeypatch.chdir(tmp_path)

    assert config.load_config().max_workers == 7


def test_the_case_folder_still_beats_the_machine(monkeypatch, tmp_path):
    """Per-case is the most specific thing there is, and `avoid_vss` alone is the
    difference between parsing a host's shadow copies and ignoring them."""
    home = _isolate(monkeypatch, tmp_path)
    _write(home / "config.yaml", max_workers=7)
    case = tmp_path / "case"
    _write(case / "config.yaml", max_workers=9)
    monkeypatch.chdir(case)

    assert config.load_config().max_workers == 9


def test_the_environment_variable_names_one_file_and_only_it(monkeypatch, tmp_path):
    """Exactly like `--config`, and for the same reason: someone who names a file
    means that file, not "add it to the pile"."""
    _isolate(monkeypatch, tmp_path)
    chosen = _write(tmp_path / "elsewhere.yaml", max_workers=3)
    monkeypatch.setenv(config.CONFIG_ENV, str(chosen))

    assert config.config_candidates() == [chosen]
    assert config.load_config().max_workers == 3


def test_an_env_var_pointing_at_nothing_is_said_out_loud(monkeypatch, tmp_path, caplog):
    """Falling back silently to the defaults is the failure this ordering exists
    to prevent: the analyst set the variable in order to change something."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv(config.CONFIG_ENV, str(tmp_path / "typo.yaml"))

    with caplog.at_level(logging.WARNING, logger="aeng"):
        config.load_config()
    assert any("not found" in r.message for r in caplog.records)


def test_the_user_config_dir_is_the_platforms_own_convention(monkeypatch, tmp_path):
    """Computed rather than taken from a dependency: one package for two
    environment lookups is not a trade worth making."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    import os

    expected = (tmp_path / "roaming") if os.name == "nt" else (tmp_path / "xdg")
    assert config.user_config_dir() == expected / "artifact-engine"


# --------------------------------------------------------------------------- #
# Saying which one won
# --------------------------------------------------------------------------- #
def test_the_command_names_every_candidate_and_which_applied(monkeypatch, tmp_path, caplog):
    home = _isolate(monkeypatch, tmp_path)
    _write(home / "config.yaml", max_workers=7)
    monkeypatch.chdir(tmp_path)

    with caplog.at_level(logging.INFO, logger="aeng"):
        assert cli.cmd_config(argparse.Namespace(config=None)) == 0
    said = "\n".join(r.message for r in caplog.records)
    assert "applied" in said and str(home / "config.yaml") in said
    assert config.CONFIG_ENV in said


def test_it_flags_a_worker_count_that_does_not_match_this_host(monkeypatch, tmp_path, caplog):
    """The line that would have explained a 24-core host running at 32 without
    anyone choosing that for it."""
    import os

    home = _isolate(monkeypatch, tmp_path)
    _write(home / "config.yaml", max_workers=(os.cpu_count() or 1) + 5)
    monkeypatch.chdir(tmp_path)

    with caplog.at_level(logging.INFO, logger="aeng"):
        cli.cmd_config(argparse.Namespace(config=None))
    said = "\n".join(r.message for r in caplog.records)
    assert "CPU(s)" in said


def test_it_flags_a_tools_dir_inside_the_install(monkeypatch, tmp_path, caplog):
    """`aeng setup` writes 310 MB there, which is fine for an editable checkout
    and is not fine for a system-wide install.

    `tools_dir` is set explicitly here rather than left at its default, because
    `conftest` repoints `PACKAGE_DIR` at a neutral directory for every test -- so
    the default no longer sits inside it, and the interesting case would not be
    the one under test.
    """
    home = _isolate(monkeypatch, tmp_path)
    _write(home / "config.yaml", tools_dir=Path(config.PACKAGE_DIR) / "tools")
    monkeypatch.chdir(tmp_path)

    with caplog.at_level(logging.INFO, logger="aeng"):
        cli.cmd_config(argparse.Namespace(config=None))
    said = "\n".join(r.message for r in caplog.records)
    assert "inside the package" in said


def test_a_tools_dir_outside_the_install_is_not_flagged(monkeypatch, tmp_path, caplog):
    """The counterpart, because a note that is always printed says nothing: an
    analyst who moved the toolchain off the install has already done the thing
    the other test warns about."""
    home = _isolate(monkeypatch, tmp_path)
    _write(home / "config.yaml", tools_dir=tmp_path / "elsewhere" / "tools")
    monkeypatch.chdir(tmp_path)

    with caplog.at_level(logging.INFO, logger="aeng"):
        cli.cmd_config(argparse.Namespace(config=None))
    said = "\n".join(r.message for r in caplog.records)
    assert "inside the package" not in said
