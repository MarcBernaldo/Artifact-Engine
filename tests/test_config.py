"""AE-109: a configuration is checked, and never read from inside the case."""

from __future__ import annotations

import os

import pytest

from artifact_engine import config as cfgmod
from artifact_engine.config import ConfigError, load_config


def _cfg(tmp_path, text: str):
    f = tmp_path / "config.yaml"
    f.write_text(text, encoding="utf-8")
    return load_config(f)


@pytest.mark.parametrize("text", [
    "avoid_vss: ture\n",              # a mistyped flag kept the default in silence
    "max_workers: \n",                # empty
    "max_workers: lots\n",            # not a number: a raw traceback
    "extract_depth: 0\n",             # extracted nothing, archive after archive
    "settle_seconds: -5\n",
    "- just a list\n",                # not a mapping of settings
    "max_workers: [unclosed\n",       # not YAML
])
def test_a_value_that_cannot_be_used_is_a_config_error(tmp_path, text):
    with pytest.raises(ConfigError):
        _cfg(tmp_path, text)


def test_a_config_file_that_is_not_there_is_an_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.yaml")


def test_an_unknown_setting_is_said(tmp_path):
    cfg = _cfg(tmp_path, "avoid_vs: false\n")
    assert any("avoid_vs" in n for n in cfg.notes) and cfg.avoid_vss is True


def test_the_worker_ceiling_holds_where_the_process_pool_does(tmp_path):
    """`ProcessPoolExecutor` refuses more than 61 workers on Windows, and phase 3
    ended with a ValueError over a config `aeng setup` writes on a 64-core host."""
    cfg = _cfg(tmp_path, "max_workers: 64\n")
    assert cfg.max_workers == (61 if os.name == "nt" else 64)
    assert cfgmod.MAX_WORKERS_CEILING <= (61 if os.name == "nt" else 64)


def test_a_working_directory_inside_the_case_is_not_read(tmp_path, monkeypatch):
    """A case folder is evidence somebody delivered: its config.yaml, parsers/ and
    profiles/ (whose `command` is run as written) are not configuration."""
    case = tmp_path / "case"
    (case / "parsers").mkdir(parents=True)
    (case / "config.yaml").write_text("avoid_vss: false\n", encoding="utf-8")
    monkeypatch.setattr(cfgmod, "install_dir", lambda: None)
    monkeypatch.chdir(case)

    outside = load_config()
    assert outside.avoid_vss is False and case / "parsers" in outside.all_parser_dirs

    inside = load_config(case_root=case)
    assert inside.avoid_vss is True and not inside.trust_cwd
    assert case / "parsers" not in inside.all_parser_dirs
    assert case / "profiles" not in inside.all_profile_dirs
    assert inside.notes


def test_a_config_error_stops_the_command_with_exit_1(tmp_path):
    from artifact_engine import cli

    (tmp_path / "bad.yaml").write_text("extract_depth: 0\n", encoding="utf-8")
    assert cli.main(["run", "-p", str(tmp_path), "-c", str(tmp_path / "bad.yaml")]) == 1


def test_aeng_run_from_inside_the_case_does_not_read_its_config(tmp_path, monkeypatch):
    import argparse

    from artifact_engine import cli
    from artifact_engine.core import extractor, pipeline

    (tmp_path / "config.yaml").write_text("extract_depth: 0\n", encoding="utf-8")
    monkeypatch.setattr(cfgmod, "install_dir", lambda: None)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(extractor, "extract_all", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "detect", lambda *a, **k: [])
    args = argparse.Namespace(path=str(tmp_path), config=None, verbose=False, force=False)
    assert cli.cmd_run(args) == cli.EXIT_INCOMPLETE        # ran: nothing detected


@pytest.mark.parametrize("text", ["settle_seconds: 0.5\n", "max_workers: 8.9\n"])
def test_a_decimal_in_a_whole_number_setting_is_an_error(tmp_path, text):
    """Found by review: cut short, `settle_seconds: 0.5` became 0, which opens an
    unsealed archive at once."""
    with pytest.raises(ConfigError):
        _cfg(tmp_path, text)


def test_a_config_error_leaves_the_last_verdict_and_prints_no_traceback(tmp_path, capsys):
    """Found by review: raised inside the run's wrapper, it printed a traceback and
    replaced the previous verdict with a stub over a typo."""
    from artifact_engine import cli

    (tmp_path / "run-summary.json").write_text('{"status": "complete"}', encoding="utf-8")
    (tmp_path / "bad.yaml").write_text("extract_depth: 0\n", encoding="utf-8")
    assert cli.main(["run", "-p", str(tmp_path), "-c", str(tmp_path / "bad.yaml")]) == 1
    assert "Traceback" not in capsys.readouterr().err
    assert (tmp_path / "run-summary.json").read_text(encoding="utf-8") == '{"status": "complete"}'


def test_every_command_says_what_loading_the_config_had_to_say(tmp_path, monkeypatch, caplog):
    import logging

    from artifact_engine import cli

    (tmp_path / "config.yaml").write_text("avoid_vs: false\n", encoding="utf-8")
    monkeypatch.setattr(cfgmod, "install_dir", lambda: None)
    monkeypatch.chdir(tmp_path)
    with caplog.at_level(logging.WARNING, logger="aeng"):
        cli.main(["list-parsers"])
    assert any("avoid_vs" in r.message for r in caplog.records)
