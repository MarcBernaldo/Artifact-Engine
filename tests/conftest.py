"""Shared test setup.

The one thing that must be neutral for every test: the config that ships beside
the tool. Since `load_config` started reading it as a baseline -- so a run
launched from a case folder or the right-click menu still gets the analyst's
settings -- the developer's own `config.yaml` would otherwise leak into every
test that builds a Config, and the suite would pass or fail depending on whose
machine it ran on (`avoid_vss: false` in that file is enough to do it).
"""

from __future__ import annotations

import pytest

from artifact_engine import logging_setup


@pytest.fixture(autouse=True)
def _no_tool_config(monkeypatch, tmp_path_factory):
    """Point the package at a directory that is NOT a checkout, so only what a
    test writes itself is ever read. Tests that want the tool-level layer set
    `PACKAGE_DIR` themselves (see test_update.py) and override this."""
    from artifact_engine import config as cfgmod

    neutral = tmp_path_factory.mktemp("no_tool_cfg") / "artifact_engine"
    neutral.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(cfgmod, "PACKAGE_DIR", neutral)


@pytest.fixture(autouse=True)
def _no_global_log(monkeypatch, tmp_path_factory):
    """Keep the suite out of the analyst's own log directory.

    `setup_logging` attaches the global log unconditionally, and the suite calls
    it -- so without this, running the tests would append to the same file real
    runs write to, and the rotation counters would be measured against whatever
    was already in it. Pointed at a temporary directory rather than disabled, so
    the tests that assert the file IS written still have somewhere to look.
    """
    monkeypatch.setenv(logging_setup.GLOBAL_LOG_ENV,
                       str(tmp_path_factory.mktemp("global_log")))
