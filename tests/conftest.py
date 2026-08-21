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


@pytest.fixture(autouse=True)
def _no_tool_config(monkeypatch, tmp_path_factory):
    """Point the package at a directory that is NOT a checkout, so only what a
    test writes itself is ever read. Tests that want the tool-level layer set
    `PACKAGE_DIR` themselves (see test_update.py) and override this."""
    from artifact_engine import config as cfgmod

    neutral = tmp_path_factory.mktemp("no_tool_cfg") / "artifact_engine"
    neutral.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(cfgmod, "PACKAGE_DIR", neutral)
