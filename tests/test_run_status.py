"""The run's verdict as one pure function (AE-115)."""

import pytest

from artifact_engine.core.report import run_status

_CLEAN = {"errors": 0, "incomplete": 0, "broken": 0, "waiting": 0, "not_hashed": 0,
          "not_covered": 0, "machines": 1}


def test_a_run_with_nothing_wrong_is_complete():
    assert run_status(**_CLEAN) == "complete"


@pytest.mark.parametrize("cause", ["errors", "incomplete", "broken", "waiting",
                                   "not_hashed", "not_covered"])
def test_each_cause_alone_makes_the_run_incomplete(cause):
    assert run_status(**{**_CLEAN, cause: 1}) == "incomplete"


def test_a_run_that_detected_no_machine_is_incomplete():
    assert run_status(**{**_CLEAN, "machines": 0}) == "incomplete"
