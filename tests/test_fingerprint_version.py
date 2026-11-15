"""A release does not re-run parsers whose code did not change."""

from artifact_engine import __version__
from artifact_engine.core import runner


def test_a_handler_reaching_the_package_does_not_carry_its_version():
    # mem_volatility imports from the package itself (`from artifact_engine import
    # volplugins`), so its closure holds artifact_engine/__init__.py: every
    # memory parser re-ran on every release.
    runner._SRC_CACHE.clear()
    blob = runner._handler_closure("artifact_engine.handlers.mem_volatility:run")
    assert b"\n--artifact_engine--\n" in blob
    assert __version__.encode() not in blob
    assert b"__version__ =" not in blob


def test_the_consolidation_does_not_carry_the_version():
    runner._SRC_CACHE.clear()
    blob = runner._handler_closure("artifact_engine.core.consolidate:build")
    assert b"\n--artifact_engine--\n" in blob
    assert b"__version__ =" not in blob.split(b"\n--artifact_engine--\n", 1)[1].split(b"\n--", 1)[0]


def test_the_rest_of_the_package_init_still_counts():
    a = b'"""doc"""\n\n__version__ = "1.0.0"\nX = 1\n'
    b = b'"""doc"""\n\n__version__ = "1.0.1"\nX = 1\n'
    c = b'"""doc"""\n\n__version__ = "1.0.0"\nX = 2\n'
    assert runner._module_source("artifact_engine", a) == runner._module_source("artifact_engine", b)
    assert runner._module_source("artifact_engine", a) != runner._module_source("artifact_engine", c)
    crlf = a.replace(b"\n", b"\r\n")
    assert b"1.0.0" not in runner._module_source("artifact_engine", crlf)
    # only the package's own: a module elsewhere keeps such a line
    assert runner._module_source("artifact_engine.core.x", a) == a
