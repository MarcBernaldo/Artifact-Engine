import sys

from artifact_engine import logging_setup


class _Args:
    """Stand-in for sys.UnraisableHookArgs (the real one has no public
    constructor); our hook and the delegate only read these attributes."""

    def __init__(self, exc, err_msg=""):
        self.exc_type = type(exc)
        self.exc_value = exc
        self.exc_traceback = None
        self.err_msg = err_msg
        self.object = None


def _with_spy_original():
    """Install our quiet hook on top of a recording spy, so we can observe what
    gets delegated. Returns (delegated_list, restore_fn)."""
    delegated: list = []
    saved = sys.unraisablehook
    sys.unraisablehook = lambda args: delegated.append(args.exc_value)
    # Force a fresh install over the spy (the spy becomes `original`).
    if getattr(sys.unraisablehook, "_aeng_quiet", False):  # pragma: no cover
        pass
    logging_setup._install_quiet_unraisablehook()

    def restore():
        sys.unraisablehook = saved

    return delegated, restore


def test_benign_buffererror_is_suppressed():
    delegated, restore = _with_spy_original()
    before = logging_setup._suppressed_unraisables
    try:
        sys.unraisablehook(_Args(BufferError("memoryview has 1 exported buffer"),
                                 "Exception ignored in tp_clear of"))
        assert delegated == []  # dropped, not delegated
        # counted, not logged: the hook does NO I/O (logging from the GC-context
        # hook re-enters the log stream and deadlocks -- see _install_...docstring)
        assert logging_setup._suppressed_unraisables == before + 1
    finally:
        restore()


def test_the_313_wording_of_the_same_conflict_is_suppressed_too():
    """CPython words one buffer-export conflict two ways, and the wording moved
    with the interpreter: 3.10 reached a memoryview ("memoryview has 1 exported
    buffer"), 3.13 reaches a BytesIO ("Existing exports of data: object cannot be
    re-sized"). Matching only the first meant the filter silently stopped working
    on the migration -- a real run printed raw tracebacks from dataclasses.py,
    functools.py and textwrap.py into the middle of the console output."""
    delegated, restore = _with_spy_original()
    before = logging_setup._suppressed_unraisables
    try:
        sys.unraisablehook(_Args(
            BufferError("Existing exports of data: object cannot be re-sized"),
            "Exception ignored in"))
        assert delegated == [], "the 3.13 wording reached the default hook and printed"
        assert logging_setup._suppressed_unraisables == before + 1
    finally:
        restore()


def test_quiet_hook_does_no_logging():
    """Regression guard: the benign path must not emit a log record. Logging from
    the GC-context unraisablehook re-enters the file handler's buffered stream and
    can deadlock the run, so the hook must stay I/O-free."""
    import logging as _logging

    _, restore = _with_spy_original()
    emitted: list = []

    class _Spy(_logging.Handler):
        def emit(self, record):
            emitted.append(record)

    lg = _logging.getLogger("aeng")
    spy = _Spy()
    lg.addHandler(spy)
    old_level = lg.level
    lg.setLevel(_logging.DEBUG)
    try:
        sys.unraisablehook(_Args(BufferError("memoryview has 2 exported buffers")))
        assert emitted == []   # hook counted it but wrote NOTHING to any handler
    finally:
        lg.removeHandler(spy)
        lg.setLevel(old_level)
        restore()


def test_other_unraisable_is_delegated():
    delegated, restore = _with_spy_original()
    try:
        real = ValueError("a genuine bug")
        sys.unraisablehook(_Args(real, "in <lambda>"))
        assert delegated == [real]  # passed through to the default hook
    finally:
        restore()


def test_unrelated_buffererror_is_delegated():
    # A BufferError that is NOT the mp/GC "exported buffer" artifact must not be
    # swallowed -- only the exact benign string is filtered.
    delegated, restore = _with_spy_original()
    try:
        other = BufferError("some other buffer problem")
        sys.unraisablehook(_Args(other))
        assert delegated == [other]
    finally:
        restore()


def test_install_is_idempotent():
    saved = sys.unraisablehook
    try:
        logging_setup._install_quiet_unraisablehook()
        first = sys.unraisablehook
        logging_setup._install_quiet_unraisablehook()
        assert sys.unraisablehook is first  # not re-wrapped
        assert getattr(sys.unraisablehook, "_aeng_quiet", False)
    finally:
        sys.unraisablehook = saved
