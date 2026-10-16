"""v0.7.120: the bodyfile detectors made faster must answer exactly as before.
Each new piece is checked against the code it replaced, on generated inputs."""
from __future__ import annotations

import random
from datetime import datetime

from artifact_engine.config import DATA_DIR
from artifact_engine.handlers import _awesome, _ransom
from artifact_engine.handlers import lin_timestomp as T

_PIECES = ["", "/", "//", "tmp", "home", "Root", "usr", "local", "opt", "var", "www", "x",
           "srv", "dev", "shm", "spool", "a.b", ".hidden", "Ä", "İ", "café"]


def _paths(rnd, n=4000):
    for _ in range(n):
        yield "/".join(rnd.choice(_PIECES) for _ in range(rnd.randint(0, 6)))


def test_bucket_and_writable_answer_as_before():
    # v0.7.140 anchored the writable test at the start of the path on purpose
    old_writable = (lambda p: (p or "").lower().startswith(T._WRITABLE))

    def old_bucket(path, ctime):
        parts = [p for p in (path or "").split("/") if p]
        return (ctime[:10], parts[0].lower() if parts else "")

    rnd = random.Random(11)
    for path in _paths(rnd):
        assert T.writable(path) == old_writable(path), path
        assert T.bucket(path, "2026-05-19 10:15:00") == old_bucket(path, "2026-05-19 10:15:00")


def test_delta_days_answers_as_before():
    def old(later, earlier):
        try:
            return (datetime.fromisoformat(later) - datetime.fromisoformat(earlier)).days
        except ValueError:
            return 0

    values = ["2026-05-19 10:15:00", "2026-05-19 09:00:00", "2019-01-01 00:00:00",
              "", "garbage", "2026-02-30 00:00:00", "2026-05-19"]
    for a in values:
        for b in values:
            assert T._delta_days(a, b) == old(a, b), (a, b)


def test_the_suffix_trie_answers_as_endswith_did():
    """`could_match` asks the suffixes as one trie over reversed strings instead
    of `endswith(tuple)`; over the shipped ransomware extensions and the note
    names, every answer must be the same -- including an empty suffix (`*`)."""
    notes, exts = _ransom.load_lists(DATA_DIR / "assets")
    lists = [exts, notes, _awesome.Patterns(
        _awesome.Entry(pattern=_awesome.to_regex(r), raw=r)
        for r in ("*.LOCKED", "*", "*.tar.gz", "*.gz", "exact.txt"))]
    rnd = random.Random(5)
    samples = []
    for p in lists:
        for sfx in p.suffixes:
            samples += [f"report{sfx}", f"report{sfx}x", sfx.upper(), sfx[1:], f"a{sfx}.b"]
    samples += [f"file.{rnd.choice(['doc', 'pdf', 'xlsx', 'locked', 'GZ', ''])}"
                for _ in range(2000)]
    for p in lists:
        for text in samples:
            low = text.lower()
            old = (low in p.literals or (bool(p.suffixes) and low.endswith(p.suffixes))
                   or (p.others is not None and p.others.search(text) is not None))
            assert p.could_match(text) == old, (text, p.suffixes[:3])
