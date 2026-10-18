"""v0.7.120: `could_match` answers exactly as the scan it short-cuts, checked
against the code it replaced, on generated inputs."""
from __future__ import annotations

import random

from artifact_engine.handlers import _awesome


def test_the_suffix_trie_answers_as_endswith_did():
    """`could_match` asks the suffixes as one trie over reversed strings instead
    of `endswith(tuple)`; every answer must be the same -- including an empty
    suffix (`*`)."""
    rnd = random.Random(5)
    exts = [f"*.{rnd.choice('abcdefgh')}{rnd.choice('xyz')}{i}" for i in range(300)]
    lists = [_awesome.Patterns(_awesome.Entry(pattern=_awesome.to_regex(r), raw=r)
                               for r in raws)
             for raws in (exts, ["*.LOCKED", "*", "*.tar.gz", "*.gz", "exact.txt"],
                          ["README_*.txt", "HOW_TO_DECRYPT.txt", "*.enc"])]
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
