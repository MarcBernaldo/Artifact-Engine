"""The web parsers' fixed-string checks as tries (v0.7.111): same answers as the
flat forms they replaced. All text is synthetic."""

import random
import re
from collections import Counter

from artifact_engine.handlers import _webcommon as C
from artifact_engine.handlers import _webrules as W
from artifact_engine.handlers import lin_web_metrics as M

# The pre-filter as v0.7.110 shipped it, a flat alternation.
_FLAT = re.compile(
    r"union|select|sleep\(|benchmark|information_schema|group_concat|extractvalue|updatexml|waitfor|"
    r"<script|%3cscript|onerror|onload|onmouseover|javascript:|<svg|<iframe|"
    r"\$\{|jndi|%24%7b|"
    r"php://|file://|data://|expect://|phar://|%3a%2f%2f|"
    r"/etc/passwd|/etc/shadow|passwd|proc/self|win\.ini|boot\.ini|"
    r"\.\./|\.\.\\|%2e%2e|%00|"
    r"shell_exec|passthru|system\(|popen|proc_open|pcntl_exec|call_user_func|invokefunction|think|"
    r"wget|curl|chmod|/bin/|bash|/dev/tcp|nc -e|ncat|phpinfo|allow_url_include|auto_prepend|"
    r"c99|r57|wso|b374k|weevely|eval\(|assert\(|base64_decode|\$_(get|post|request|cookie)",
)


def _texts(words, rnd, n=4000):
    """Random text around chopped and whole words: hits, near-misses, case."""
    noise = "/?=&.-_%2e:{}$()<> aZ09\\"
    for _ in range(n):
        parts = []
        for _ in range(rnd.randint(0, 4)):
            w = rnd.choice(words)
            if rnd.random() < 0.5:
                a = rnd.randint(0, len(w))
                w = w[a:a + rnd.randint(1, len(w))]
            if rnd.random() < 0.2:
                w = w.upper()
            parts.append(w)
            parts.append("".join(rnd.choice(noise) for _ in range(rnd.randint(0, 3))))
        yield "".join(parts)


def _flat_words():
    """The strings the flat pattern matched, read off its branches."""
    words = set()
    for b in _FLAT.pattern.split("|"):
        words.add(b.replace("\\", "") if b != r"\.\.\\" else "..\\")
    words -= {"$_(get", "post", "request", "cookie)"}
    return sorted(words | {"$_get", "$_post", "$_request", "$_cookie"})


def test_the_payload_prefilter_answers_as_the_flat_pattern_did():
    """Text is built from the OLD pattern's strings, so a word the new list
    lost still shows up -- and the answers would differ."""
    rnd = random.Random(7)
    words = _flat_words()
    for w in words:
        assert _FLAT.fullmatch(w), w
    for text in _texts(words, rnd):
        assert W.prefilter(text) == (_FLAT.search(text.lower()) is not None), text


def test_the_list_is_the_flat_patterns_strings():
    assert set(_flat_words()) == set(W._PREFILTER_WORDS)


def test_hosting_answers_as_the_substring_scan_did():
    rnd = random.Random(3)
    words = list(C._HOSTING)
    for org in _texts(words, rnd):
        assert C.is_hosting(org) == any(k in org.lower() for k in C._HOSTING), org


def test_top_is_most_common_ties_included():
    rnd = random.Random(5)
    for _ in range(2000):
        c = Counter({f"k{i}": rnd.randint(1, 4) for i in range(rnd.randint(0, 40))})
        for n in (1, 2, 4, 8):
            assert M._top(c, n) == c.most_common(n)
