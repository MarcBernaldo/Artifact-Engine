"""The literal gate in front of huntweb's IOC regexes (v0.7.110). All text is synthetic."""

import random
import re

import pytest

from artifact_engine.config import DATA_DIR
from artifact_engine.core import regex_literals as L
from artifact_engine.handlers._indicators import combined, load_indicators


def _gate(patterns, flags=re.IGNORECASE):
    rxs = [re.compile(p, flags) for p in patterns]
    whole = re.compile("|".join(f"(?:{p})" for p in patterns), flags)
    return L.LiteralGate(rxs, whole), whole


@pytest.mark.parametrize("pattern, expected", [
    (r"\b(sqlmap|nikto)\b", [{"sqlmap", "nikto"}]),
    (r"/\.(env|git)\b", [{"/.env", "/.git"}]),
    (r"\.(php|conf)\.(bak|old)", [{".php.bak", ".php.old", ".conf.bak", ".conf.old"}]),
    (r"php[34]?\.exe", [{"php.exe", "php3.exe", "php4.exe"}]),
    (r"/cgi-bin/.*(%2e|bash)", [{"/cgi-bin/"}, {"%2e", "bash"}]),
    (r"(abc)+def", [{"abc"}, {"def"}]),
    (r"(abc)*def", [{"def"}]),
    (r"a|bcd", []),                                   # one branch has nothing
    (r"[^/]+\.txt", [{".txt"}]),
    (r"\w+\s\d+", []),
    ("café", []),                                # not ASCII
])
def test_what_a_regex_needs(pattern, expected):
    got = L.candidates(re.compile(pattern, re.IGNORECASE))
    assert [set(o) for o in got] == expected


def test_the_fold_covers_every_letter_ignorecase_maps_to_ascii():
    """Recomputed on the running interpreter: a character `(?i)[a-z]` matches
    whose lowered form is not that ASCII letter would let a match past the gate."""
    odd = {chr(o) for o in range(0x80, 0x110000) if re.fullmatch("(?i)[a-z]", chr(o))}
    for c in odd:
        assert re.fullmatch("[a-z]", L.fold(c)), hex(ord(c))


def test_a_dotless_i_still_reaches_the_regex(monkeypatch):
    monkeypatch.setattr(L, "CALIBRATE", 1)
    gate, whole = _gate([r"\bnikto\b"])
    gate("warm-up")
    text = "Mozilla nıkto/2.5"
    assert whole.search(text) and gate(text)


_ATOMS = ["abc", "x", "/.", "%2e", "b", "c", "[ab]", "[0-9]", r"\d", r"\s", ".", r"\b", "q?",
          "(ab|cd)", "(xy)+", "(z)*", "[^a]", "ab?c", "(?:a|bc)", "ABC", "(Xy|qZ)"]


def _random_pattern(rnd):
    def piece(depth):
        if depth < 2 and rnd.random() < 0.3:
            return "(" + "|".join(seq(depth + 1) for _ in range(rnd.randint(2, 3))) + ")"
        return rnd.choice(_ATOMS)

    def seq(depth):
        return "".join(piece(depth) for _ in range(rnd.randint(1, 4)))
    return seq(0)


def test_the_gate_answers_exactly_what_the_regexes_do(monkeypatch):
    """The guarantee, fuzzed: 400 random regex lists, each over 300 random texts,
    before and after calibration -- the gate never disagrees with `whole`."""
    monkeypatch.setattr(L, "CALIBRATE", 50)
    rnd = random.Random(11)
    alphabet = "abcxyzq/.%2e0159 _-ABCXYZıſ"
    for _ in range(400):
        patterns = [_random_pattern(rnd) for _ in range(rnd.randint(1, 4))]
        gate, whole = _gate(patterns)
        for _ in range(300):
            text = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 30)))
            assert gate(text) == (whole.search(text) is not None), (patterns, text)


def test_the_web_ioc_list_answers_the_same_through_the_gate(monkeypatch):
    monkeypatch.setattr(L, "CALIBRATE", 20)
    rules = load_indicators(DATA_DIR / "assets" / "web_suspicious.txt")
    whole = combined(rules)
    gate = L.LiteralGate([rx for _, rx in rules], whole)
    texts = ["/index.php?id=1 Mozilla/5.0 (Windows NT 10.0)"] * 30 + [
        "/.git/config curl/8", "/x.php.bak Mozilla", "/cgi-bin/../bin/sh x", "GET /pma/ x",
        "/a sqlmap/1.7", "() { :; }; /bin/bash", "/x?%{(#context)}", "/WSO.PHP x",
        "/vendor/phpunit/src/Util/PHP/eval-stdin.php", "/x ${jndi:ldap://h/a}",
        "/index.php?page=home", "/.environment-check x", "/a?q=x Mozilla/5.0"]
    for t in texts:
        assert gate(t) == (whole.search(t) is not None), t


def test_a_set_most_lines_contain_is_not_used(monkeypatch):
    monkeypatch.setattr(L, "CALIBRATE", 10)
    gate, _ = _gate([r"\.php\b", r"zzz"])
    for _ in range(10):
        gate("/index.php?x=1")
    assert [rx.pattern for rx in gate.open] == [r"\.php\b"]          # asked of every line
    assert gate("/a.php?q=1") and not gate("/a.phpx") and gate("/zzz")


def test_huntweb_finds_the_same_with_and_without_the_gate(tmp_path, monkeypatch):
    import csv
    import io
    import logging

    from artifact_engine.core.runner import ParserContext
    from artifact_engine.handlers import lin_huntweb as H
    monkeypatch.setattr(L, "CALIBRATE", 3)
    lines = [
        '10.0.0.5 - - [10/Oct/2026:13:00:01 +0000] "GET /.git/config HTTP/1.1" 404 1 "-" "curl/8"',
        '10.0.0.6 - - [10/Oct/2026:13:00:02 +0000] "GET /pma/ HTTP/1.1" 200 1 "-" "Mozilla"',
        '10.0.0.7 - - [10/Oct/2026:13:00:03 +0000] "GET /a HTTP/1.1" 200 1 "-" "sqlmap/1.7"',
        '10.0.0.8 - - [10/Oct/2026:13:00:04 +0000] "GET /index.php?id=7 HTTP/1.1" 200 1 "-" "Mozilla"',
        '10.0.0.9 - - [10/Oct/2026:13:00:05 +0000] "GET /x.php.bak HTTP/1.1" 200 1 "-" "Mozilla"',
    ] * 4
    ap = tmp_path / "[root]" / "var" / "log" / "apache2"
    ap.mkdir(parents=True)
    (ap / "access.log").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def run(out):
        H.run(ParserContext(evidence=tmp_path, out=out, tools=tmp_path, assets=DATA_DIR / "assets",
                            machine_name="HOST-01", volume="live",
                            log=logging.getLogger("aeng.test")))
        return list(csv.reader(io.StringIO((out / "huntweb.csv").read_text(encoding="utf-8"))))

    gated = run(tmp_path / "gated")
    monkeypatch.setattr(H, "LiteralGate", lambda rxs, whole: (
        lambda text: whole is not None and whole.search(text) is not None))
    assert gated == run(tmp_path / "plain")
    # sqlmap, .php.bak; /pma/ and /.git/ are no longer indicators (v0.7.142)
    assert len(gated) == 1 + 2 * 4
