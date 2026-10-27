"""The web timeline read in slices (v0.7.112): every row once, and web_metrics
answering exactly as one pass does. All values are synthetic."""

import csv
import logging
import random
import re
from itertools import pairwise

import pytest

from artifact_engine.config import DATA_DIR
from artifact_engine.core.runner import ParserContext, marker_path
from artifact_engine.handlers import _webshard as S
from artifact_engine.handlers import lin_web_metrics as M
from artifact_engine.handlers._webcommon import _PREPARSED, _PREPARSED_HEADER, _from_csv

_PATHS = ["/", "/index.php", "/a", "/b", "/c", "/.git/config", "/wp-login.php", "/x.php.bak",
          "/admin", "/login", "/d", "/e", "/search", "/img/1.png", "/img/2.png"]
_UAS = ["Mozilla/5.0", "curl/8", "sqlmap/1.7", "-", "", "Go-http-client/1.1", "UA-a", "UA-b",
        "UA, with comma", 'UA "quoted"']
_QUERIES = ["", "", "id=1", "q=union select 1", "p=../../etc/passwd", "x=1", "y=2", "z=3"]
_STATUS = ["200", "200", "200", "301", "401", "403", "404", "404", "500", "418", "-"]
_METHODS = ["GET", "GET", "POST", "HEAD", "PUT", "PROPFIND", "", "get"]


def _rows(rnd, n, ips=40):
    out = []
    for i in range(n):
        day = 1 + rnd.randint(0, 3)
        t = "" if rnd.random() < 0.03 else f"2026-10-0{day} 1{rnd.randint(0, 9)}:00:{i % 60:02d} +0000"
        out.append([t, f"10.0.{rnd.randint(0, 3)}.{rnd.randint(1, ips)}", "", rnd.choice(_METHODS),
                    rnd.choice(_STATUS), str(rnd.randint(0, 5000)) if rnd.random() < 0.9 else "-",
                    rnd.choice(_PATHS) + (str(rnd.randint(0, 30)) if rnd.random() < 0.3 else ""),
                    rnd.choice(_QUERIES), "-", rnd.choice(_UAS), "access.log", "", ""])
    return out


def _case(tmp_path, rows, newline_at_end=True, extra=b""):
    """A volume as a finished `web_access` leaves it: logs, timeline, marker."""
    ap = tmp_path / "[root]" / "var" / "log" / "apache2"
    ap.mkdir(parents=True)
    (ap / "access.log").write_text("x\n", encoding="utf-8")
    pre = tmp_path / _PREPARSED
    pre.parent.mkdir(parents=True)
    with pre.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(_PREPARSED_HEADER)
        w.writerows(rows)
    data = pre.read_bytes() + extra
    if not newline_at_end:
        data = data.rstrip(b"\r\n")
    pre.write_bytes(data)
    marker_path(pre.parent, "web_access").write_text("x", encoding="utf-8")
    return pre


def _ctx(tmp_path, out):
    return ParserContext(evidence=tmp_path, out=out, tools=tmp_path, assets=DATA_DIR / "assets",
                         machine_name="HOST-01", volume="live", log=logging.getLogger("aeng.test"))


def _flat(records):
    return [(tuple(getattr(r, k) for k in r.__slots__), src) for r, src in records]


@pytest.mark.parametrize("size", [1, 7, 100, 333, 10**9])
@pytest.mark.parametrize("newline_at_end", [True, False])
def test_the_slices_hold_every_row_once(tmp_path, size, newline_at_end):
    rows = _rows(random.Random(1), 300)
    rows[17][6] = "/caf\u00e9/\u2028odd\x85"          # characters `csv` does not end a row on
    pre = _case(tmp_path, rows, newline_at_end,
                extra=b"2026-10-01,10.0.0.1,,GET,200,1,/cut,,-,-,f,\r\n"     # one field short
                + b'2026-10-01,10.0.0.2,,GET,200,1,"/\xff\xfe",,-,-,f,,\r\n')
    parts = S.ranges(pre, size)
    assert parts[0][0] == len(pre.read_bytes().split(b"\n", 1)[0]) + 1
    assert parts[-1][1] == pre.stat().st_size
    assert all(a[1] == b[0] for a, b in pairwise(parts))
    got = [x for lo, hi in parts for x in _flat(S.read(pre, lo, hi))]
    assert got == _flat(_from_csv(pre))
    assert len(got) == 301                           # the short row is not a request


def test_a_timeline_of_only_its_header_has_no_slices(tmp_path):
    pre = _case(tmp_path, [])
    assert S.ranges(pre, 10) == []


def _small_ceilings(monkeypatch):
    for name, n in (("_PATH_CAP", 4), ("_MAX_404_PATHS", 6), ("_MAX_UAS", 4),
                    ("_MAX_AUTH_ROWS", 7), ("_MAX_PATHS", 9), ("_MAX_QUERIES", 4),
                    ("_UA_IPS", 3), ("_404_IPS", 2), ("_IP_PATHS", 3), ("_IP_UAS", 2),
                    ("_IP_QUERIES", 2), ("_IP_404_CAP", 2), ("_SAMPLES", 2)):
        monkeypatch.setattr(M, name, n)


def _state(t):
    """Everything a _Tally holds that the outputs read, in the order they read it.
    The IP sets (per IP, per UA, per 404 path) are read only for their size."""
    ips = [(ip, st.requests, st.s2xx, st.s3xx, st.s401, st.s403, st.s404, st.s4xx,
            st.s5xx, st.size, len(st.paths), st.capped, list(st.methods.items()), st.attack,
            st.first, st.last, list(st.days.items()), st.samples, list(st.p404.items()),
            list(st.allm.items()), list(st.tp.items()), list(st.uas.items()), list(st.qs.items()))
           for ip, st in t.stats.items()]
    return (ips, list(t.p404.items()), {k: len(v) for k, v in t.p404_ips.items()},
            list(t.auth.items()), list(t.methods_all.items()), list(t.paths_all.items()),
            list(t.uas_all.items()), {k: len(v) for k, v in t.uas_ips.items()},
            list(t.queries_all.items()), t.over_reqs, t.requests)


def test_merged_slices_count_what_one_pass_counts(tmp_path, monkeypatch):
    """The guarantee, fuzzed with every ceiling small enough to be reached many
    times over: slices counted without ceilings and merged in file order hold
    exactly what one bounded pass holds."""
    _small_ceilings(monkeypatch)
    rnd = random.Random(5)
    for k in range(6):
        sub = tmp_path / str(k)
        sub.mkdir()
        pre = _case(sub, _rows(rnd, 1500))
        one = M._Tally().feed(_from_csv(pre))
        for size in (900, 5000, 40000):
            whole = M._Tally()
            for lo, hi in S.ranges(pre, size):
                whole.merge(M._slice(pre, lo, hi))
            assert _state(whole) == _state(one), (k, size)


def _sequential(monkeypatch, size):
    monkeypatch.setattr(S, "slices", lambda ctx: [
        (tmp, lo, hi) for tmp in [ctx.evidence / _PREPARSED] for lo, hi in S.ranges(tmp, size)])
    monkeypatch.setattr(S, "in_order", lambda fn, parts, *a: (fn(*p, *a) for p in parts))


def test_too_many_ips_for_a_merge_counts_again_in_one_pass(tmp_path, monkeypatch):
    _small_ceilings(monkeypatch)
    monkeypatch.setattr(M, "_MAX_IPS", 15)
    pre = _case(tmp_path, _rows(random.Random(9), 1500, ips=60))
    one = M._Tally().feed(_from_csv(pre))
    assert one.over_reqs > 0                         # the ceiling dropped requests
    _sequential(monkeypatch, 2000)
    assert _state(M._count(_ctx(tmp_path, tmp_path / "o"))) == _state(one)


def _outputs(out):
    def html(p):
        return re.sub(r"\d{4}-\d\d-\d\d \d\d:\d\d", "", p.read_text(encoding="utf-8"))
    files = sorted(out.glob("*.csv"))
    return ([(f.name, f.read_bytes()) for f in files],
            [html(p) for p in sorted(out.glob("*.html"))])


def test_a_sliced_run_writes_what_one_pass_writes(tmp_path, monkeypatch):
    _case(tmp_path, _rows(random.Random(3), 3000, ips=200))
    monkeypatch.setattr(S, "slices", lambda ctx: None)
    M.run(_ctx(tmp_path, tmp_path / "one"))
    monkeypatch.undo()
    _sequential(monkeypatch, 4000)
    M.run(_ctx(tmp_path, tmp_path / "sliced"))
    one, sliced = _outputs(tmp_path / "one"), _outputs(tmp_path / "sliced")
    assert one == sliced and one[1] and '"10.0.' in one[1][0]


def test_the_pool_returns_slices_in_file_order(tmp_path, monkeypatch):
    """Real processes, small slices: a later slice finishing first must still be
    folded after the earlier ones."""
    _case(tmp_path, _rows(random.Random(4), 3000, ips=200))
    monkeypatch.setattr(S, "slices", lambda ctx: None)
    M.run(_ctx(tmp_path, tmp_path / "one"))
    monkeypatch.undo()
    monkeypatch.setattr(S, "workers", lambda: 3)
    monkeypatch.setattr(S, "MIN_BYTES", 0)
    monkeypatch.setattr(S, "SLICE_BYTES", 9000)
    ctx = _ctx(tmp_path, tmp_path / "pool")
    assert len(S.slices(ctx)) > 6
    M.run(ctx)
    assert _outputs(tmp_path / "one") == _outputs(tmp_path / "pool")


def test_no_slices_for_a_small_timeline_or_the_raw_logs(tmp_path, monkeypatch):
    pre = _case(tmp_path, _rows(random.Random(2), 50))
    monkeypatch.setattr(S, "workers", lambda: 4)
    ctx = _ctx(tmp_path, tmp_path / "o")
    assert S.slices(ctx) is None                     # under MIN_BYTES
    monkeypatch.setattr(S, "MIN_BYTES", 0)
    assert S.slices(ctx)
    marker_path(pre.parent, "web_access").unlink()   # web_access did not finish
    assert S.slices(ctx) is None
