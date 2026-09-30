"""`docs/atlas.html` describes the parsers that ship, or CI is red.

The overview of what this tool reads and produces was a hand-written page. It was
true the day it was written and would have started ageing with the next parser,
with nothing in the repository to notice. These tests are what makes it an output
of the tool instead: the page is regenerated and compared, and a parser cannot
land without saying where it reads from and what its table is.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from artifact_engine.config import DATA_DIR
from artifact_engine.core import atlas
from artifact_engine.core.runner import parser_fingerprint
from artifact_engine.registry import load_parsers, load_profiles

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def parsers():
    return load_parsers([DATA_DIR / "parsers"])


@pytest.fixture(scope="module")
def page():
    return atlas.build()


def test_the_committed_page_still_describes_the_parsers_that_ship(page):
    """The whole point of the atlas (docs/ARCHITECTURE.md §4b). A parser added,
    renamed, recategorised or given a different description without regenerating
    leaves this page describing a tool that is not the one in the repository -- and
    that is exactly the drift the hand-written version could not be protected from.

        python -m artifact_engine.core.atlas
    """
    committed = (REPO / atlas.PAGE).read_text(encoding="utf-8")

    assert committed == page, (
        "docs/atlas.html no longer matches the manifests -- regenerate it with "
        "`python -m artifact_engine.core.atlas` and commit the result")


def test_every_bundled_parser_says_where_it_reads_from_and_what_its_table_is(parsers):
    """A new parser cannot land undocumented. Both keys default to something valid
    so a parser an ANALYST adds of their own still loads; what this pins is the 113
    that ship, where an empty `source` would render an empty cell on the page."""
    no_source = sorted(p.id for p in parsers if not p.source.strip())
    assert no_source == [], f"no `source:` in the manifest of: {no_source}"
    bad = sorted(p.id for p in parsers if p.alert not in atlas.ALERT_LABEL)
    assert bad == [], f"`alert:` is not detect/flag/context in: {bad}"


def test_the_documentary_keys_cost_no_re_parse(parsers):
    """`source` and `alert` are documentation, so writing one must not invalidate a
    `.done` marker -- otherwise editing the map re-parses the case. Verified against
    the fingerprint itself rather than by reading `core/runner.py`: it hashes
    id/command/handler/short/requires/tool.binary and the handler's import closure,
    and neither key is any of those."""
    p = next(p for p in parsers if p.handler)
    before = parser_fingerprint(p)

    changed = p.model_copy(update={"source": "somewhere else entirely",
                                   "alert": "detect" if p.alert != "detect" else "flag"})

    assert parser_fingerprint(changed) == before


def test_the_page_names_every_parser_that_ships(parsers, page):
    """The comparison above would pass a generator that silently dropped rows, as
    long as the committed copy had been regenerated from the same bug."""
    missing = sorted(p.id for p in parsers if f"<code>{p.id}</code>" not in page)

    assert missing == []
    assert f"<h2>The {len(parsers)} artifacts</h2>" in page


def test_the_page_asks_the_network_for_nothing(page):
    """The rule the two existing reports follow: an analyst opens this from a case
    folder on a machine with no route out, and a page that fetches a font or a
    library is a page that renders wrong exactly there."""
    remote = re.findall(r'(?:src|href)\s*=\s*"(?:https?:)?//[^"]*"', page)
    assert remote == []
    assert "http://" not in page and "https://" not in page


def test_the_page_is_built_from_what_ships_not_from_the_working_directory(tmp_path,
                                                                         monkeypatch):
    """`Config.all_parser_dirs` starts with `./parsers`, so a generator built on it
    would render a different page depending on where it was run -- and the analyst's
    own parsers would end up in the repository's copy of the map."""
    (tmp_path / "parsers").mkdir()
    (tmp_path / "parsers" / "mine.yaml").write_text(
        'id: mine_only\nname: "Mine"\ndescription: "d"\nos: windows\n'
        'category: detections\nsource: "s"\nalert: detect\n'
        'handler: "artifact_engine.handlers.win_byovd:run"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert "mine_only" not in atlas.build()


def test_a_profile_with_no_manifest_is_still_on_the_page(page):
    """LiveResponse arriving on its own is a machine `core/detector.py` builds, not
    one any `data/profiles` manifest describes. A page generated only from the
    manifests would leave out an acquisition the tool accepts."""
    assert "windows_liveresponse" in page

    profiles = load_profiles([DATA_DIR / "profiles"])
    for p in profiles:
        assert f'class="tag win">{p.id}<' in page or f'class="tag lin">{p.id}<' in page
