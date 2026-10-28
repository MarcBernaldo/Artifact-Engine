"""Handler: hosts a remote-access or tunnelling tool talks to, where Windows saw them.
Output: alert_remote_access_domains.csv

`win_rmm` finds these tools by the files Amcache recorded. This finds them by
the network side: every host name in the browser's history and downloads and,
on the live volume, in a Velociraptor LiveResponse's DNS cache, matched against
the domains LOLRMM and LOTTunnels list (`_domains`). A browser that visited
`*.trycloudflare.com` or a resolver that cached `relay-*.net.anydesk.com` puts
the tool on the machine even when its binary is gone.

One row per tool, host, source and user: how many history entries or cache
records name it, the latest time and one example. Context: legitimate support
tools match too, and the analyst confirms whether each was authorised.
"""

from __future__ import annotations

import csv
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _domains
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers._tables import find_table, machine_root
from artifact_engine.handlers.win_liveresponse_velociraptor import (
    _artifact_key,
    _find_results,
    _read_jsonl,
)

TABLE = "alert_remote_access_domains.csv"
HEADER = ["tool", "catalog", "match", "host", "source", "who", "hits", "last_utc",
          "example"]
_EXAMPLE_CHARS = 300


def _rows(path: Path | None):
    if path is None:
        return
    try:
        with open(path, encoding="utf-8", errors="replace", newline="") as fh:
            yield from csv.DictReader(fh)
    except (OSError, csv.Error):
        return


def _sightings(ctx):
    """(source, who, host, time_utc, example) for every host name the machine kept."""
    csvs = machine_root(Path(ctx.out)) / "CSVs"
    for r in _rows(find_table(csvs, "art_browser_history")):
        url = r.get("url") or ""
        yield "art_browser_history", r.get("user") or "", _domains.host_of(url), \
            r.get("last_visit_utc") or "", url
    for r in _rows(find_table(csvs, "art_browser_downloads")):
        url = r.get("source_url") or ""
        yield "art_browser_downloads", r.get("user") or "", _domains.host_of(url), \
            r.get("start_time_utc") or "", url
    if str(ctx.volume).upper().startswith("VSS"):
        return                                   # LiveResponse is the live host's
    results = _find_results(ctx)
    if results is None:
        return
    for f in results.glob("*.json"):
        if _artifact_key(f) == "Windows.System.DNSCache":
            for rec in _read_jsonl(f):
                name = str(rec.get("Name") or "")
                yield "dns_cache", "", name, "", f"{name} {rec.get('Record') or ''}".strip()


def run(ctx) -> None:
    matcher = _domains.load(Path(ctx.assets))
    if not len(matcher):
        raise HandlerSkip("no remote-access domain list (rmm_lolrmm.yaml / lottunnels)")
    found: dict[tuple, list] = {}
    for source, who, host, when, example in _sightings(ctx):
        hit = matcher.match(host)
        if not hit:
            continue
        tool, catalog, pattern = hit
        host = host.lower().rstrip(".")
        key = (tool, host, source, who)
        row = found.get(key)
        if row is None:
            found[key] = [tool, catalog, pattern, host, source, who, 1, when,
                          example[:_EXAMPLE_CHARS]]
            continue
        row[6] += 1
        if when > row[7]:
            row[7], row[8] = when, example[:_EXAMPLE_CHARS]
    rows = sorted(found.values(), key=lambda r: (r[0].lower(), r[3], r[4], r[5]))
    write_csv(ctx.out, TABLE, HEADER, rows)
