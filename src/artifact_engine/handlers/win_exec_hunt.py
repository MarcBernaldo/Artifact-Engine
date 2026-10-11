"""Handler: one search of every execution artifact, for every catalog (v0.7.103).
Output: rmm.csv, lolbas.csv, byovd.csv, suspicious_tools.csv

Three detectors used to read Amcache, each on its own. This reads every artifact
that records a program -- Amcache, Prefetch, ShimCache, BAM, UserAssist, PCA,
SRUM, services, scheduled tasks, shortcuts and jump lists, the live response's
processes (`_execution`) -- once, and asks each catalog about every record:

  rmm     remote-access and tunnelling tools: the curated list, LOLRMM's catalog
          and LOTTunnels' list (`win_rmm`), by exact file name or install folder;
  lolbas  a LOLBAS binary outside its home, in a user-writable staging folder
          (`win_lolbas`);
  byovd   a driver or program whose SHA1 LOLDrivers lists (`win_byovd`) -- Amcache
          is the only source that records a hash;
  suspicious_tools  a program whose file name the analyst's `suspicious_tools.txt`
          names (mimikatz, rubeus, sharphound, rclone...), by its category.

One row per finding and file, however many artifacts saw it: `sources` names
them (`amcache, bam, prefetch`), `first_seen_utc` / `last_seen_utc` span the
UTC clocks among them, `runs` is the highest run count any of them kept, and
`users` the accounts that ran it. A source that keeps only a name (Prefetch
without its path) joins the one row that has that name, if there is just one.

Adding a catalog means adding a hunter here, not another pass over the
artifacts. Self-gates when no catalog is installed or the machine has none of
the artifacts.
"""

from __future__ import annotations

from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers import _execution as X
from artifact_engine.handlers._alertgroups import machine_root
from artifact_engine.handlers._indicators import load_indicators
from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.win_byovd import _load_hashes, _norm_sha1
from artifact_engine.handlers.win_liveresponse_velociraptor import _in_staging
from artifact_engine.handlers.win_lolbas import _load_lolbas
from artifact_engine.handlers.win_rmm import _load_rmm, _match

_SPAN = ("sources", "first_seen_utc", "last_seen_utc", "runs", "users")


class _Seen:
    """What every artifact said about one file, merged."""

    def __init__(self, fixed: list) -> None:
        self.fixed = fixed
        self.path = ""
        self.sources: set[str] = set()
        self.times: list[str] = []
        self.runs = 0
        self.users: set[str] = set()
        self.sha1 = ""

    def add(self, s: X.Sighting) -> None:
        self.sources.add(s.source)
        if s.time_utc:
            self.times.append(s.time_utc)
        self.runs = max(self.runs, s.runs)
        if s.user:
            self.users.add(s.user)
        if s.path and not self.path:      # the first reader with one: Amcache's spelling
            self.path = s.path
        if s.sha1 and not self.sha1:
            self.sha1 = s.sha1

    def merge(self, other: _Seen) -> None:
        self.sources |= other.sources
        self.times += other.times
        self.runs = max(self.runs, other.runs)
        self.users |= other.users

    def span(self) -> list:
        return [", ".join(sorted(self.sources)), min(self.times, default=""),
                max(self.times, default=""), self.runs or "", ", ".join(sorted(self.users))]


class _Hunter:
    table = ""
    header: tuple[str, ...] = ()

    @property
    def active(self) -> bool:
        """False when this hunter's catalog is not installed."""
        raise NotImplementedError

    def __init__(self) -> None:
        self.found: dict[tuple, _Seen] = {}

    def see(self, s: X.Sighting) -> None:
        hit = self.hit(s)
        if hit is None:
            return
        key, fixed = hit
        cur = self.found.get(key)
        if cur is None:
            cur = self.found[key] = _Seen(fixed)
        cur.add(s)

    def hit(self, s: X.Sighting):
        raise NotImplementedError

    def fold_names(self) -> None:
        """A name-only record joins the single row with a path for that name."""
        named = [k for k in self.found if k[-1].startswith("name:")]
        for k in named:
            name = k[-1][5:]
            peers = [p for p in self.found if p[:-1] == k[:-1] and not p[-1].startswith("name:")
                     and X.basename(p[-1]) == name]
            if len(peers) == 1:
                self.found[peers[0]].merge(self.found.pop(k))

    def rows(self) -> list[list]:
        raise NotImplementedError


class _Rmm(_Hunter):
    table = "rmm.csv"
    header = ("tool", "match", "path", *_SPAN, "sha1")

    def __init__(self, assets: Path) -> None:
        super().__init__()
        self.tools = _load_rmm(assets)
        self.memo: dict[tuple, tuple | None] = {}

    @property
    def active(self) -> bool:
        return bool(self.tools)

    def hit(self, s):
        k = (s.name, s.path)
        if k not in self.memo:                   # SRUM repeats one program thousands of times
            self.memo[k] = _match(s.name, s.path, self.tools)
        m = self.memo[k]
        if not m:
            return None
        where = X.norm_path(s.path) or "name:" + s.name
        return (m[0], where), [m[0], m[1]]

    def rows(self):
        self.fold_names()
        rows = [[*v.fixed, v.path, *v.span(), v.sha1] for v in self.found.values()]
        return sorted(rows, key=lambda r: (r[0].lower(), r[2].lower()))


class _Lolbas(_Hunter):
    table = "lolbas.csv"
    header = ("binary", "path", *_SPAN, "sha1")

    def __init__(self, assets: Path) -> None:
        super().__init__()
        self.names = _load_lolbas(assets)

    @property
    def active(self) -> bool:
        return bool(self.names)

    def hit(self, s):
        if s.name not in self.names or not s.path or not _in_staging(s.path):
            return None
        return (X.norm_path(s.path),), [s.name]

    def rows(self):
        rows = [[*v.fixed, v.path, *v.span(), v.sha1] for v in self.found.values()]
        return sorted(rows, key=lambda r: (r[0], r[1].lower()))


class _Byovd(_Hunter):
    table = "byovd.csv"
    header = ("category", "known_driver", "amcache_name", "path", "sha1", "first_seen_utc")

    def __init__(self, assets: Path) -> None:
        super().__init__()
        self.hashes = _load_hashes(assets)

    @property
    def active(self) -> bool:
        return bool(self.hashes)

    def hit(self, s):
        h = _norm_sha1(s.sha1)
        info = self.hashes.get(h) if h else None
        if not info:
            return None
        return (h,), [info.get("c", ""), info.get("n", ""), s.name, s.path, h]

    def rows(self):
        rows = [[*v.fixed, min(v.times, default="")] for v in self.found.values()]
        # malicious first, then by known driver name
        return sorted(rows, key=lambda r: (r[0] != "malicious", r[0], r[1]))


class _Named(_Hunter):
    """`suspicious_tools.txt` -- the analyst-editable list the shell histories are
    checked against -- asked about each program's FILE NAME only: a folder named
    after a tool is not the tool, and the list's command-line patterns
    (`procdump ... lsass`) simply never match a name.

    The categories that describe an ACTION rather than a tool are left to the
    command lines: `lsass_dump` names `createdump`, which every .NET install
    ships -- measured on a real case, 211 rows of the runtime's own crash dumper.
    """

    table = "suspicious_tools.csv"
    _ACTIONS = frozenset({"lsass_dump", "shadow_delete", "amsi_bypass", "firewall_disable",
                          "log_clearing", "history_evasion", "payload_pipe_shell"})
    header = ("category", "binary", "path", *_SPAN, "sha1")

    def __init__(self, assets: Path) -> None:
        super().__init__()
        self.rules = [(label, rx) for label, rx in load_indicators(assets / "suspicious_tools.txt")
                      if label not in self._ACTIONS]
        self.memo: dict[str, str] = {}

    @property
    def active(self) -> bool:
        return bool(self.rules)

    def hit(self, s):
        if s.name not in self.memo:
            self.memo[s.name] = next((label for label, rx in self.rules if rx.search(s.name)), "")
        label = self.memo[s.name]
        if not label:
            return None
        return (label, X.norm_path(s.path) or "name:" + s.name), [label, s.name]

    def rows(self):
        self.fold_names()
        rows = [[*v.fixed, v.path, *v.span(), v.sha1] for v in self.found.values()]
        return sorted(rows, key=lambda r: (r[0], r[1], r[2].lower()))


def run(ctx) -> None:
    assets = Path(ctx.assets)
    hunters = [h for h in (_Rmm(assets), _Lolbas(assets), _Byovd(assets), _Named(assets))
               if h.active]
    if not hunters:
        raise HandlerSkip("no catalog (rmm_*.yaml / lolbas.yaml / loldrivers_hashes.json / "
                          "suspicious_tools.txt)")
    csvs = machine_root(Path(ctx.out)) / "CSVs"
    n = 0
    for s in X.sightings(ctx, csvs):
        n += 1
        for h in hunters:
            h.see(s)
    if not n:
        raise HandlerSkip("no execution artifact parsed on this volume")
    for h in hunters:
        write_csv(ctx.out, h.table, list(h.header), h.rows())
