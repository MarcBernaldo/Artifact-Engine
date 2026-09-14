"""Path resolution and global configuration loading."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from artifact_engine.core import netclass
from artifact_engine.logging_setup import get_logger

log = get_logger()


def _default_workers() -> int:
    # Use all cores (capped) so tools run highly in parallel across machines.
    return min(os.cpu_count() or 4, 32)


# A hand-edited config could set any number, and `_plan_pools` can hand back
# `max_workers` process workers AND `max_workers` thread workers in the same run
# -- so the live worker count reaches twice this. The 3.10/Windows interpreter
# fault was reproduced around 128 concurrent workers, so 64 keeps the worst case
# under it. Nothing enforced this before: the default was capped at 32 with that
# threshold in mind and a YAML value went straight through unchecked.
MAX_WORKERS_CEILING = 64


# Root of the installed package (contains the data/ folder)
PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR / "data"
DEFAULT_TOOLS_DIR = PACKAGE_DIR / "tools"


@dataclass
class Config:
    """Effective configuration for a run."""

    tools_dir: Path = DEFAULT_TOOLS_DIR
    # Directories to search for manifests (bundled + user overrides)
    profile_dirs: list[Path] = field(default_factory=lambda: [DATA_DIR / "profiles"])
    parser_dirs: list[Path] = field(default_factory=lambda: [DATA_DIR / "parsers"])
    assets_dir: Path = DATA_DIR / "assets"
    max_workers: int = field(default_factory=_default_workers)
    extract_depth: int = 3       # levels of nested wrappers (zip inside zip)
    # VSS (shadow copies). True (default) skips them; set false to ALSO parse each
    # snapshot as an extra volume -- slower: multiplies parsing by the snapshot count.
    avoid_vss: bool = True
    # Consolidate a host's live volume and its shadow copies into ONE .db/.xlsx/
    # report.txt instead of one per volume (only meaningful with avoid_vss: false).
    # A machine with ten snapshots otherwise means eleven databases to search for a
    # single logon; merged, each artifact is one table with the rows the volumes
    # share collapsed and a `volumes` column recording where each survivor came
    # from. The per-volume CSVs are left untouched either way. Set false to keep a
    # separate database per snapshot.
    merge_vss: bool = True
    # Run pure-Python handlers in a process pool (real parallelism past the GIL);
    # command parsers (external tools) always stay on threads. False = old
    # thread-only behaviour.
    parse_processes: bool = True
    # Consolidation outputs (both default on). The .xlsx pass dominates
    # consolidation time (xlsxwriter writes cell by cell), so emit_xlsx: false is
    # the biggest single speed-up when you only need to query the .db.
    emit_db: bool = True
    emit_xlsx: bool = True
    # Phase-0 integrity of loose-drop folders (weblogs*/fortigate*). Default true:
    # the dropped logs ARE the evidence in a web/firewall case, so their hashes
    # belong in the chain of custody. Set false to skip hashing the (often
    # thousands of rotated) files INSIDE a drop folder when custody of them is not
    # required -- the delivered container(s) at the case root are always hashed.
    traces_include_drops: bool = True
    # CIDR ranges the organisation owns, however routable they are. Empty by
    # default, which keeps `is_global` as the answer. Declaring a range never
    # deletes or hides a row: it RECLASSIFIES the address, because "we own that
    # range" is a claim about ownership, not about innocence. See core/netclass.py.
    internal_networks: list[str] = field(default_factory=list)
    # Seconds a delivered archive with no `.sha256` seal must have gone unchanged
    # before phases 0 and 1 touch it (core/arrival.py). 0 opens it as soon as it is
    # seen, which suits an analyst starting a run after a copy; a host started by a
    # timer wants minutes. A seal is checked either way.
    settle_seconds: int = 0
    # Announcing a finished run to something outside the case (core/notify.py).
    # Off by default and deliberately so: this is the only code in the tool whose
    # purpose is to send content off this machine, and a default that transmits is
    # a default nobody chose. `stdout` needs no secret and is the one to wire a
    # pipeline up with; `webhook` POSTs the same JSON to `notify_url`.
    notify: str = "none"
    notify_url: str = ""
    # What the run is announced UNDER. Never derived from the case directory: its
    # name routinely carries the client, the site or the incident. Left empty, the
    # run travels as a digest of the case path -- stable, and meaningless to
    # anyone who does not already have the path.
    notify_label: str = ""
    notify_timeout: int = 10
    # Every config file applied, in the order they were (later overrides earlier).
    # Empty = built-in defaults, nothing was read. A LIST rather than one path
    # because two can layer -- the tool's own file as the baseline and a per-case
    # one over it -- and naming only the winner would hide half of what produced
    # the outputs.
    sources: list[Path] = field(default_factory=list)

    @property
    def all_profile_dirs(self) -> list[Path]:
        # User overrides in the cwd take priority
        return [Path.cwd() / "profiles", *self.profile_dirs]

    @property
    def all_parser_dirs(self) -> list[Path]:
        return [Path.cwd() / "parsers", *self.parser_dirs]


_TRUE = {"true", "1", "yes", "y", "on"}
_FALSE = {"false", "0", "no", "n", "off"}


def _as_bool(value, default: bool) -> bool:
    """A YAML value as a flag, accepting how people actually write one.

    YAML already gives `true`/`false` as real booleans, but an analyst editing the
    file by hand writes `1`, `yes` or `on` just as readily -- and comparing
    `str(value).lower() == "true"` turned every one of those into a silent FALSE,
    i.e. the exact opposite of what was asked for. Anything unrecognised keeps the
    default rather than guessing.
    """
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def install_dir() -> Path | None:
    """The checkout the engine is imported from, when it is one.

    `<root>/src/artifact_engine/config.py` -> `<root>`, confirmed by the
    `pyproject.toml` beside it so an installed wheel (whose parent is just
    `site-packages`) never matches something arbitrary."""
    root = PACKAGE_DIR.parents[1]
    return root if (root / "pyproject.toml").is_file() else None


# The one environment variable this engine reads for configuration. Named rather
# than guessed at, and treated exactly like `--config`: an explicit pointer means
# "use this file", not "add it to the pile".
CONFIG_ENV = "ARTIFACT_ENGINE_CONFIG"


def user_config_dir() -> Path:
    r"""Where this MACHINE's own settings live, outside any checkout.

    MEASURED, and the reason this exists: `config.yaml` sits at the root of the
    source tree, so copying the tool to another machine carries the previous
    machine's tuning with it. A 24-core Linux host was observed running with
    `max_workers: 32` and `emit_xlsx: false` because both had travelled across in
    a folder copy -- neither chosen for it, and nothing said where they came from.

    `install_dir()` is also None for a non-editable install, so a wheel had no
    baseline location at all and settings depended on where the analyst happened
    to be standing.

    Computed rather than taken from `platformdirs`: one dependency for two
    `os.environ` lookups is not a trade worth making, and both conventions are
    stable.
    """
    if os.name == "nt":
        base = os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "artifact-engine"


def config_candidates(path: Path | None = None) -> list[Path]:
    """Config files to apply, in increasing priority.

    The tool's own folder comes FIRST so it acts as the baseline, and the current
    directory can still override it per case. Searching only the cwd -- what this
    did until now -- meant the settings depended on where you happened to be
    standing: launched from the right-click menu, or from the case folder, the
    file sitting next to the tool was never found and the run silently fell back
    to defaults. `avoid_vss` alone decides whether shadow copies are parsed, so
    that is a different acquisition, not a different preference.

    Running from the checkout makes both locations the same file; it is applied
    once.
    """
    if path:
        return [path]
    env = os.environ.get(CONFIG_ENV)
    if env:
        # Exclusive, like `--config`, and for the same reason: someone who names a
        # file means that file. Whether it EXISTS is `load_config`'s problem, and
        # it says so rather than falling back silently to a different machine's
        # settings, which is the failure this whole ordering is about.
        return [Path(env)]
    out: list[Path] = []
    root = install_dir()
    if root:
        out += [root / "config.yaml", root / "config.local.yaml"]
    # Between the two on purpose: the install is the baseline the tool ships with,
    # this is what the MACHINE was set up with, and the working directory is what
    # THIS case wants. Specific beats general, and per-case is the most specific.
    out += [user_config_dir() / "config.yaml"]
    out += [Path.cwd() / "config.yaml", Path.cwd() / "config.local.yaml"]
    seen: set[Path] = set()
    uniq: list[Path] = []
    for c in out:
        try:
            key = c.resolve()
        except OSError:
            key = c
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    return uniq


def load_config(path: Path | None = None) -> Config:
    """Load config from YAML if present; otherwise return defaults.

    Later files override earlier ones -- see `config_candidates` for the order."""
    cfg = Config()
    cands = config_candidates(path)
    # An explicit pointer that names nothing is a mistake worth a line, not a
    # silent fall back to the defaults: the analyst set it to change something.
    if len(cands) == 1 and not cands[0].is_file() and (path or os.environ.get(CONFIG_ENV)):
        log.warning(f"[!] config file not found: {cands[0]} - running with defaults")
    for cand in cands:
        if cand and cand.is_file():
            data = yaml.safe_load(cand.read_text(encoding="utf-8")) or {}
            if "tools_dir" in data:
                cfg.tools_dir = Path(data["tools_dir"])
            # Same treatment as tools_dir: the geo databases and the community
            # YARA set are hundreds of MB of regenerable content, and an analyst
            # may well want them off the system disk or shared between installs.
            if "assets_dir" in data:
                cfg.assets_dir = Path(data["assets_dir"])
            asked = int(data.get("max_workers", cfg.max_workers))
            if asked > MAX_WORKERS_CEILING:
                log.warning(f"[!] max_workers {asked} in {cand.name} exceeds the "
                            f"{MAX_WORKERS_CEILING} ceiling; using {MAX_WORKERS_CEILING}. "
                            f"Past it the worker count approaches the level where the "
                            f"interpreter fault was reproduced.")
                asked = MAX_WORKERS_CEILING
            cfg.max_workers = max(1, asked)
            cfg.extract_depth = int(data.get("extract_depth", cfg.extract_depth))
            cfg.settle_seconds = max(0, int(data.get("settle_seconds", cfg.settle_seconds)))
            cfg.notify_timeout = int(data.get("notify_timeout", cfg.notify_timeout))
            for key in ("notify", "notify_url", "notify_label"):
                if key in data:
                    setattr(cfg, key, str(data[key] or ""))
            for key in ("avoid_vss", "merge_vss", "parse_processes",
                        "emit_db", "emit_xlsx", "traces_include_drops"):
                current = getattr(cfg, key)
                setattr(cfg, key, _as_bool(data.get(key, current), current))
            if "internal_networks" in data:
                # Parsed here rather than at each call site so a typo is reported
                # once, at load, instead of quietly matching nothing all run.
                parsed = netclass.parse(data["internal_networks"])
                cfg.internal_networks = [str(n) for n in parsed.networks]
            cfg.sources.append(cand)
    return cfg
