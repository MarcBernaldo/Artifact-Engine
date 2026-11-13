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
#
# On Windows the ceiling is 61 (AE-109): `ProcessPoolExecutor` refuses more there,
# so a `max_workers` of 62-64 -- what `aeng setup` writes on a 64-core host -- ended
# phase 3 with a ValueError.
MAX_WORKERS_CEILING = 61 if os.name == "nt" else 64


class ConfigError(ValueError):
    """A configuration that cannot be used as written (AE-109): said, and the
    command stops, instead of a default kept in silence or a raw traceback."""


# Root of the installed package (contains the data/ folder)
PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR / "data"
DEFAULT_TOOLS_DIR = PACKAGE_DIR / "tools"


SIGMA_RULES_REPO = "https://github.com/MarcBernaldo/artifact-engine-sigma.git"
SIGMA_DISK_REPO = "https://github.com/MarcBernaldo/sigma.git"
SIGMA_DISK_BRANCH = "aeng"


@dataclass
class Config:
    """Effective configuration for a run."""

    tools_dir: Path = DEFAULT_TOOLS_DIR
    # Directories to search for manifests (bundled + user overrides)
    profile_dirs: list[Path] = field(default_factory=lambda: [DATA_DIR / "profiles"])
    parser_dirs: list[Path] = field(default_factory=lambda: [DATA_DIR / "parsers"])
    assets_dir: Path = DATA_DIR / "assets"
    # Extra Sigma rules: a git URL or a local path. `aeng update` mirrors its rules/
    # folder into assets/sigma_custom (and hayabusa's rules). Defaults to the public
    # artifact-engine-sigma repository; an empty string turns it off.
    sigma_rules_repo: str = SIGMA_RULES_REPO
    # SigmaHQ's rules ADAPTED to the engine's own tables: a fork of SigmaHQ (git URL
    # or local path) and its branch. `aeng update` mirrors its rules/windows into
    # assets/sigma_disk (alert_win_sigma) and its rules/web into assets/sigma_disk_web
    # (alert_web, v0.7.198); an empty repo turns it off and both parsers read
    # SigmaHQ's rules as they are (bundled sets and hayabusa's copy).
    sigma_disk_repo: str = SIGMA_DISK_REPO
    sigma_disk_branch: str = SIGMA_DISK_BRANCH
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
    # Consolidation outputs. The .xlsx pass dominates consolidation time
    # (xlsxwriter writes cell by cell) and the analyst works in the .db, so the
    # .xlsx is off unless asked for (v0.7.200, AE-049): emit_xlsx: true.
    emit_db: bool = True
    emit_xlsx: bool = False
    # Index the time and pivot columns of the .db's big tables (core/dbnav.py).
    # Measured on four real hosts: about a second and 27 MB per million rows and
    # index; their .db grew 20 to 29% and took 10 to 77 s longer to build. False
    # keeps the .db at its tables and views.
    db_indexes: bool = True
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
    # Every config file applied, in the order they were (later overrides earlier).
    # Empty = built-in defaults, nothing was read. A LIST rather than one path
    # because two can layer -- the tool's own file as the baseline and a per-case
    # one over it -- and naming only the winner would hide half of what produced
    # the outputs.
    sources: list[Path] = field(default_factory=list)
    # Whether the working directory's `parsers/`, `profiles/` and `config.yaml`
    # are read. Not when it is the case root or inside it (AE-109): a manifest's
    # `command` is run as written, and a case folder is evidence somebody else
    # delivered, not configuration.
    trust_cwd: bool = True
    # What loading had to say, logged once logging is set up (`_log_config`): the
    # config is read before it, so these never reached aeng-run.log.
    notes: list[str] = field(default_factory=list)

    @property
    def all_profile_dirs(self) -> list[Path]:
        # User overrides in the cwd take priority
        return ([Path.cwd() / "profiles"] if self.trust_cwd else []) + self.profile_dirs

    @property
    def all_parser_dirs(self) -> list[Path]:
        return ([Path.cwd() / "parsers"] if self.trust_cwd else []) + self.parser_dirs


_TRUE = {"true", "1", "yes", "y", "on"}
_FALSE = {"false", "0", "no", "n", "off"}


def install_dir() -> Path | None:
    """The checkout the engine is imported from, when it is one.

    `<root>/src/artifact_engine/config.py` -> `<root>`, confirmed by the
    `pyproject.toml` beside it so an installed wheel (whose parent is just
    `site-packages`) never matches something arbitrary."""
    root = PACKAGE_DIR.parents[1]
    return root if (root / "pyproject.toml").is_file() else None


def config_candidates(path: Path | None = None, trust_cwd: bool = True) -> list[Path]:
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
    out: list[Path] = []
    root = install_dir()
    if root:
        out += [root / "config.yaml", root / "config.local.yaml"]
    if trust_cwd:
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


_KEYS = {"tools_dir", "assets_dir", "sigma_rules_repo", "sigma_disk_repo",
         "sigma_disk_branch", "max_workers", "extract_depth", "settle_seconds",
         "avoid_vss", "merge_vss", "parse_processes", "emit_db", "emit_xlsx",
         "db_indexes", "traces_include_drops", "internal_networks"}


def _number(data: dict, key: str, current: int, where: str, least: int) -> int:
    if key not in data:
        return current
    v = data[key]
    try:
        if isinstance(v, bool) or v is None or not str(v).strip():
            raise ValueError
        if isinstance(v, float) and not v.is_integer():
            # Cut short before (found by review): `settle_seconds: 0.5` became 0,
            # which opens an unsealed archive at once and never checks its seal.
            raise ValueError
        n = int(v)
    except (TypeError, ValueError):
        raise ConfigError(f"{where}: {key} must be a whole number, not {v!r}") from None
    if n < least:
        raise ConfigError(f"{where}: {key} must be {least} or more, not {n}")
    return n


def _flag(data: dict, key: str, current: bool, where: str) -> bool:
    if key not in data:
        return current
    v = data[key]
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    # Kept as the default in silence before (AE-109): `avoid_vss: ture` parsed no
    # snapshot and said nothing.
    raise ConfigError(f"{where}: {key} must be true or false, not {v!r}")


def _inside(cwd: Path, case_root: Path) -> bool:
    try:
        cwd, case_root = cwd.resolve(), case_root.resolve()
    except OSError:
        return False
    return cwd == case_root or case_root in cwd.parents


def load_config(path: Path | None = None, case_root: Path | None = None) -> Config:
    """Load config from YAML if present; otherwise return defaults.

    Later files override earlier ones -- see `config_candidates` for the order.
    A value that cannot be used raises `ConfigError`; an unknown key is a note.
    With `case_root`, a working directory that is the case or inside it is not
    read at all (`Config.trust_cwd`)."""
    cfg = Config()
    if path is not None and not Path(path).is_file():
        raise ConfigError(f"config file {path} does not exist")
    if case_root is not None and _inside(Path.cwd(), Path(case_root)):
        cfg.trust_cwd = False
        cfg.notes.append(f"the working directory {Path.cwd()} is inside the case: its "
                         f"config.yaml, parsers/ and profiles/ are NOT read")
    for cand in config_candidates(path, trust_cwd=cfg.trust_cwd):
        if cand and cand.is_file():
            try:
                data = yaml.safe_load(cand.read_text(encoding="utf-8")) or {}
            except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
                raise ConfigError(f"{cand}: cannot be read as YAML: {e}") from None
            if not isinstance(data, dict):
                raise ConfigError(f"{cand}: not a mapping of settings")
            for key in sorted(set(data) - _KEYS):
                cfg.notes.append(f"{cand.name}: unknown setting {key!r} ignored (a typo?)")
            if "tools_dir" in data:
                cfg.tools_dir = Path(data["tools_dir"])
            # Same treatment as tools_dir: the geo databases and the community
            # YARA set are hundreds of MB of regenerable content, and an analyst
            # may well want them off the system disk or shared between installs.
            if "assets_dir" in data:
                cfg.assets_dir = Path(data["assets_dir"])
            if "sigma_rules_repo" in data:
                cfg.sigma_rules_repo = str(data["sigma_rules_repo"] or "").strip()
            if "sigma_disk_repo" in data:
                cfg.sigma_disk_repo = str(data["sigma_disk_repo"] or "").strip()
            if "sigma_disk_branch" in data:
                cfg.sigma_disk_branch = (str(data["sigma_disk_branch"] or "").strip()
                                         or SIGMA_DISK_BRANCH)
            asked = _number(data, "max_workers", cfg.max_workers, cand.name, 1)
            if asked > MAX_WORKERS_CEILING:
                cfg.notes.append(f"max_workers {asked} in {cand.name} exceeds the "
                                 f"{MAX_WORKERS_CEILING} ceiling; using "
                                 f"{MAX_WORKERS_CEILING}")
                asked = MAX_WORKERS_CEILING
            cfg.max_workers = asked
            # 0 extracted nothing at all, archive after archive, without a word.
            cfg.extract_depth = _number(data, "extract_depth", cfg.extract_depth, cand.name, 1)
            cfg.settle_seconds = _number(data, "settle_seconds", cfg.settle_seconds,
                                         cand.name, 0)
            for key in ("avoid_vss", "merge_vss", "parse_processes",
                        "emit_db", "emit_xlsx", "db_indexes", "traces_include_drops"):
                setattr(cfg, key, _flag(data, key, getattr(cfg, key), cand.name))
            if "internal_networks" in data:
                # Parsed here rather than at each call site so a typo is reported
                # once, at load, instead of quietly matching nothing all run.
                parsed = netclass.parse(data["internal_networks"])
                cfg.internal_networks = [str(n) for n in parsed.networks]
            cfg.sources.append(cand)
    return cfg
