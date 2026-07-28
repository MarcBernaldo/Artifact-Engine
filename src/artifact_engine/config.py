"""Path resolution and global configuration loading."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


def _default_workers() -> int:
    # Use all cores (capped) so tools run highly in parallel across machines.
    return min(os.cpu_count() or 4, 32)


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
    # Where these values came from. None = built-in defaults, nothing was read.
    # Recorded because the file is looked up in the CURRENT DIRECTORY: the same
    # command launched from the case folder instead of the tool's picks up
    # different settings, and `avoid_vss` alone decides whether shadow copies are
    # parsed at all. That has to be visible in the log, not inferred afterwards.
    source: Path | None = None

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


def load_config(path: Path | None = None) -> Config:
    """Load config from YAML if present; otherwise return defaults."""
    cfg = Config()
    candidates = [path] if path else [Path.cwd() / "config.yaml", Path.cwd() / "config.local.yaml"]
    for cand in candidates:
        if cand and cand.is_file():
            data = yaml.safe_load(cand.read_text(encoding="utf-8")) or {}
            if "tools_dir" in data:
                cfg.tools_dir = Path(data["tools_dir"])
            cfg.max_workers = int(data.get("max_workers", cfg.max_workers))
            cfg.extract_depth = int(data.get("extract_depth", cfg.extract_depth))
            for key in ("avoid_vss", "merge_vss", "parse_processes",
                        "emit_db", "emit_xlsx", "traces_include_drops"):
                current = getattr(cfg, key)
                setattr(cfg, key, _as_bool(data.get(key, current), current))
            cfg.source = cand
    return cfg
