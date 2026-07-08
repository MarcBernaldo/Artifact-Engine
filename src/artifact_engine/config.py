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
    # IRIS integration (optional)
    use_iris: bool = False
    iris_url: str = ""
    iris_token: str = ""

    @property
    def all_profile_dirs(self) -> list[Path]:
        # User overrides in the cwd take priority
        return [Path.cwd() / "profiles", *self.profile_dirs]

    @property
    def all_parser_dirs(self) -> list[Path]:
        return [Path.cwd() / "parsers", *self.parser_dirs]


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
            cfg.avoid_vss = str(data.get("avoid_vss", cfg.avoid_vss)).lower() == "true"
            cfg.parse_processes = str(data.get("parse_processes", cfg.parse_processes)).lower() == "true"
            cfg.emit_db = str(data.get("emit_db", cfg.emit_db)).lower() == "true"
            cfg.emit_xlsx = str(data.get("emit_xlsx", cfg.emit_xlsx)).lower() == "true"
            cfg.traces_include_drops = str(
                data.get("traces_include_drops", cfg.traces_include_drops)).lower() == "true"
            cfg.use_iris = str(data.get("use_iris", cfg.use_iris)).lower() == "true"
            cfg.iris_url = data.get("iris_url", cfg.iris_url)
            cfg.iris_token = data.get("iris_token", cfg.iris_token)
    return cfg
