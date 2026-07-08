"""Loading and validation of the parser and profile YAML manifests."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from artifact_engine.logging_setup import get_logger
from artifact_engine.models import ParserManifest, ProfileManifest

log = get_logger()


def _load_yaml_dir(dirs: list[Path]) -> list[tuple[Path, dict]]:
    docs: list[tuple[Path, dict]] = []
    seen: set[str] = set()
    for d in dirs:
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*.y*ml")):
            # Override: if a file with the same name was already loaded, skip it
            if f.name in seen:
                continue
            seen.add(f.name)
            try:
                data = yaml.safe_load(f.read_text(encoding="utf-8"))
            except yaml.YAMLError as e:
                log.error(f"[!] invalid YAML in {f}: {e}")
                continue
            if isinstance(data, dict):
                docs.append((f, data))
    return docs


def load_parsers(dirs: list[Path]) -> list[ParserManifest]:
    parsers: list[ParserManifest] = []
    ids: set[str] = set()
    for path, data in _load_yaml_dir(dirs):
        try:
            m = ParserManifest(**data)
        except ValidationError as e:
            log.error(f"[!] invalid parser in {path}:\n{e}")
            continue
        if m.id in ids:
            log.error(f"[!] duplicate parser id '{m.id}' in {path}")
            continue
        ids.add(m.id)
        parsers.append(m)
    _check_dependencies(parsers)
    return parsers


def load_profiles(dirs: list[Path]) -> list[ProfileManifest]:
    profiles: list[ProfileManifest] = []
    ids: set[str] = set()
    for path, data in _load_yaml_dir(dirs):
        try:
            m = ProfileManifest(**data)
        except ValidationError as e:
            log.error(f"[!] invalid profile in {path}:\n{e}")
            continue
        if m.id in ids:
            log.error(f"[!] duplicate profile id '{m.id}' in {path}")
            continue
        ids.add(m.id)
        profiles.append(m)
    return profiles


def _check_dependencies(parsers: list[ParserManifest]) -> None:
    by_id = {p.id for p in parsers}
    for p in parsers:
        for dep in p.depends_on:
            if dep != "all" and dep not in by_id:
                log.warning(f"[!] parser '{p.id}' depends on '{dep}' which does not exist")
