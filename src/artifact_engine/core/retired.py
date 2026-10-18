"""Remove what a parser removed from the engine left in a case parsed before.

A parser that is renamed has a successor, which names it under `replaces:` and
retires its tables on its own run (`outputs.retire`, v0.7.156). A parser removed
with nothing in its place has no run left to do that: its tables would stay in
the category folder and be consolidated into every rebuilt `.db` as if something
still produced them. `data/retired_parsers.yaml` lists those parsers with their
OS, category and the names they wrote (globs allowed: Chainsaw named its CSVs
after the rule that fired), and `sweep` retires them in every machine before the
parse, through the same `outputs.retire`: the declared names whatever their age,
then the `.outputs` record and `.done` marker, plus the `.assets` record. An entry
can also name a table a live parser stopped writing (`web_404_paths`), so a case
whose record predates v0.7.106 -- which `outputs.settle` cannot clean -- loses it
too.

Never a live parser's: an entry whose id a loaded parser still has (a copy kept
in a user parser dir) is skipped, and so is any name a loaded parser of the same
OS and category writes -- its declared outputs, `<id>.csv`, or `<short>_*` for a
tool that names its own files. A file it cannot remove (open in Excel) keeps the
record and is returned, and the scheduler turns it into an `error` run of that
id on that machine, so the run's verdict says the table was consolidated
anyway. Kept out of `runner` and `outputs`: every handler imports those, so an
edit there re-parses everything.
"""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

import yaml

from artifact_engine.config import DATA_DIR
from artifact_engine.core import asset_state, outputs, runner
from artifact_engine.logging_setup import get_logger

log = get_logger()

RETIRED = DATA_DIR / "retired_parsers.yaml"


def load(path: Path = RETIRED) -> dict[str, dict]:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        log.warning(f"[!] retired parsers list unreadable ({path}): {e}")
        return {}
    return {str(k): v for k, v in data.items() if isinstance(v, dict)}


def _live_patterns(parsers, os_: str, category: str) -> list[str]:
    """Names (fnmatch patterns, casefolded) a loaded parser writes in that folder."""
    pats: list[str] = []
    for p in parsers or ():
        if p.os != os_ or p.category != category:
            continue
        pats.append(f"{p.id}.csv".casefold())
        if p.short:
            pats.append(f"{p.short}_*".casefold())
        for o in p.outputs or ():
            pats.append(Path(str(o.path)).name.casefold())
    return pats


def _names(out_dir: Path, patterns: list[str]) -> list[str]:
    names: set[str] = set()
    for pat in patterns:
        if any(c in pat for c in "*?["):
            names.update(p.name for p in out_dir.glob(pat))
        else:
            names.add(pat)
    return sorted(names)


def sweep(machines, out_dir_of, retired: dict[str, dict] | None = None,
          parsers=()) -> list[tuple[int, str, str]]:
    """Retire every listed entry in every machine of its OS. `out_dir_of(machine,
    category)` is the scheduler's folder rule; `parsers` the loaded ones, which
    are never touched. Returns (machine index, entry id, name) per file left."""
    retired = load() if retired is None else retired
    live_ids = {p.id for p in parsers or ()}
    left: list[tuple[int, str, str]] = []
    for i, m in enumerate(machines):
        for pid, spec in retired.items():
            if pid in live_ids:
                continue
            os_, category = spec.get("os", ""), spec.get("category", "")
            if os_ and os_ != m.os:
                continue
            out = Path(out_dir_of(m, category))
            if not out.is_dir():
                continue
            live = _live_patterns(parsers, os_ or m.os, category)
            # a live parser's file is never deleted, whether the entry declares it
            # or only the removed parser's own record lists it
            kept = [f.name for f in out.iterdir()
                    if any(fnmatch(f.name.casefold(), pat) for pat in live)]
            names = _names(out, list(spec.get("outputs") or []))
            traces = [runner.marker_path(out, pid), outputs.record_path(out, pid),
                      asset_state.record_path(out, pid)]
            if not any((out / n).exists() for n in names) and not any(
                    t.exists() for t in traces):
                continue
            failed = outputs.retire(out, pid, names, fresh=kept)
            if failed:
                left += [(i, pid, n) for n in failed]
                continue
            asset_state.record(out, pid, None)
            log.info(f"[*] {m.name}: removed what the retired parser {pid} left "
                     f"({len(set(names) - set(kept))} file(s))")
    if left:
        log.warning(f"[!] {len(left)} output(s) of removed parsers could not be deleted "
                    f"and will be consolidated this run (open in another program?): "
                    f"{'; '.join(f'{machines[i].name}: {n}' for i, _, n in left[:5])}")
    return left
