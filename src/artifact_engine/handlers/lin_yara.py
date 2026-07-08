"""Handler: YARA scan of high-risk directories. Output: yara.csv

Compiles every rule under <assets>/yara/ -- the small bundled set plus, when
`aeng setup` has fetched it, Florian Roth's signature-base (assets/yara/
signature-base/) and any rules you drop there yourself -- and scans the
directories an attacker actually stages in: /tmp, /var/tmp, /dev/shm, the web
roots, user homes, /root and /usr/local/{bin,sbin}. Each rule file is compiled
on its own first so one bad file (missing module/external) can't sink the set;
LOKI/THOR external variables are supplied so signature-base rules load.

FP discipline (the big trap on UAC data): the collector unpacks itself and the
THOR scanner under /tmp/<tag>/, and THOR ships thousands of malware signatures
and rule files -- scanning them would self-match massively. So the walk prunes
the collector/THOR/rule-repo trees, btrfs/zfs snapshots, EDR vendor dirs, and
anything over a size cap (implants/shells are tiny). category: detections.

Self-gates (HandlerSkip) when yara-python or the rules are unavailable, or no
target directory has content.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from artifact_engine.core.runner import HandlerSkip
from artifact_engine.handlers._lincommon import root, write_csv

_SNAPSHOT = re.compile(r"/\.snapshots/\d+/snapshot/|/\.zfs/snapshot/")
_MAX_BYTES = 30_000_000          # implants/webshells are small; skip big blobs

# Directories to scan, relative to [root]. Webroots reuse the webshells set.
_SCAN_DIRS = ("tmp", "var/tmp", "dev/shm", "var/www", "srv/www", "srv/http",
              "usr/share/nginx", "root", "usr/local/bin", "usr/local/sbin")
_HOME = "home"                   # plus each user's home (one level down)

# Directory names whose subtree is never an attacker's loose drop, so scanning
# them only yields FPs: the collector + THOR + rule repos (self-match), EDR
# vendor trees, vendored dependency trees (legit code that trips generic rules),
# and config-management agents (Salt ships modules full of curl|bash, sockets).
_PRUNE_EXACT = {
    "signature-base", "yara-rules", "yara", "sigma", ".snapshots", ".zfs",
    "__pycache__", "site-packages", "dist-packages", "node_modules", "vendor",
    "bower_components", "venv-salt-minion",
}
_PRUNE_SUBSTR = ("thor", "sophos", "crowdstrike", "falcon", "defender", "mdatp",
                 "salt-minion")

# Files that are never the target (compiled artefacts, shell history already
# parsed elsewhere, the collector's own log).
_SKIP_EXT = {".pyc", ".pyo", ".map"}
_SKIP_NAMES = {
    "uac.log", ".bash_history", ".zsh_history", ".sh_history", ".history",
    ".mysql_history", ".psql_history", ".python_history", ".lesshst",
    ".node_repl_history", ".rediscli_history",
}


def _prune(name: str) -> bool:
    low = name.lower()
    if name.startswith("uac-") or low in _PRUNE_EXACT:
        return True
    if name.startswith(".root_") and name.endswith("_salt"):   # Salt minion temp tree
        return True
    return any(s in low for s in _PRUNE_SUBSTR)


# External variables LOKI/THOR-style rules (signature-base) reference. Defined
# (empty) at compile time so those rules don't fail with "undefined identifier";
# the path-based ones are supplied per file at scan time.
_EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "",
              "owner": "", "md5": "", "type": "", "imphash": ""}


def _externals_for(name: str, rel: str, ext: str) -> dict:
    e = dict(_EXTERNALS)
    e.update(filename=name, filepath=rel, extension=ext)
    return e


def _compile_rules(assets: Path, log):
    try:
        import yara  # noqa: PLC0415 - optional, only needed for this parser
    except ImportError as e:
        raise HandlerSkip("yara-python not installed") from e
    rule_dir = assets / "yara"
    if not rule_dir.is_dir():
        raise HandlerSkip("no yara rules in assets/yara")

    # Recurse so downloaded sets (assets/yara/signature-base/) load too. Compile
    # each file alone first and keep only those that succeed (a single bad file
    # -- bad module, missing external -- otherwise kills the whole combined set).
    paths = sorted(p for p in rule_dir.rglob("*") if p.suffix.lower() in (".yar", ".yara"))
    ok: dict[str, str] = {}
    skipped = 0
    used: set[str] = set()
    for p in paths:
        try:
            yara.compile(filepath=str(p), externals=_EXTERNALS)
        except yara.Error:
            skipped += 1
            continue
        ns = p.stem
        while ns in used:                 # namespace per file -> dup rule names ok
            ns += "_"
        used.add(ns)
        ok[ns] = str(p)
    if not ok:
        raise HandlerSkip("no compilable yara rules")
    if log:
        log.debug(f"yara: {len(ok)} rule file(s) loaded, {skipped} skipped")
    try:
        return yara.compile(filepaths=ok, externals=_EXTERNALS)
    except yara.Error as e:
        raise HandlerSkip(f"yara rules failed to compile: {e}") from e


def _scan_roots(base: Path):
    """Existing target directories under [root] (homes expanded one level)."""
    for d in _SCAN_DIRS:
        p = base / d
        if p.is_dir():
            yield p
    home = base / _HOME
    if home.is_dir():
        for user in home.iterdir():
            if user.is_dir():
                yield user


_STAGING = ("tmp", "var/tmp", "dev/shm")


def _collector_tag_dirs(base: Path) -> set[str]:
    """Absolute paths of the collector's `<tag>` dirs under /tmp etc. (the dir
    that holds the uac-*/thor* unpack AND THOR's own *_thor_*.html/.txt reports,
    which quote malware signatures and would self-match). Prune the whole dir."""
    tags: set[str] = set()
    for s in _STAGING:
        sd = base / s
        if not sd.is_dir():
            continue
        for child in sd.iterdir():
            try:
                if child.is_dir() and any(
                        e.name.startswith("uac-") or "thor" in e.name.lower()
                        for e in child.iterdir()):
                    tags.add(str(child))
            except OSError:
                continue
    return tags


def _match_ids(match) -> str:
    ids: list[str] = []
    for s in getattr(match, "strings", []):
        ident = getattr(s, "identifier", None) or (s[1] if isinstance(s, tuple) else "")
        if ident and ident not in ids:
            ids.append(ident)
    return ",".join(ids)


def run(ctx) -> None:
    rules = _compile_rules(ctx.assets, ctx.log)
    base = root(ctx.evidence)
    roots = list(_scan_roots(base))
    if not roots:
        raise HandlerSkip("no target directory present")

    collector = _collector_tag_dirs(base)
    rows: list[list] = []
    seen: set[str] = set()
    for start in roots:
        for dirpath, dirnames, filenames in os.walk(start):
            dirnames[:] = [d for d in dirnames
                           if not _prune(d) and os.path.join(dirpath, d) not in collector]
            if _SNAPSHOT.search(Path(dirpath).as_posix() + "/"):
                continue
            for fn in filenames:
                if fn in _SKIP_NAMES or Path(fn).suffix.lower() in _SKIP_EXT:
                    continue
                f = Path(dirpath) / fn
                try:
                    if not f.is_file() or f.is_symlink():
                        continue
                    if f.stat().st_size > _MAX_BYTES:
                        continue
                    rel = f.relative_to(base).as_posix()
                    if rel in seen:                # homes overlap with nothing, but be safe
                        continue
                    ext = f.suffix.lower().lstrip(".")
                    matches = rules.match(
                        str(f), externals=_externals_for(fn, rel, ext), timeout=60)
                except (OSError, ValueError):
                    continue
                except Exception:  # noqa: BLE001 - yara timeout/error on one file
                    continue
                if not matches:
                    continue
                seen.add(rel)
                size = f.stat().st_size
                for m in matches:
                    rows.append([m.rule, ",".join(m.tags), rel, size, _match_ids(m), "yes"])

    rows.sort(key=lambda r: (r[0], r[2]))
    write_csv(ctx.out, "yara.csv", ["rule", "tags", "file", "size", "strings", "suspicious"], rows)
