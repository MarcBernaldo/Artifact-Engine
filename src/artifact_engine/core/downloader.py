"""Download and verify external binaries for `aeng setup`.

Resolves the URL (GitHub release or direct URL), downloads, verifies SHA256 if
declared, unpacks if applicable and renames. Best-effort: if it fails (e.g. no
network) it reports and continues, it does not break setup.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from artifact_engine.logging_setup import get_logger
from artifact_engine.models import ToolSource

log = get_logger()


def _long(path: Path) -> str:
    """Windows extended-length (\\\\?\\) form of an absolute path, to bypass the
    260-char MAX_PATH limit. Unchanged on POSIX."""
    s = str(Path(path))
    if os.name == "nt" and not s.startswith("\\\\?\\"):
        s = "\\\\?\\" + s
    return s


def _extractall_longpath(zf: zipfile.ZipFile, dest: Path) -> None:
    """Like ZipFile.extractall but writes each member through an extended-length
    path, so a deeply-nested archive (hayabusa bundles thousands of Sigma rules in
    a very deep tree) extracts even when `dest` already sits under a long path
    (e.g. a deep Downloads folder) -- a plain extractall raises FileNotFoundError
    there on Windows. Rejects path-traversal entries."""
    base = Path(dest).resolve()
    for m in zf.infolist():
        parts = [p for p in m.filename.split("/") if p not in ("", ".", "..")]
        if not parts:
            continue
        target = base.joinpath(*parts)
        if m.is_dir():
            os.makedirs(_long(target), exist_ok=True)
            continue
        os.makedirs(_long(target.parent), exist_ok=True)
        with zf.open(m) as src, open(_long(target), "wb") as out:
            shutil.copyfileobj(src, out)


def latest_release(repo: str) -> dict | None:
    """The latest GitHub release of `repo`, or None if it cannot be read.

    Kept separate from the download so `aeng update` can ask "is there anything
    newer?" over one small API call, instead of pulling tens of megabytes to find
    out that nothing changed."""
    import requests

    try:
        r = requests.get(f"https://api.github.com/repos/{repo}/releases/latest", timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:  # noqa: BLE001 - offline / rate-limited / no release
        log.warning(f"[!] cannot read the latest release of {repo}: {e}")
        return None


def latest_tag(repo: str) -> str:
    """Version of the latest release, `v` stripped (e.g. '3.10.0'). '' if unknown."""
    rel = latest_release(repo)
    return str((rel or {}).get("tag_name", "")).lstrip("vV")


def _github_asset_url(repo: str, asset: str) -> str | None:
    rel = latest_release(repo)
    if rel is None:
        return None
    for a in rel.get("assets", []):
        if a.get("name") == asset:
            return a.get("browser_download_url")
    log.error(f"[!] asset '{asset}' not found in the latest release of {repo}")
    return None


def _resolve_url(src: ToolSource) -> str | None:
    if src.url:
        return src.url
    if src.repo and src.asset:
        return _github_asset_url(src.repo, src.asset)
    log.error("[!] ToolSource without 'url' or 'repo'+'asset'")
    return None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def file_sha256(path: Path) -> str:
    """Public SHA256 of a file (used to record the tools lockfile)."""
    return _sha256(path)


def fetch_tool(tool, tools_dir: Path, purge_dirs: tuple[str, ...] = ()) -> bool:
    """Download a parser's binary. Returns True if it ended up ready.

    `purge_dirs` are folders under `tools_dir` emptied just before unpacking --
    for a tool that bundles a rule set (chainsaw), so a rule upstream withdrew
    does not survive the update and go on firing. They are removed only once the
    download has succeeded, so a failed fetch never leaves a gutted install.
    """
    import requests

    src: ToolSource = tool.source
    try:
        url = _resolve_url(src)
        if not url:
            return False
        tools_dir.mkdir(parents=True, exist_ok=True)
        tmp = tools_dir / (src.asset or Path(url).name or tool.binary)
        log.info(f"[+] downloading {tool.binary} from {url}")
        with requests.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            with open(tmp, "wb") as fh:
                # A loop, not `writelines`: these are 1 MB binary blobs, and
                # calling them lines would only mislead the next reader.
                for chunk in r.iter_content(chunk_size=1024 * 1024):  # noqa: FURB122
                    fh.write(chunk)

        if src.sha256:
            got = _sha256(tmp)
            if got.lower() != src.sha256.lower():
                log.error(f"[!] SHA256 mismatch for {tool.binary}: expected {src.sha256}, got {got}")
                tmp.unlink(missing_ok=True)
                return False
            log.info(f"[+] SHA256 verified for {tool.binary}")
        else:
            log.warning(f"[!] {tool.binary}: no sha256 declared (no integrity check)")

        if src.unpack and zipfile.is_zipfile(tmp):
            dest = (tools_dir / src.unpack_dir) if src.unpack_dir else tools_dir
            for d in purge_dirs:                 # the archive is already in hand
                shutil.rmtree(tools_dir / d, ignore_errors=True)
            dest.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(tmp) as zf:
                _extractall_longpath(zf, dest)   # traversal-safe + long-path safe
            tmp.unlink(missing_ok=True)

        if src.rename_to:
            (tools_dir / src.rename_to).replace(tools_dir / tool.binary)

        return (tools_dir / tool.binary).exists()
    except Exception as e:  # noqa: BLE001
        log.error(f"[!] error fetching {tool.binary}: {e}")
        return False


# --------------------------------------------------------------------------- #
# Offline geo assets for the web hunt (huntweb): db-ip country + ASN + Tor exits
# --------------------------------------------------------------------------- #
_DBIP_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{ym}.mmdb.gz"
_TOR_URL = "https://check.torproject.org/torbulkexitlist"


def _download(url: str, dest: Path, *, gunzip: bool = False) -> bool:
    import gzip

    import requests

    with requests.get(url, stream=True, timeout=120) as r:
        r.raise_for_status()
        raw = r.content
    data = gzip.decompress(raw) if gunzip else raw
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return dest.is_file() and dest.stat().st_size > 0


def _fetch_dbip(kind: str, dest: Path, force: bool = False) -> bool:
    """Fetch a db-ip lite mmdb (kind = 'country' | 'asn'). db-ip publishes
    monthly with the year-month in the URL, so try this month then the prior.

    `force` re-downloads over a file that is already there -- what `aeng update`
    needs and `aeng setup` must not do: setup fills the gaps, update refreshes
    what has since gone stale (these databases are re-cut every month)."""
    from datetime import date, datetime, timezone

    if dest.is_file() and not force:
        log.info(f"[=] {dest.name} already present")
        return True
    # UTC, not local: the publisher's month is what names the file, and near a
    # month boundary a machine behind UTC would ask for one that is not up yet.
    today = datetime.now(timezone.utc).date()
    stamp = dest.with_name(dest.name + ".ym")   # which monthly cut is on disk
    prev = today.replace(day=1).toordinal() - 1
    months = (f"{today.year}-{today.month:02d}", date.fromordinal(prev).strftime("%Y-%m"))
    # db-ip re-cuts these once a month, so a forced refresh inside the same month
    # would pull ~18 MB to write the identical bytes back. The stamp records which
    # cut is on disk; without one (an install from before it existed) we refetch.
    if dest.is_file() and stamp.is_file():
        try:
            if stamp.read_text(encoding="utf-8").strip() == months[0]:
                log.info(f"[=] {dest.name} is the current monthly cut ({months[0]})")
                return True
        except OSError:
            pass
    for ym in months:
        try:
            log.info(f"[+] downloading db-ip {kind}-lite ({ym})")
            if _download(_DBIP_URL.format(kind=kind, ym=ym), dest, gunzip=True):
                stamp.write_text(ym, encoding="utf-8")
                return True
        except Exception as e:  # noqa: BLE001
            log.warning(f"[!] db-ip {kind} {ym} unavailable: {e}")
    return False


def fetch_web_assets(assets_dir: Path, force: bool = False) -> int:
    """Download the offline IP-origin databases huntweb needs: CC-BY db-ip
    country-lite (country) + asn-lite (VPN/hosting org) + the Tor exit list.
    Best-effort; returns how many of the 3 are ready. `force` refreshes files
    already on disk (see `_fetch_dbip`)."""
    ready = 0
    country = assets_dir / "dbip-country-lite.mmdb"
    if _fetch_dbip("country", country, force):
        ready += 1
    if _fetch_dbip("asn", assets_dir / "dbip-asn-lite.mmdb", force):
        ready += 1

    tor = assets_dir / "tor-exit-nodes.txt"
    try:
        log.info("[+] downloading Tor exit-node list")
        if _download(_TOR_URL, tor):
            ready += 1
    except Exception as e:  # noqa: BLE001
        log.warning(f"[!] Tor exit list unavailable: {e}")

    # The DBs are useless without the reader library; warn loudly rather than
    # let huntweb silently degrade every IP origin to '?'.
    if country.is_file():
        try:
            import maxminddb  # noqa: F401
        except ImportError:
            log.warning("[!] 'maxminddb' is not installed -- huntweb IP origin lookup "
                        "will be disabled. Install it: pip install maxminddb")

    return ready


# mthcht/awesome-lists (MIT): community detection lists for the tables this engine
# builds and could not judge -- service names, scheduled-task names, ransom notes.
# Fetched rather than bundled: they are updated continuously upstream, and a
# frozen copy of a threat list ages into a false sense of coverage.
_AWESOME_RAW = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/{name}"

# Only the lists this engine has an artifact to match against -- which is not the
# same as "lists something already reads": the services list has a consumer
# (`service_installs`), the other three are fetched ahead of theirs so that adding
# a parser is a parser and not also a downloader change. Deliberately absent: the
# 431 KB user-agent list would swamp `web_suspicious.txt` (sixty-two curated
# low-FP lines), and named pipes / mutexes need live handle enumeration that no
# collector here performs.
AWESOME_LISTS = (
    "suspicious_windows_services_names_list.csv",
    "suspicious_windows_tasks_list.csv",
    "ransomware_notes_list.csv",
    "ransomware_extensions_list.csv",
)


def fetch_awesome_lists(assets_dir: Path, force: bool = False) -> int:
    """Download the awesome-lists CSVs into `assets/awesome/`. Returns how many
    are on disk afterwards.

    Best-effort by design: every consumer treats these as enrichment, so a failed
    fetch costs a tool name and a reference, never a detection.
    """
    dest_dir = Path(assets_dir) / "awesome"
    ready = 0
    for name in AWESOME_LISTS:
        dest = dest_dir / name
        if dest.is_file() and not force:
            ready += 1
            continue
        try:
            log.info(f"[+] downloading awesome-lists {name}")
            if _download(_AWESOME_RAW.format(name=name), dest):
                ready += 1
        except Exception as e:  # noqa: BLE001
            log.warning(f"[!] awesome-lists {name} unavailable: {e}")
            if dest.is_file():
                ready += 1          # the copy already on disk still counts
    return ready


# Florian Roth's signature-base (Detection Rule License 1.1): the community
# YARA ruleset lin_yara compiles alongside its own bundled rules.
_SIGBASE_URL = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
_SIGBASE_REPO = "Neo23x0/signature-base"

# codeload answers with ETag: W/"<40-hex commit>" (sometimes without the W/).
_RE_ETAG_SHA = re.compile(r'"?([0-9a-f]{40})"?\s*$')


def _etag_commit(etag: str) -> str:
    m = _RE_ETAG_SHA.search((etag or "").strip())
    return m.group(1) if m else ""


def _branch_commit(repo: str, branch: str = "master") -> str:
    """Commit at the tip of `branch`, or "" -- best-effort, never breaks a sync."""
    import requests

    try:
        r = requests.get(f"https://api.github.com/repos/{repo}/commits/{branch}",
                         headers={"Accept": "application/vnd.github+json"}, timeout=30)
        r.raise_for_status()
        return str(r.json().get("sha", ""))[:40]
    except Exception:  # noqa: BLE001 - provenance is best-effort, rules are not
        return ""


# Names this tool wrote on the last sync. Anything in the folder that is NOT
# listed here was put there by the analyst, so a sync never touches it.
_SIGBASE_MANIFEST = ".aeng-signature-base.json"


@dataclass
class RuleSync:
    """Outcome of a signature-base sync -- what the rule set gained and lost."""

    total: int = 0
    added: int = 0
    removed: int = 0
    ok: bool = False
    commit: str = ""     # upstream commit the rules came from ("" if unresolved)

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)


def fetch_yara_rules(assets_dir: Path) -> RuleSync:
    """Sync Florian Roth's signature-base YARA rules into
    <assets>/yara/signature-base/.

    A rule upstream WITHDREW is deleted here too. That is the whole difference
    between a download and a sync, and it matters: rules are usually withdrawn
    because they turned out to fire on benign files, so a copy left behind keeps
    producing exactly the false positive upstream retired. Only files a previous
    sync wrote are ever removed (they are listed in a manifest beside them), so
    rules the analyst drops into the same folder survive untouched.

    Best-effort: on any failure the rules already on disk are left as they are.
    """
    import io
    import json
    import zipfile

    import requests

    dest = assets_dir / "yara" / "signature-base"
    try:
        log.info("[+] downloading signature-base YARA rules (Neo23x0)")
        with requests.get(_SIGBASE_URL, timeout=180) as r:
            r.raise_for_status()
            # The URL is a BRANCH head, so "the rules" is whatever master held at
            # the moment of the request -- and the sync deletes rules upstream
            # withdrew. Without the commit there is no way to answer "which
            # version of this rule produced this hit, and can you show me its text
            # as it stood that day?", which is the question a re-examination or a
            # defence expert asks. GitHub returns it in the ETag of the archive;
            # the API call is the fallback, not the first choice, so a rate limit
            # cannot cost us the rules themselves.
            commit = _etag_commit(r.headers.get("ETag", "")) or _branch_commit(_SIGBASE_REPO)
            zf = zipfile.ZipFile(io.BytesIO(r.content))
        members = [n for n in zf.namelist()
                   if "/yara/" in n and n.endswith((".yar", ".yara"))]
        if not members:
            log.warning("[!] signature-base archive had no yara rules")
            return RuleSync()

        manifest = dest / _SIGBASE_MANIFEST
        try:
            raw = json.loads(manifest.read_text(encoding="utf-8"))
            # Manifests written before provenance was recorded are a bare list.
            previous = set(raw if isinstance(raw, list) else raw.get("files", []))
        except (OSError, ValueError):
            previous = set()

        dest.mkdir(parents=True, exist_ok=True)
        current = set()
        for m in members:
            name = Path(m).name
            (dest / name).write_bytes(zf.read(m))          # flatten into one dir
            current.add(name)

        withdrawn = sorted(previous - current)
        for name in withdrawn:
            (dest / name).unlink(missing_ok=True)
        manifest.write_text(json.dumps(
            {"repo": _SIGBASE_REPO, "commit": commit,
             "retrieved_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "files": sorted(current)},
            indent=1), encoding="utf-8")

        sync = RuleSync(total=len(current), added=len(current - previous),
                        removed=len(withdrawn), ok=True, commit=commit)
        detail = f"  (+{sync.added} new, -{sync.removed} withdrawn)" if previous else ""
        where = f" @{commit[:12]}" if commit else " (commit unknown)"
        log.info(f"[+] signature-base{where}: {sync.total} rule file(s) -> {dest}{detail}")
        return sync
    except Exception as e:  # noqa: BLE001 - best-effort, never break setup
        log.warning(f"[!] signature-base unavailable: {e}")
        return RuleSync()


HAYABUSA_REPO = "Yamato-Security/hayabusa"
CHAINSAW_REPO = "WithSecureLabs/chainsaw"


def installed_hayabusa_version(tools_dir: Path) -> str:
    """Installed hayabusa version, read off the exe name (`hayabusa-3.9.0-win-x64
    .exe`) -- the release stamps it there, so nothing has to be executed."""
    for exe in (tools_dir / "hayabusa").glob("hayabusa*.exe"):
        mo = re.search(r"(\d+\.\d+\.\d+)", exe.name)
        if mo:
            return mo.group(1)
    return ""


def installed_chainsaw_version(tools_dir: Path, binary: str) -> str:
    """Installed chainsaw version. Its exe name carries no version, so ask the
    binary (`chainsaw --version` -> 'chainsaw 2.16.0'). Returns '' if it cannot
    be run -- an unknown version is treated as "refresh it" by the caller."""
    exe = tools_dir / binary
    if not exe.is_file():
        return ""
    try:
        out = subprocess.run([str(exe), "--version"], capture_output=True, text=True,
                             timeout=30, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    mo = re.search(r"(\d+\.\d+\.\d+)", out)
    return mo.group(1) if mo else ""


def fetch_hayabusa(tools_dir: Path, force: bool = False) -> bool:
    """Download Hayabusa (Windows x64, rules + config bundled) into
    tools/hayabusa/. The release assets are version-stamped, so resolve the
    latest win-x64 (non live-response) asset from the API. Best-effort.

    `force` replaces an install that is already there -- hayabusa ships its Sigma
    rule set inside the archive, so a new release is new detection content, not
    just a new binary. The old versioned exe is removed so the folder never ends
    up with two."""
    import io
    import zipfile

    import requests

    dest = tools_dir / "hayabusa"
    if dest.is_dir() and any(dest.glob("hayabusa*.exe")) and not force:
        log.info("[=] hayabusa already present")
        return True
    try:
        rel = latest_release(HAYABUSA_REPO)
        if rel is None:
            return False
        asset = next((a for a in rel.get("assets", [])
                      if a.get("name", "").endswith("win-x64.zip")
                      and "live-response" not in a.get("name", "")), None)
        if not asset:
            log.warning("[!] hayabusa: no win-x64 asset in latest release")
            return False
        log.info(f"[+] downloading {asset['name']}")
        with requests.get(asset["browser_download_url"], timeout=300) as r:
            r.raise_for_status()
            zf = zipfile.ZipFile(io.BytesIO(r.content))
        # Only now that the archive is in hand: a download that fails must leave
        # the working install alone, never a half-removed one.
        for old in dest.glob("hayabusa*.exe"):
            old.unlink(missing_ok=True)      # the name is versioned; never keep two
        # `rules/` is upstream's alone, and a withdrawn Sigma rule left behind goes
        # on firing -- same reason the signature-base sync deletes. `config/` is
        # NOT purged: it is what an analyst tunes, and extracting overwrites the
        # files upstream ships anyway.
        shutil.rmtree(dest / "rules", ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)
        _extractall_longpath(zf, dest)  # exe + rules/ + config/; long-path safe
        ok = any(dest.glob("hayabusa*.exe"))
        log.info(f"[+] hayabusa ready -> {dest}" if ok else "[!] hayabusa exe missing after unpack")
        return ok
    except Exception as e:  # noqa: BLE001 - never break setup
        log.warning(f"[!] hayabusa unavailable: {e}")
        return False
