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
import zipfile
from dataclasses import dataclass, field
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


# The EZ tools' modern builds (`download.ericzimmermanstools.com/net/<Tool>.zip`,
# .NET 10 since that site dropped its `/net9/` path) do not carry their runtime:
# on a host without it every one of them exits at launch, which a run reports as
# that parser failing, case after case. Each build says what it needs in its
# `<Tool>.runtimeconfig.json`, and by default .NET rolls forward only within a
# major -- a .NET 9 build does not run on a host that has only .NET 10 -- so
# what is checked is that exact major, not "the newest one".
_NETCORE_RUNTIME = re.compile(r"^Microsoft\.NETCore\.App (\d+)\.\d+")
DOTNET_DOWNLOAD = "https://dotnet.microsoft.com/download/dotnet/{major}.0"


def dotnet_runtime_majors() -> set[int]:
    """The .NET (Core) runtime majors installed; empty when `dotnet` is not on
    PATH or lists none."""
    import subprocess
    try:
        out = subprocess.run(["dotnet", "--list-runtimes"], capture_output=True,
                             text=True, timeout=30, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    return {int(m.group(1)) for line in out.splitlines()
            if (m := _NETCORE_RUNTIME.match(line.strip()))}


def required_dotnet_major(binary: Path) -> int | None:
    """The .NET major a tool's `<stem>.runtimeconfig.json` names, or None for a
    tool without one (self-contained, or not a .NET program)."""
    import json
    try:
        cfg = json.loads(binary.with_suffix(".runtimeconfig.json").read_text(encoding="utf-8"))
        version = cfg["runtimeOptions"]["framework"]["version"]
        return int(str(version).split(".")[0])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def missing_dotnet(tools_dir: Path, binaries) -> dict[int, list[str]]:
    """{.NET major: [tool, ...]} for the installed tools whose runtime is absent."""
    needs = {b: n for b in sorted(set(binaries))
             if (n := required_dotnet_major(Path(tools_dir) / b)) is not None}
    if not needs:
        return {}                     # nothing to ask `dotnet` about
    installed = dotnet_runtime_majors()
    gaps: dict[int, list[str]] = {}
    for b, need in needs.items():
        if need not in installed:
            gaps.setdefault(need, []).append(b)
    return gaps


def fetch_tool(tool, tools_dir: Path) -> bool:
    """Download a parser's binary. Returns True if it ended up ready."""
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
# Offline geo assets for the web parsers (alert_web, art_web_metrics): db-ip country +
# ASN + Tor exits
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
    """Download the offline IP-origin databases the web parsers read: CC-BY db-ip
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
    # let the web parsers silently degrade every IP origin to '?'.
    if country.is_file():
        try:
            import maxminddb  # noqa: F401
        except ImportError:
            log.warning("[!] 'maxminddb' is not installed -- web IP origin lookup "
                        "will be disabled. Install it: pip install maxminddb")

    return ready


# mthcht/awesome-lists (MIT): community detection lists for the tables this engine
# builds and could not judge -- service names and scheduled-task names.
# Fetched rather than bundled: they are updated continuously upstream, and a
# frozen copy of a threat list ages into a false sense of coverage.
_AWESOME_RAW = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/{name}"

# Only the lists this engine has an artifact to match against, each with a
# consumer: `art_service_installs` and `art_task_installs`. (The two ransomware lists went
# with `ransomware_mft` / `ransomware_bodyfile` in v0.7.161.) Deliberately absent: the
# 431 KB user-agent list would swamp `web_suspicious.txt` (nineteen curated
# low-FP indicators), and named pipes / mutexes need live handle enumeration that no
# collector here performs.
AWESOME_LISTS = (
    "suspicious_windows_services_names_list.csv",
    "suspicious_windows_tasks_list.csv",
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


def fetch_lottunnels(assets_dir: Path, force: bool = False) -> bool:
    """Download LOTTunnels and write `assets/lottunnels/tunnels.yaml` (v0.7.102).

    GPL-3.0, so fetched here and never bundled: see `core/lol_tunnels.py`. The
    repository's archive is read in a temporary file, only its tool pages are
    parsed, and only the derived list is kept. Best-effort like the
    awesome-lists: without it `win_rmm` and `alert_remote_access_domains` still read
    LOLRMM.
    """
    import tempfile

    from artifact_engine.core import lol_tunnels

    dest = Path(assets_dir) / lol_tunnels.ASSET
    if dest.is_file() and not force:
        return True
    try:
        log.info("[+] downloading LOTTunnels")
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "lottunnels.zip"
            if not _download(lol_tunnels.SOURCE_URL, archive):
                return dest.is_file()
            entries = lol_tunnels.from_zip(archive)
        if not entries:
            log.warning("[!] LOTTunnels archive held no tool pages; kept the list on disk")
            return dest.is_file()
        today = datetime.now(timezone.utc).date().isoformat()
        text = lol_tunnels.render(entries, today)
        if dest.is_file() and lol_tunnels.same_tools(dest.read_text(encoding="utf-8"), text):
            return True             # only the retrieval date would change: keep the file
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
        return True
    except Exception as e:  # noqa: BLE001
        log.warning(f"[!] LOTTunnels unavailable: {e}")
        return dest.is_file()


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
    release: str = ""    # YARA-Forge only: the release the package came from
    rules: int = 0       # YARA-Forge only: rules kept across `total` files
    left_out: int = 0    # YARA-Forge only: rules of repositories with no reviewed licence

    new_release: bool = False   # YARA-Forge only: a release other than the one on disk
    blocked: list[str] = field(default_factory=list)   # written, but not readable back

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed or self.new_release)


def _unreadable(dest: Path, written: dict[str, bytes]) -> list[str]:
    """The files just written to `dest` that do not read back as written.

    An antivirus scanning the folder quarantines rule files for the malware
    strings they quote, or denies every read of them: the write succeeds, and
    the file is lost to the scan later with no error at the point it happened.
    """
    bad = []
    for name, data in written.items():
        try:
            same = (dest / name).read_bytes() == data
        except OSError:
            same = False
        if not same:
            bad.append(name)
    return sorted(bad)


def _warn_blocked(what: str, dest: Path, names: list[str]) -> None:
    shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
    log.warning(f"[!] {what}: {len(names)} rule file(s) could not be read back ({shown}): "
                f"an antivirus is blocking or removing them; exclude {dest} from its "
                f"scan, then run `aeng update`")


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
        written: dict[str, bytes] = {}
        for m in members:
            name = Path(m).name
            written[name] = zf.read(m)
            (dest / name).write_bytes(written[name])       # flatten into one dir
        current = set(written)

        withdrawn = sorted(previous - current)
        for name in withdrawn:
            (dest / name).unlink(missing_ok=True)
        manifest.write_text(json.dumps(
            {"repo": _SIGBASE_REPO, "commit": commit,
             "retrieved_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "files": sorted(current)},
            indent=1), encoding="utf-8")

        sync = RuleSync(total=len(current), added=len(current - previous),
                        removed=len(withdrawn), ok=True, commit=commit,
                        blocked=_unreadable(dest, written))
        detail = f"  (+{sync.added} new, -{sync.removed} withdrawn)" if previous else ""
        where = f" @{commit[:12]}" if commit else " (commit unknown)"
        log.info(f"[+] signature-base{where}: {sync.total} rule file(s) -> {dest}{detail}")
        if sync.blocked:
            _warn_blocked("signature-base", dest, sync.blocked)
        return sync
    except Exception as e:  # noqa: BLE001 - best-effort, never break setup
        log.warning(f"[!] signature-base unavailable: {e}")
        return RuleSync()


# YARA-Forge (YARAHQ): a weekly release that gathers ~40 public YARA repositories,
# drops the rules that fail its quality checks and ships the rest as one file per
# package. `extended`, not `core`: on the cases it was measured on, `core` lost the
# one hit the existing rules had and `extended` kept it.
_FORGE_REPO = "YARAHQ/yara-forge"
FORGE_PACKAGE = "extended"
_FORGE_URL = ("https://github.com/YARAHQ/yara-forge/releases/latest/download/"
              "yara-forge-rules-{package}.zip")
_FORGE_MANIFEST = ".aeng-yara-forge.json"
# `latest/download/...` answers with a redirect to `/releases/download/<tag>/...`.
_RE_FORGE_TAG = re.compile(r"/releases/download/([^/]+)/")
_RE_FORGE_SET = re.compile(rb"(?m)^/\*\r?\n \* YARA Rule Set\r?\n")
_RE_FORGE_RULE = re.compile(rb"(?m)^(?:private\s+|global\s+)*rule\s+\w")

# The repositories whose licence was read and allows this use, keyed by the
# repository URL each rule set's header names (no scheme, no trailing slash,
# lower case). Most rules carry no licence of their own, so the repository's is
# the one that applies. A repository missing here -- one that states no licence
# at all, or one a later release adds -- is left out and named in the log, never
# loaded on trust.
#
# signature-base is not here on purpose: `fetch_yara_rules` syncs all of it, and
# the package keeps 4,316 of its 5,990 rules and none of the 596 that match on
# the file name or path this engine passes in.
FORGE_LICENCES = {
    "github.com/reversinglabs/reversinglabs-yara-rules": "MIT",
    "github.com/kevoreilly/capev2": "GPL-3.0",
    "github.com/airbnb/binaryalert": "Apache-2.0",
    "github.com/deadbits/yara-rules": "Unlicense",
    "github.com/eset/malware-ioc": "BSD-2-Clause",
    "github.com/mandiant/red_team_tool_countermeasures": "BSD-2-Clause",
    "github.com/chronicle/gcti": "Apache-2.0",
    "github.com/malpedia/signator-rules": "CC-BY-SA-4.0",
    "github.com/advanced-threat-research/yara-rules": "Apache-2.0",
    "github.com/telekom-security/malware_analysis": "MIT",
    "github.com/volexity/threat-intel": "BSD-2-Clause",
    "github.com/jpcertcc/malconfscan": "BSD-3-Clause",
    "github.com/dr4k0nia/yara-rules": "DRL-1.1",
    "github.com/embee-research/yara-detection-rules": "DRL-1.1",
    "github.com/avast/ioc": "DRL-1.1",
    "github.com/elceef/yara-rulz": "MIT",
    "github.com/cod3nym/detection-rules": "DRL-1.1",
    "github.com/craiu/yararules": "GPL-3.0",
    "github.com/ditekshen/detection": "BSD-2-Clause",
    "github.com/withsecurelabs/iocs": "BSD-2-Clause",
    "github.com/magicsword-io/loldrivers": "Apache-2.0",
    "github.com/sekoia-io/community": "DRL-1.1",
    "github.com/synacktiv/synacktiv-rules": "DRL-1.1",
}
_FORGE_SIGBASE = "github.com/neo23x0/signature-base"


def _repo_key(url: str) -> str:
    return re.sub(r"^https?://", "", url.strip()).rstrip("/").lower()


def split_forge(package: bytes) -> tuple[bytes, list[tuple[str, str, bytes]]]:
    """The import lines of a YARA-Forge package, and its rule sets as (repository
    name, repository URL, text) -- one set per source repository, each opening
    with a comment that names the repository and quotes its licence.

    Bytes in, bytes out: a rule's text strings are matched byte for byte, so the
    package is never decoded and re-encoded on its way to disk. A set whose
    header names no repository comes back with an empty URL.
    """
    starts = [m.start() for m in _RE_FORGE_SET.finditer(package)]
    if not starts:
        return b"", []
    imports = b"".join(m.group(0) + b"\n"
                       for m in re.finditer(rb'(?m)^import "\w+"', package[:starts[0]]))
    sets = []
    for a, b in zip(starts, starts[1:] + [len(package)]):
        text = package[a:b]
        name = re.search(rb" \* Repository Name: ([^\r\n]+)", text)
        repo = re.search(rb" \* Repository: (\S+)", text)
        sets.append((name.group(1).decode("utf-8", "replace").strip() if name else "",
                     repo.group(1).decode("utf-8", "replace") if repo else "", text))
    return imports, sets


def forge_release() -> str:
    """Tag of the latest YARA-Forge release ("" if unknown), read off the redirect
    of its download link: no API call, so no API rate limit."""
    import requests

    try:
        r = requests.head(_FORGE_URL.format(package=FORGE_PACKAGE),
                          allow_redirects=False, timeout=30)
        m = _RE_FORGE_TAG.search(r.headers.get("Location", ""))
        return m.group(1) if m else ""
    except Exception:  # noqa: BLE001 - offline: the caller decides what that means
        return ""


def installed_forge_release(assets_dir: Path) -> str:
    """The YARA-Forge release on disk, from the sync's manifest ("" if none)."""
    import json

    try:
        raw = json.loads((Path(assets_dir) / "yara" / "yara-forge" / _FORGE_MANIFEST)
                         .read_text(encoding="utf-8"))
        return str(raw.get("release", ""))
    except (OSError, ValueError, AttributeError):
        return ""


def fetch_yara_forge(assets_dir: Path, force: bool = False,
                     retry_blocked: bool = False) -> RuleSync:
    """Sync the YARA-Forge `extended` package into <assets>/yara/yara-forge/, one
    file per source repository whose licence is in FORGE_LICENCES.

    One file per repository, not the package's single file: the rules are compiled
    file by file and a file that fails is skipped, so one rule this yara cannot
    compile costs its repository's rules, not all ten thousand. Each file keeps
    the header that quotes its repository's licence.

    Like `fetch_yara_rules` it is a sync: a file a previous sync wrote that this
    release no longer yields is deleted, files the analyst put in the folder are
    never touched, and a manifest beside them records the release, the package's
    SHA256 and, per file, its repository, licence and rule count. The download is
    skipped when the release on disk is the latest, `force` is not set, and
    `retry_blocked` is not set while files are blocked.

    A file that does not read back as written (an antivirus blocked or removed
    it) is recorded under `blocked`, with the same fields, not `files`, and does
    not count as missing: otherwise every later setup would download the release
    again only for the antivirus to remove the same file. `retry_blocked`
    downloads it once more, for when the folder has since been excluded.

    Best-effort: on any failure the rules already on disk are left as they are.
    """
    import io
    import json
    import zipfile
    from collections import Counter

    import requests

    dest = Path(assets_dir) / "yara" / "yara-forge"
    manifest = dest / _FORGE_MANIFEST
    try:
        raw = json.loads(manifest.read_text(encoding="utf-8"))
        previous = dict(raw.get("files") or {})
        was_blocked = dict(raw.get("blocked") or {})
    except (OSError, ValueError, AttributeError, TypeError):
        raw, previous, was_blocked = {}, {}, {}
    try:
        latest = "" if force else forge_release()
        if (latest and latest == raw.get("release") and previous
                and not (retry_blocked and was_blocked)
                and all((dest / n).is_file() for n in previous)):
            log.info(f"[=] YARA-Forge {latest} already present")
            if was_blocked:
                _warn_blocked("YARA-Forge", dest, sorted(was_blocked))
            return RuleSync(total=len(previous), ok=True, release=latest,
                            rules=sum(int(v.get("rules", 0)) for v in previous.values()),
                            left_out=sum((raw.get("left_out") or {}).values()),
                            blocked=sorted(was_blocked))

        log.info(f"[+] downloading YARA-Forge rules ({FORGE_PACKAGE} package)")
        with requests.get(_FORGE_URL.format(package=FORGE_PACKAGE), timeout=180) as r:
            r.raise_for_status()
            hops = [h.headers.get("Location", "") for h in r.history] + [r.url]
            release = next((m.group(1) for m in map(_RE_FORGE_TAG.search, hops) if m), "")
            data = r.content
        zf = zipfile.ZipFile(io.BytesIO(data))
        member = next((n for n in zf.namelist()
                       if n.endswith(f"yara-rules-{FORGE_PACKAGE}.yar")), None)
        if member is None:
            log.warning("[!] YARA-Forge archive had no rule package")
            return RuleSync()
        imports, sets = split_forge(zf.read(member))

        files: dict[str, dict] = {}
        texts: dict[str, bytes] = {}
        left_out: Counter = Counter()
        for name, repo, text in sets:
            key = _repo_key(repo)
            if key == _FORGE_SIGBASE:
                continue                    # synced in full by fetch_yara_rules
            rules = len(_RE_FORGE_RULE.findall(text))
            licence = FORGE_LICENCES.get(key)
            if licence is None:
                left_out[repo or "(unnamed)"] += rules
                continue
            stem = re.sub(r"[^a-z0-9]+", "_", (name or key).lower()).strip("_") or "rules"
            fname = f"{stem}.yar"
            while fname in texts:
                stem += "_"
                fname = f"{stem}.yar"
            head = f"// YARA-Forge {release or '?'} ({FORGE_PACKAGE}): {repo}, {licence}\n"
            texts[fname] = head.encode("utf-8") + imports + b"\n" + text
            files[fname] = {"repo": repo, "licence": licence, "rules": rules}
        if not files:
            log.warning("[!] YARA-Forge package yielded no rule set with a reviewed licence")
            return RuleSync()

        dest.mkdir(parents=True, exist_ok=True)
        for fname, text in texts.items():
            (dest / fname).write_bytes(text)
        blocked = {n: files.pop(n) for n in _unreadable(dest, texts)}
        withdrawn = sorted((set(previous) | set(was_blocked)) - set(texts))
        for fname in withdrawn:
            try:
                (dest / fname).unlink(missing_ok=True)
            except OSError:
                pass                        # held by the antivirus; it goes with it
        manifest.write_text(json.dumps(
            {"source": _FORGE_REPO, "release": release, "package": FORGE_PACKAGE,
             "sha256": hashlib.sha256(data).hexdigest(),
             "retrieved_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "files": files, "blocked": blocked, "left_out": dict(sorted(left_out.items()))},
            indent=1), encoding="utf-8")

        for repo, n in sorted(left_out.items()):
            log.info(f"[i] YARA-Forge: {n} rule(s) of {repo} left out, no reviewed licence")
        sync = RuleSync(total=len(files), added=len(set(files) - set(previous)),
                        removed=len(withdrawn), ok=True, release=release,
                        rules=sum(f["rules"] for f in files.values()),
                        left_out=sum(left_out.values()),
                        new_release=release != raw.get("release"), blocked=sorted(blocked))
        log.info(f"[+] YARA-Forge {release or '(release unknown)'}: {sync.rules} rule(s) "
                 f"in {sync.total} file(s) -> {dest}; {sync.left_out} left out")
        if blocked:
            _warn_blocked(f"YARA-Forge ({sum(b['rules'] for b in blocked.values())} rule(s))",
                          dest, sync.blocked)
        return sync
    except Exception as e:  # noqa: BLE001 - best-effort, never break setup
        log.warning(f"[!] YARA-Forge unavailable: {e}")
        return RuleSync()


HAYABUSA_REPO = "Yamato-Security/hayabusa"


def installed_hayabusa_version(tools_dir: Path) -> str:
    """Installed hayabusa version, read off the exe name (`hayabusa-3.9.0-win-x64
    .exe`) -- the release stamps it there, so nothing has to be executed."""
    for exe in (tools_dir / "hayabusa").glob("hayabusa*.exe"):
        mo = re.search(r"(\d+\.\d+\.\d+)", exe.name)
        if mo:
            return mo.group(1)
    return ""


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
