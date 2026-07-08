"""Download and verify external binaries for `aeng setup`.

Resolves the URL (GitHub release or direct URL), downloads, verifies SHA256 if
declared, unpacks if applicable and renames. Best-effort: if it fails (e.g. no
network) it reports and continues, it does not break setup.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import zipfile
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


def _github_asset_url(repo: str, asset: str) -> str | None:
    import requests

    api = f"https://api.github.com/repos/{repo}/releases/latest"
    r = requests.get(api, timeout=30)
    r.raise_for_status()
    for a in r.json().get("assets", []):
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
                for chunk in r.iter_content(chunk_size=1024 * 1024):
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


def _fetch_dbip(kind: str, dest: Path) -> bool:
    """Fetch a db-ip lite mmdb (kind = 'country' | 'asn'). db-ip publishes
    monthly with the year-month in the URL, so try this month then the prior."""
    from datetime import date

    if dest.is_file():
        log.info(f"[=] {dest.name} already present")
        return True
    today = date.today()
    prev = today.replace(day=1).toordinal() - 1
    for ym in (f"{today.year}-{today.month:02d}", date.fromordinal(prev).strftime("%Y-%m")):
        try:
            log.info(f"[+] downloading db-ip {kind}-lite ({ym})")
            if _download(_DBIP_URL.format(kind=kind, ym=ym), dest, gunzip=True):
                return True
        except Exception as e:  # noqa: BLE001
            log.warning(f"[!] db-ip {kind} {ym} unavailable: {e}")
    return False


def fetch_web_assets(assets_dir: Path) -> int:
    """Download the offline IP-origin databases huntweb needs: CC-BY db-ip
    country-lite (country) + asn-lite (VPN/hosting org) + the Tor exit list.
    Best-effort; returns how many of the 3 are ready."""
    ready = 0
    country = assets_dir / "dbip-country-lite.mmdb"
    if _fetch_dbip("country", country):
        ready += 1
    if _fetch_dbip("asn", assets_dir / "dbip-asn-lite.mmdb"):
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
            import maxminddb  # noqa: F401, PLC0415
        except ImportError:
            log.warning("[!] 'maxminddb' is not installed -- huntweb IP origin lookup "
                        "will be disabled. Install it: pip install maxminddb")

    return ready


# Florian Roth's signature-base (Detection Rule License 1.1): the community
# YARA ruleset lin_yara compiles alongside its own bundled rules.
_SIGBASE_URL = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"


def fetch_yara_rules(assets_dir: Path) -> int:
    """Download Florian Roth's signature-base YARA rules into
    <assets>/yara/signature-base/. Best-effort; returns the number of .yar files
    written (0 on failure)."""
    import io
    import zipfile

    import requests

    dest = assets_dir / "yara" / "signature-base"
    try:
        log.info("[+] downloading signature-base YARA rules (Neo23x0)")
        with requests.get(_SIGBASE_URL, timeout=180) as r:
            r.raise_for_status()
            zf = zipfile.ZipFile(io.BytesIO(r.content))
        members = [n for n in zf.namelist()
                   if "/yara/" in n and n.endswith((".yar", ".yara"))]
        if not members:
            log.warning("[!] signature-base archive had no yara rules")
            return 0
        dest.mkdir(parents=True, exist_ok=True)
        for m in members:
            (dest / Path(m).name).write_bytes(zf.read(m))   # flatten into one dir
        log.info(f"[+] signature-base: {len(members)} rule file(s) -> {dest}")
        return len(members)
    except Exception as e:  # noqa: BLE001 - best-effort, never break setup
        log.warning(f"[!] signature-base unavailable: {e}")
        return 0


def fetch_hayabusa(tools_dir: Path) -> bool:
    """Download Hayabusa (Windows x64, rules + config bundled) into
    tools/hayabusa/. The release assets are version-stamped, so resolve the
    latest win-x64 (non live-response) asset from the API. Best-effort."""
    import io
    import zipfile

    import requests

    dest = tools_dir / "hayabusa"
    if dest.is_dir() and any(dest.glob("hayabusa*.exe")):
        log.info("[=] hayabusa already present")
        return True
    try:
        api = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
        rel = requests.get(api, timeout=60)
        rel.raise_for_status()
        asset = next((a for a in rel.json().get("assets", [])
                      if a.get("name", "").endswith("win-x64.zip")
                      and "live-response" not in a.get("name", "")), None)
        if not asset:
            log.warning("[!] hayabusa: no win-x64 asset in latest release")
            return False
        log.info(f"[+] downloading {asset['name']}")
        with requests.get(asset["browser_download_url"], timeout=300) as r:
            r.raise_for_status()
            zf = zipfile.ZipFile(io.BytesIO(r.content))
        dest.mkdir(parents=True, exist_ok=True)
        _extractall_longpath(zf, dest)  # exe + rules/ + config/; long-path safe
        ok = any(dest.glob("hayabusa*.exe"))
        log.info(f"[+] hayabusa ready -> {dest}" if ok else "[!] hayabusa exe missing after unpack")
        return ok
    except Exception as e:  # noqa: BLE001 - never break setup
        log.warning(f"[!] hayabusa unavailable: {e}")
        return False
