"""Phase 1 - Recursive extraction.

Supports .zip, .tar, .tar.gz/.tgz, .tar.bz2, .tar.xz, .gz (standalone) and .7z.
- tar.gz is extracted in ONE pass (tarfile), avoiding 7zip's two-step process.
- Recursive: extracts nested archives (zip inside zip, etc.).
- Robust on Windows:
    * 7-Zip fallback for methods Python does not support (Deflate64, etc.).
    * sanitizes NTFS-illegal names (: * ? " < > | and control chars), common in
      Linux acquisitions (UAC).
- Safe: blocks path traversal (lexical check) and aborts on zip-bombs.
- Idempotent: marks each completed destination with a sentinel file, so a failed
  or interrupted extraction is retried on the next pass.
"""

from __future__ import annotations

import gzip
import os
import re
import shutil
import tarfile
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from artifact_engine.core import procs
from artifact_engine.logging_setup import get_logger

log = get_logger()

MAX_RATIO = 200                   # suspicious uncompressed/compressed ratio
MAX_TOTAL = 80 * 1024**3          # 80 GiB uncompressed per archive
MARKER = ".aeng_extracted_ok"     # "destination completed" sentinel

# Containers that bundle a tree (extracted and recursed into).
# Standalone .gz (rotated logs, .mem.swab.gz dumps) are NOT auto-extracted.
CONTAINER_KINDS = {"zip", "tar", "7z"}

# Velociraptor sub-collections (KAPE side-collects them under <collection>/Velociraptor/).
# They are NOT pulled in by the generic nested-container pass (that one stays narrow
# on purpose). Only LiveResponse is extracted: it holds the volatile/live state nothing
# else captures. QuickTriage.zip is intentionally excluded -- its artifacts (Prefetch,
# Amcache, AppCompat, SRUM, lnk, RecycleBin...) duplicate the dedicated KAPE parsers.
# Add a name here if the collection profile changes.
VELOCIRAPTOR_ZIPS = ("LiveResponse.zip",)


@dataclass
class ExtractResult:
    archive: Path
    dest: Path
    ok: bool
    error: str = ""
    sanitized: int = 0
    skipped: int = 0
    used_7z: bool = False
    warnings: bool = False
    warning_detail: str = ""


_TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar")

_WIN_ILLEGAL = re.compile(r'[<>:"|?*]')
_CTRL = re.compile(r"[\x00-\x1f]")
_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


# --------------------------------------------------------------------------- #
# Archive type
# --------------------------------------------------------------------------- #
def _kind(path: Path) -> str | None:
    name = path.name.lower()
    if name.endswith(".zip"):
        return "zip"
    if name.endswith(_TAR_SUFFIXES):
        return "tar"
    if name.endswith(".7z"):
        return "7z"
    if name.endswith(".gz"):  # standalone .gz (not tar)
        return "gz"
    return None


def is_archive(path: Path) -> bool:
    return path.is_file() and _kind(path) is not None


def is_container(path: Path) -> bool:
    return path.is_file() and _kind(path) in CONTAINER_KINDS


def _dest_dir(path: Path) -> Path:
    name = path.name
    lower = name.lower()
    for suf in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if lower.endswith(suf):
            return path.with_name(name[: -len(suf)])
    return path.with_name(path.stem)


# --------------------------------------------------------------------------- #
# Path safety and name sanitization
# --------------------------------------------------------------------------- #
def _sanitize_component(part: str) -> str:
    """Clean a path component so it is valid on the host OS."""
    if os.name != "nt":
        return _CTRL.sub("_", part)
    s = _CTRL.sub("_", _WIN_ILLEGAL.sub("_", part))
    s = s.rstrip(" .")  # NTFS does not allow trailing space or dot
    if not s:
        return "_"
    if s.split(".")[0].upper() in _RESERVED:
        s = "_" + s
    return s


def _safe_relpath(member: str) -> tuple[Path | None, bool]:
    """Turn a member name into a safe relative path.

    LEXICAL check (does not touch the filesystem): rejects '..' and absolute paths.
    Returns (path|None, sanitized). None => unsafe member, ignore it.
    """
    member = member.replace("\\", "/")
    parts: list[str] = []
    changed = False
    for part in member.split("/"):
        if part in ("", ".", "/"):
            continue
        if part == "..":
            return None, False
        clean = _sanitize_component(part)
        if clean != part:
            changed = True
        parts.append(clean)
    if not parts:
        return None, False
    return Path(*parts), changed


# --------------------------------------------------------------------------- #
# 7-Zip (fallback)
# --------------------------------------------------------------------------- #
def find_7z(tools_dir: Path | None = None) -> Path | None:
    cands: list[Path] = []
    if tools_dir:
        cands += [tools_dir / "7zip" / "7z.exe", tools_dir / "7z.exe", tools_dir / "7za.exe"]
    for name in ("7z", "7za", "7zz"):
        w = shutil.which(name)
        if w:
            cands.append(Path(w))
    cands += [
        Path(r"C:\Program Files\7-Zip\7z.exe"),
        Path(r"C:\Program Files (x86)\7-Zip\7z.exe"),
    ]
    for c in cands:
        if c and c.is_file():
            return c
    return None


# Generic 7-Zip counters with no useful info (dropped from the warning).
_7Z_NOISE = ("sub items errors", "archives with errors", "files:", "errors:")
_7Z_PREFIX = re.compile(r"^(ERROR|WARNING)\s*:\s*")


def _seven_errors(*streams: str) -> str:
    """Extract the useful error/warning lines from 7-Zip output.

    Keeps the real cause (e.g. 'data after the end of the payload data : <file>')
    and drops the generic counters. Strips the 'ERROR:'/'WARNING:' prefix.
    """
    msgs: list[str] = []
    seen: set[str] = set()
    for s in streams:
        for line in (s or "").splitlines():
            t = line.strip()
            if not t:
                continue
            low = t.lower()
            if not any(k in low for k in ("error", "warning", "cannot", "after the end")):
                continue
            if any(noise in low for noise in _7Z_NOISE):
                continue
            t = _7Z_PREFIX.sub("", t).strip()
            if t and t not in seen:
                seen.add(t)
                msgs.append(t)
    return " | ".join(msgs[:4])[:240]


def _extract_with_7z(seven: Path, path: Path, dest: Path) -> tuple[bool, str]:
    """Extract with 7-Zip. Returns (had_warnings, detail). Raises on total failure.

    7-Zip rc: 0=ok, 1=warning (non-fatal), 2=fatal. With rc>=2 it often extracts
    almost everything (e.g. minor corruption of one file), so if content was
    produced we accept it with warnings instead of discarding the whole acquisition.
    """
    dest.mkdir(parents=True, exist_ok=True)
    cmd = [str(seven), "x", "-y", "-bb0", "-bsp0", f"-o{dest}", str(path)]
    rc, out, err = procs.run(cmd)
    detail = _seven_errors(out, err)
    if rc == 0:
        return False, ""
    if rc == 1:
        return True, detail
    if any(dest.iterdir()):
        log.debug(f"7z rc={rc} on {path.name} (partial): {detail}")
        return True, detail
    raise RuntimeError(f"rc={rc}: {detail or '7-Zip failure'}")


# --------------------------------------------------------------------------- #
# Native extractors
# --------------------------------------------------------------------------- #
def _extract_zip(path: Path, dest: Path) -> tuple[int, int]:
    sanitized = skipped = 0
    with zipfile.ZipFile(path) as zf:
        comp = sum(i.compress_size for i in zf.infolist()) or 1
        total = sum(i.file_size for i in zf.infolist())
        if total > MAX_TOTAL or (total / comp) > MAX_RATIO:
            raise RuntimeError(f"possible zip-bomb (ratio {int(total / comp)}x, {total} bytes)")
        for info in zf.infolist():
            rel, changed = _safe_relpath(info.filename)
            if rel is None:
                skipped += 1
                continue
            sanitized += changed
            target = dest / rel
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
    return sanitized, skipped


def _extract_tar(path: Path, dest: Path) -> tuple[int, int]:
    sanitized = skipped = 0
    with tarfile.open(path, "r:*") as tf:
        for m in tf.getmembers():
            rel, changed = _safe_relpath(m.name)
            if rel is None:
                skipped += 1
                continue
            sanitized += changed
            target = dest / rel
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not m.isreg():  # symlinks, devices, fifos: skipped (safety/portability)
                skipped += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                skipped += 1
                continue
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
    return sanitized, skipped


def _extract_gz(path: Path, dest: Path) -> tuple[int, int]:
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / path.stem  # drop .gz
    with gzip.open(path, "rb") as src, open(out, "wb") as fh:
        shutil.copyfileobj(src, fh)
    return 0, 0


def _extract_7z_native(path: Path, dest: Path) -> tuple[int, int]:
    import py7zr  # type: ignore

    with py7zr.SevenZipFile(path, "r") as zf:
        zf.extractall(path=dest)
    return 0, 0


def _clear_dir(d: Path) -> None:
    for child in d.iterdir():
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def _extract_one(path: Path, dest: Path, seven: Path | None) -> ExtractResult:
    marker = dest / MARKER
    if marker.is_file():
        return ExtractResult(path, dest, ok=True)
    dest.mkdir(parents=True, exist_ok=True)
    kind = _kind(path)
    used_7z = warned = False
    try:
        if kind == "zip":
            san, sk = _extract_zip(path, dest)
        elif kind == "tar":
            san, sk = _extract_tar(path, dest)
        elif kind == "gz":
            san, sk = _extract_gz(path, dest)
        elif kind == "7z":
            try:
                san, sk = _extract_7z_native(path, dest)
            except ImportError as e:
                raise RuntimeError("py7zr missing") from e
        else:
            return ExtractResult(path, dest, ok=False, error="unsupported format")
    except Exception as e:  # noqa: BLE001 - retried or reported
        if seven is None:
            return ExtractResult(path, dest, ok=False, error=f"{e} (no 7-Zip)")
        log.debug(f"{path.name}: {e} -> retrying with 7-Zip")
        detail = ""
        try:
            _clear_dir(dest)
            warned, detail = _extract_with_7z(seven, path, dest)
            san, sk, used_7z = 0, 0, True
        except Exception as e2:  # noqa: BLE001
            return ExtractResult(path, dest, ok=False, error=f"7-Zip: {e2}")
        marker.write_text("ok", encoding="utf-8")
        return ExtractResult(
            path, dest, ok=True, sanitized=san, skipped=sk,
            used_7z=used_7z, warnings=warned, warning_detail=detail,
        )
    marker.write_text("ok", encoding="utf-8")
    return ExtractResult(path, dest, ok=True, sanitized=san, skipped=sk, used_7z=used_7z, warnings=warned)


def _nested_containers(dest: Path, processed: set[Path]) -> list[Path]:
    """Containers DIRECTLY inside an extracted destination (double-compressed
    acquisition: zip inside zip). Does not search subfolders, so it doesn't pull
    in inner zips like Velociraptor or the .gz files under /var/log."""
    out = []
    try:
        children = list(dest.iterdir())
    except OSError:
        return out
    for p in children:
        if is_container(p) and p.resolve() not in processed:
            out.append(p)
    return out


def extract_all(
    root: Path,
    tools_dir: Path | None = None,
    max_depth: int = 3,
    max_workers: int = 4,
) -> list[ExtractResult]:
    """Extract the parent acquisitions (and nested wrappers) IN PARALLEL.

    Only handles CONTAINERS (zip/tar/tar.gz/7z); standalone .gz (rotated logs,
    memory dumps) are left compressed. Recurses only into containers that hang
    directly off an already-extracted destination (the 'zip inside zip' case).
    """
    seven = find_7z(tools_dir)
    if not seven:
        log.warning("[i] 7-Zip not found: ZIPs using Deflate64 or other unsupported methods will fail")

    processed: set[Path] = set()
    results: list[ExtractResult] = []
    level = sorted((p for p in root.iterdir() if is_container(p)), key=lambda p: p.name.lower())

    depth = 0
    while level and depth < max_depth:
        for p in level:
            processed.add(p.resolve())
        workers = max(1, min(max_workers, len(level)))
        ex = ThreadPoolExecutor(max_workers=workers)
        futs = [ex.submit(_extract_one, a, _dest_dir(a), seven) for a in level]
        try:
            level_results = [f.result() for f in as_completed(futs)]
        except KeyboardInterrupt:
            procs.cancel_all()                            # kill in-flight 7-Zip
            ex.shutdown(wait=False, cancel_futures=True)  # drop the pending ones
            raise
        ex.shutdown(wait=True)
        results.extend(level_results)

        nxt: list[Path] = []
        for r in level_results:
            if r.ok:
                nxt.extend(_nested_containers(r.dest, processed))
        level = nxt
        depth += 1

    results.sort(key=lambda r: r.archive.name.lower())
    return results


# Loose-drop folder conventions (see the matching detection profiles).
# Accepts a bare numeric suffix too (weblogs1, weblogs2) -- how analysts
# actually name multiple drops. Public: Phase-0 integrity also keys off it.
DROP_DIR = re.compile(r"(weblogs|fortigate)(\d+|[-_].+)?$", re.IGNORECASE)


def extract_drops(root: Path, tools_dir: Path | None = None) -> list[ExtractResult]:
    """Extract archives dropped INSIDE a loose-drop folder (`weblogs[-label]`,
    `fortigate[-label]`), in place.

    Exports arrive zipped and named any which way (`logs_marzo.zip`,
    `export.tar.gz`); the analyst just copies them into the drop folder. The
    generic pass never sees them (it only extracts containers at the case root),
    so this one walks each drop dir (case root + one level down) and extracts
    every container next to itself, one nested level deep (zip inside zip).
    Standalone .gz rotated logs stay compressed (the parsers stream them).
    Idempotent via the same .aeng_extracted_ok marker."""
    seven = find_7z(tools_dir)
    drops = [d for pat in ("*", "*/*") for d in root.glob(pat)
             if d.is_dir() and DROP_DIR.fullmatch(d.name)]
    # `-p` may point AT the drop folder itself (detection matches the root as a
    # machine, so extraction must look there too or its archives never open).
    if DROP_DIR.fullmatch(root.name):
        drops.append(root)
    results: list[ExtractResult] = []
    processed: set[Path] = set()
    for drop in sorted(set(drops)):
        level = [p for p in sorted(drop.rglob("*")) if is_container(p)]
        for _ in range(2):                       # containers + one nested level
            level = [p for p in level if p.resolve() not in processed]
            if not level:
                break
            nxt: list[Path] = []
            for z in level:
                processed.add(z.resolve())
                r = _extract_one(z, _dest_dir(z), seven)
                results.append(r)
                if r.ok:
                    nxt.extend(_nested_containers(r.dest, processed))
            level = nxt
    return results


def extract_velociraptor(
    root: Path,
    tools_dir: Path | None = None,
    names: tuple[str, ...] = VELOCIRAPTOR_ZIPS,
) -> list[ExtractResult]:
    """Extract the wanted Velociraptor sub-collections (LiveResponse.zip) in place.

    These sit at <collection>/Velociraptor/<name> -- too deep for the generic
    nested-container pass, which deliberately stays at the top level. We look only
    where they actually are (collection root and one level down), so we don't
    rglob the whole multi-million-file KAPE tree. Each extracts next to itself
    (LiveResponse.zip -> Velociraptor/LiveResponse/results/*.json) and is
    idempotent via the same .aeng_extracted_ok marker.
    """
    seven = find_7z(tools_dir)
    found: list[Path] = []
    for name in names:
        for pat in (f"Velociraptor/{name}", f"*/Velociraptor/{name}"):
            found.extend(z for z in root.glob(pat) if z.is_file())
    results = [_extract_one(z, _dest_dir(z), seven) for z in sorted(set(found))]
    return results
