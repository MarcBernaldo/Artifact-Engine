"""Handler: YARA over the memory of every process in an image (v0.7.93).

The same rules the disk scan uses (`assets/yara`: the bundled sets plus
signature-base) are compiled once, saved, and handed to Volatility's
`windows.vadyarascan` as a compiled file, which matches them against every
process's virtual memory. Code that never touches the disk -- a reflectively
loaded DLL, a beacon decrypted in place -- is only ever visible here.

Volatility prints one row per matched STRING, so one rule firing in one process
is dozens of rows. The table kept, `mem_yara`, is one row per process and rule:
how many strings matched, a sample of what they were and where, and the rule's
own description, score and reference, read from the compiled rules. That is the
table mem_findings turns into alerts.

A match inside a security product's own process is very often the product's
signatures, not an infection: those rows say so in `in_security_product`, and
the alert built on them is lowered, never dropped.
"""

from __future__ import annotations

import csv
import tempfile
from collections import defaultdict
from pathlib import Path

from artifact_engine.handlers._lincommon import write_csv
from artifact_engine.handlers.lin_yara import _compile_rules
from artifact_engine.handlers.mem_volatility import run_plugin

_PLUGIN = "windows.vadyarascan.VadYaraScan"
_SAMPLES = 5

# Processes of endpoint-security products, as editable name prefixes: what a
# YARA rule matches in their memory is usually the signature it was written from.
ASSET = "security_processes.txt"


def load_security(assets: Path) -> tuple[str, ...]:
    """The prefixes of `assets/security_processes.txt` (lower-case), or ()."""
    try:
        text = (Path(assets) / ASSET).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()
    return tuple(ln.split("#", 1)[0].strip().lower() for ln in text.splitlines()
                 if ln.split("#", 1)[0].strip())


_HEADER = ["pid", "process", "rule", "hits", "samples", "description", "score",
           "reference", "in_security_product"]


def _meta(rules) -> dict[str, dict]:
    """rule name -> its meta, from the compiled set. Volatility reports a match by
    the rule's name alone, so two files defining one name share the first's meta."""
    out: dict[str, dict] = {}
    try:
        for r in rules:
            out.setdefault(r.identifier, dict(getattr(r, "meta", None) or {}))
    except TypeError:                    # an older yara-python cannot iterate rules
        pass
    return out


def run(ctx) -> None:
    rules = _compile_rules(Path(ctx.assets), ctx.log)
    security_prefixes = load_security(Path(ctx.assets))
    meta = _meta(rules)
    with tempfile.TemporaryDirectory(prefix="aeng-yara-") as tmp:
        compiled = Path(tmp) / "rules.yarc"
        rules.save(str(compiled))
        raw = run_plugin(ctx, _PLUGIN, "mem_yara_raw",
                         extra=["--yara-compiled-file", compiled.as_uri()])
    if raw is None:
        return                              # ran, matched nothing
    try:
        hits: dict[tuple, dict] = defaultdict(lambda: {"n": 0, "samples": []})
        with raw.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            for r in csv.DictReader(fh):
                key = (r.get("PID") or "", r.get("ImageFileName") or "", r.get("Rule") or "")
                h = hits[key]
                h["n"] += 1
                if len(h["samples"]) < _SAMPLES:
                    h["samples"].append(f"{r.get('Component', '')}={r.get('Value', '')[:60]}"
                                        f"@{r.get('Offset', '')}")
    finally:
        raw.unlink(missing_ok=True)         # the per-string table is not kept
    rows = []
    for (pid, proc, name), h in sorted(hits.items(), key=lambda kv: (-kv[1]["n"], kv[0])):
        m = meta.get(name, {})
        security = bool(security_prefixes) and proc.lower().startswith(security_prefixes)
        rows.append([pid, proc, name, h["n"], " | ".join(h["samples"]),
                     str(m.get("description", ""))[:300], m.get("score", ""),
                     str(m.get("reference", ""))[:200], "yes" if security else ""])
    write_csv(ctx.out, "mem_yara.csv", _HEADER, rows)
