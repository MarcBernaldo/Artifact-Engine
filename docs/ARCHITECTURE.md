# Artifact Engine — Architecture & Contributor Guide

Single-sheet context for the project. Read this and you have enough to extend it.
DFIR triage tool: it takes a folder of acquisitions (KAPE on Windows, UAC on
Linux), extracts them, detects each machine, runs a set of forensic parsers in
parallel, and consolidates everything per machine into `.db` + `.xlsx` +
`report.txt`.

---

## 1. Run it

```
aeng setup                 # download external binaries into the tools/ dir
aeng run -p <evidence_dir> # full pipeline over a folder of acquisitions
aeng run -p <dir> --force  # re-parse even if already done
aeng lateral -p <dir>      # rebuild only lateral_movement.csv/.html (phase 5) from existing outputs
aeng list-parsers          # every loaded parser (id, os, cmd/py, description)
aeng list-profiles         # every loaded detection profile
```

`aeng` == `artifact-engine` == `python -m artifact_engine`. Flags: `-c config.yaml`,
`-v` verbose.

---

## 2. Pipeline (cli.py `cmd_run`)

| Phase | Module | What it does |
|------|--------|--------------|
| 0 Integrity | `core/hashing.py` | SHA256 of every original file → `traces.txt` (before touching anything). |
| 1 Extraction | `core/extractor.py` | Decompress acquisitions (zip/tar/7z, nested up to `extract_depth`), parallel. Phase 1c (`extract_drops`) additionally unpacks containers dropped inside loose-drop folders (`weblogs*`/`fortigate*`, see §10) in place. |
| 2 Detection | `core/detector.py` | Walk the tree, match `data/profiles/*.yaml`, produce `Machine` objects (OS, collector, volumes). VSS snapshots are pruned, optionally attached as their own machines. Console labels encode provenance so a hostname is never shown bare-and-repeated: `HOST` (live disk), `HOST-VSS<n>` (shadow-copy snapshot), and a `-LR` tag when the host also carries Velociraptor LiveResponse (parsed on the live volume, not a separate machine); same-host collisions fall back to the acquisition date. |
| 3 Parsing | `core/scheduler.py` + `core/runner.py` | One global pool runs every (machine × volume × parser) task, interleaved across machines, ordered by `depends_on` level. Pure-Python handlers run in a process pool (`parse_processes`, real parallelism past the GIL); external-tool parsers stay on threads. |
| 4 Consolidation | `core/consolidate.py` + `core/report.py` | Parallel across machines (process pool when >1 machine + `parse_processes`, else threads; live per-machine progress bars): every `CSVs/**/*.csv` (excluding any nested `VSS<n>/` subfolder -- VSS snapshots are their own machines) and LiveResponse `JSONs/*.json` → `<machine>.db` (SQLite) and `<machine>.xlsx` (same set, except sheets past Excel's row limit → `.db` only), selectable via `emit_db`/`emit_xlsx`, plus `report.txt`. Then a root-level `run-summary.{txt,json}` rolls up all machines. |
| 5 Lateral movement | `core/lateral.py` | Cross-machine logon correlation (Security 4624/4625/4648, Kerberos 4768/4769) → `lateral_movement.csv` (full edge list) + `lateral_movement.html` (self-contained force-directed graph, no libraries). Hosts matched by IP/name from `machine_info.json`; RDP / explicit-cred / failed / case-to-case / anonymous-logon edges flagged; external sources kept. Account labels are canonicalised (`<NETBIOS_UPPER>\<user_lower>`, so `CORP\Administrator` / `corp\administrator` / `CORP.LOCAL\Administrator` merge into one edge/actor, while a different domain stays distinct). A null-session network logon (`ANONYMOUS LOGON`) gets reason `anonymous_logon` (enumeration / SMB-relay IOC). Off-case graph nodes split by role — `server` (reached by NAME, an internal box the admin hit) vs `external` (a bare source IP) — so targets and attacker origins read apart. The top-`_MAX_EXTERNAL` volume cap never culls an external touching a high-signal edge (`_HIGH_SIGNAL`: brute-force / anonymous / pivot / chainsaw / explicit-cred), so a one-shot attacker IP always stays. RDPClient dial-outs (1024/1102) attribute their account by resolving the event's `UserId` SID through the machine's ProfileList (`reg_profList.csv`) — the channel logs in the user's session, so `UserName` is always empty. Edges are enriched with matching **chainsaw** rule verdicts (e.g. "Account Brute Force", "RDP Logon") from the per-machine `chainsaw_*` CSVs (`chainsaw` column), and a 4769 service ticket for a host SPN (`HOST$`) is drawn source→that host rather than source→DC. **Pivot chains**: an inbound logon onto an acquired host paired with outbound activity from it by the same account within a window (X→B→Y) marks both edges `chain` and is listed in the graph's "Attack paths" panel. The HTML is interactive: direction arrows on curved edges, search by user/host, filter by logon category (colour-coded failed/explicit/rdp/runas/kerberos/network) and a time-range slider with chronological playback, wheel zoom + pan, per-edge username + date labels, and a chronological timeline sidebar. VSS snapshots are skipped (point-in-time copies of the live host would duplicate every edge). Full detail: [LATERAL_MOVEMENT.md](LATERAL_MOVEMENT.md). |

Per-parser failures are isolated: one crash never aborts the run; it is recorded
in `run.json`, the machine's `report.txt`, and the root `run-summary.{txt,json}`
(per-machine ok/skip/err, slowest parser, full error list).

---

## 3. Layout

```
src/artifact_engine/
  cli.py                 entry point (run/setup/list-*)
  config.py              Config + path resolution (tools/parsers/profiles/assets dirs)
  models.py              pydantic manifests: ParserManifest, ProfileManifest, Tool, ToolSource
  registry.py            load + validate the YAML manifests
  core/
    hashing extractor detector scheduler runner consolidate report
    lateral.py           phase 5: cross-machine logon graph (csv + html)
    sigma_engine.py      compile SigmaHQ rules to SQLite queries (pysigma)
    downloader.py        fetch_tool() + asset fetchers for `aeng setup`
    procs.py             subprocess wrapper (timeouts, Ctrl+C cancel)
  handlers/              Python parser handlers (win_* / lin_*), see §6
  data/
    parsers/windows/*.yaml
    parsers/linux/*.yaml
    profiles/*.yaml
    sigma/{linux,web}/   bundled SigmaHQ rule snapshots (pinned in sigma/VERSION)
    assets/              RECmd batches (.reb), detection lists (lolbas/loldrivers/
                         rmm), analyst-editable indicator lists (web_suspicious.txt,
                         suspicious_tools.txt -> CUSTOM_DETECTIONS.md), offline geo
                         (db-ip mmdb + Tor exits, via `aeng setup`), yara/
  tools/                 downloaded binaries (gitignored except vendored scripts)
tests/                   pytest suite (local-only: gitignored, not published)
```

Config defaults (`config.py`): `tools_dir = <pkg>/tools`, parsers/profiles/assets
under `<pkg>/data`. A `parsers/` or `profiles/` folder **in the current working
directory overrides** the bundled ones (same filename wins) — drop-in custom
parsers without touching the package.

---

## 4. The parser manifest (`models.py: ParserManifest`)

```yaml
id: <unique id>                 # required; idempotency marker + report key
name: "Human name"
description: "One line"
os: windows | linux | any       # gates which machines it runs on
category: execution             # → output subfolder (see §7)
short: ""                       # prefix for multi-output tools (see §5)
requires: ["rel/path", ...]     # ALL must exist on the volume or the parser is skipped
provides: [logical_node]        # dependency-graph node names
depends_on: [other_id]          # parsers that must finish first
timeout: 600                    # seconds
on_vss: true                    # false = skip on VSS snapshot machines (heavy parsers
                                # whose output ~equals the live volume's, e.g. mft_transcode)

# EXACTLY ONE executor:
#  (a) external binary
tool:
  binary: Tool.exe              # path under tools_dir
  source: { ... }               # see §8; only needed for `aeng setup`
command:                        # list form preferred (robust with spaces)
  - "{binary}"
  - "-f"
  - "{evidence}/path/to/artifact"
  - "--csv"
  - "{out}"
#  (b) python handler
handler: "artifact_engine.handlers.<module>:<func>"

outputs:                        # optional, documentary
  - { path: "{out}/x.csv", format: csv }
```

Placeholders in `command`: `{binary} {evidence} {out} {tools} {assets} {machine}`.
Validation: exactly one of `command`/`handler`; `command` requires `tool`. A bad
manifest is logged and skipped — it never half-breaks a run.

`requires` paths are relative to the **volume root** (e.g. the `C` drive folder, or
the UAC root). They gate triggering; the handler/tool should still no-op cleanly if
the artifact turns out to be absent or empty.

---

## 5. Naming conventions (IMPORTANT — follow exactly)

### Handler files (`handlers/`, one flat dir → need an OS prefix)
`win_<artifact>.py` or `lin_<artifact>.py`, short artifact name, exposing `def run(ctx)`
(or named functions for a shared source — `win_wmi.py` has `persistence` + `ccm_rua`).
Shared non-handler helpers use a leading underscore (`_lincommon.py`).

Examples: `win_browser.py`, `win_wmi.py`, `win_pca.py`, `win_wer.py`, `win_deepblue.py`,
`lin_bash.py`, `lin_users.py`, `lin_cron.py`, `lin_ssh.py`, `lin_wtmp.py`,
`lin_network.py`, `lin_logins.py`, `lin_processes.py`, `lin_machineinfo.py`, `lin_anomalies.py`.

### Parser YAML files (`data/parsers/{windows,linux}/` — already OS-foldered → NO OS prefix)
Filename starts with the **artifact**. If several tools each parse one slice of an
artifact, add a detail suffix:

```
evtx_rdp_auth.yaml  evtx_rdp_in.yaml  evtx_system.yaml   (windows)
reg_bamdam.yaml     amcache.yaml      prefetch.yaml
bash.yaml  users.yaml  cron.yaml  ssh.yaml  wtmp.yaml     (linux)
network.yaml  logins.yaml  processes.yaml  machineinfo.yaml  anomalies.yaml
```

Linux files **never** start with `linux_`; keep them short (`bash.yaml`, not
`linux_bash_history.yaml`).

**Filenames must be unique across BOTH OS folders.** `registry._load_yaml_dir`
dedups by basename (the override mechanism: a user parser dir replaces a bundled
parser by same filename), so `windows/x.yaml` and `linux/x.yaml` would collide
and one is silently dropped. The one artifact that exists on both OSes — YARA —
is therefore `linux/yara.yaml` (id `yara`) and `windows/win_yara.yaml` (id
`win_yara`). `test_bundled_parsers_load` guards this (every yaml → a loaded
parser; no duplicate filename or id).

### Output CSV names: same convention as the YAML
Artifact-first, short, English. One artifact → one (or few) clean CSV(s):
- Single-output tool that honors `--csvf` → set the final name directly
  (`--csvf prefetch.csv` → `prefetch.csv`).
- Multi-output tool that can't be told the name → set `short:` and the runner
  prefixes/renames every produced CSV to `<short>_<subtype>.csv`
  (e.g. `short: srum` → `srum_NetworkUsages.csv`; `short: search` for SIDR).
- Handlers name their files directly (`browser_history.csv`, `wmi_persistence.csv`,
  `bash.csv`).

`runner._clean_output_names()` does the tidy-up on success: strips EZ timestamp
prefixes and `_Output`, drops RECmd's redundant `<timestamp>/` subfolder, and
applies `short`.

**Isolation (important):** every parser runs into a private `.work_<id>/` dir;
`short`/cleanup apply only to that dir, then the results are merged into the shared
category folder. So parsers of the same category running in parallel (the global
pool) can never rename each other's outputs — a `short` parser only ever touches
its own files.

### IDs
Match the artifact (`bash`, `wmi_persistence`, `evtx_security`). Must be globally
unique across both OS folders.

### Timestamp columns: label the basis with a suffix
A date/time column carries a `_utc` or `_local` suffix so the analyst never has to
guess the zone (no concrete TZ in the header — `machineinfo.timezone` resolves what
"local" is for that host):
- `_utc` — value is derived from an epoch and rendered UTC (`fromtimestamp(sec,
  tz=timezone.utc)`): `wtmp/btmp.time_utc`, `packages.install_time_utc`,
  `bodyfile.{atime,mtime,ctime,crtime}_utc`, `fortigate.time_utc`.
- `_local` — passthrough of a tool that renders in the host's local zone with no
  offset in the string: `last`/`lastb`/`lastlog` (`logins.{start,end}_local`,
  `lastlog.latest_local`), `ps` (`processes.started_local`), package logs
  (`pkg_history.time_local`).
- No suffix when the basis is source-dependent or the offset is already in the
  value: `web_access.time` / `huntweb.time` (the `+ZZZZ` offset is kept in every
  value by `_webcommon._iso_time`), `auth.timestamp` (syslog local **or** RFC3339
  with offset — as-logged), `sigma.timestamp` (raw passthrough of the matched log).
  `machineinfo.boot_time` stays as-is: it is a key/value row sitting next to the
  `timezone` field, and its JSON key is a `core/report.py` contract.

A full sweep of the ~35 `lin_*` handlers confirms these are the only date-bearing
columns; the rest (anomalies/services/persistence/etc.) carry no timestamp column.

---

## 6. Python handler contract (`runner.ParserContext`)

```python
def run(ctx) -> None:
    # ctx.evidence : Path  volume root, READ-ONLY (never write here)
    # ctx.out      : Path  output folder for this category (create + write CSVs here)
    # ctx.tools    : Path  binaries dir
    # ctx.assets   : Path  rules/wordlists dir
    # ctx.machine_name, ctx.volume : str
    # ctx.log      : logger
    ...
```

Write one CSV per artifact into `ctx.out`. Wrap risky parsing so the handler
degrades to an empty/partial CSV instead of raising (a raise → the parser is marked
`error`, not fatal).

---

## 7. Categories → output folders (`scheduler._CATEGORY_DIR`)

```
filesystem→Filesystem  execution→Execution  eventlogs→EventLogs
registry→Registry  systeminfo→SystemInfo  shell→Shell
browser→Browser  persistence→Persistence  search→Search
network→Network  processes→Processes  detections→Detections  web→Web
```

A category not in the map becomes a folder of that literal name. **Add new
categories here** so the output folder is named nicely. Consolidation globs
`CSVs/**/*.csv` recursively, so a new folder needs nothing else. Special case:
`liveresponse` writes to `JSONs/` (sibling of `CSVs/`, JSON-native, consolidated
from there).

---

## 8. External tools & `aeng setup` (`models.ToolSource`, `core/downloader.py`)

```yaml
tool:
  binary: sidr.exe
  source:
    repo: owner/name          # GitHub: latest release...
    asset: sidr.exe           # ...asset with this exact name
    # or: url: "https://.../tool.zip"
    sha256: "<hex>"           # optional integrity check (recommended)
    unpack: true              # zip → extract
    unpack_dir: subfolder     # isolate DLLs under tools/<subfolder>
    rename_to: downloaded.exe # rename to `binary` after download
```

`setup` collects every `tool` with a `source`, downloads only what's missing, and
writes a default `config.yaml` (`max_workers` = CPU count). Network failures are
best-effort: setup continues.

**`sha256` and the lockfile.** Declaring `sha256` hard-verifies the download and is
right for *pinned* release assets. Most tools here (EZ net9, chainsaw/SIDR `latest`)
ship from rolling URLs, so hard-pinning would break `setup` on every upstream
release. Instead `setup` writes `tools/tools.lock.json` recording the sha256 + size
+ source of every ready binary — an audit trail of exactly which tool builds ran
(DFIR defensibility), without blocking updates.

Besides `tool` sources, `setup` also fetches (best-effort, all optional at run
time): the **offline geo assets** for the web/netstat origin columns
(`fetch_web_assets`: db-ip country + ASN lite mmdb, Tor exit list → `assets/`),
the **YARA signature-base** ruleset (`fetch_yara_rules` →
`assets/yara/signature-base/`), and **hayabusa** (version-stamped release asset
resolved via the API → `tools/hayabusa/`). Missing assets degrade gracefully
(country `?`, no Tor tag, bundled-rules-only YARA).

---

## 9. Adding a parser — step by step

### A. Python handler (preferred for SQLite / INI / text / binary carving, or when the reference tool is Python-2)

1. Create `handlers/win_<artifact>.py` (or `lin_<artifact>.py`) with `def run(ctx)`.
   Write `<artifact>.csv` (+ extra sub-artifact CSVs) into `ctx.out`.
2. Create `data/parsers/<os>/<artifact>.yaml`:
   ```yaml
   id: <artifact>
   name: "..."
   description: "..."
   os: windows
   category: execution
   requires: ["relative/path/that/must/exist"]
   handler: "artifact_engine.handlers.win_<artifact>:run"
   ```
3. New category? add it to `scheduler._CATEGORY_DIR`.
4. Add a unit test in `tests/test_parsing.py` (build a tiny fixture under `tmp_path`,
   call the handler with `_ctx(...)`, assert on the CSV).

### B. External binary (compiled tools with no Python equivalent: EZ tools, chainsaw, SIDR)

1. Create `data/parsers/<os>/<artifact>.yaml` with `tool` + `command` (list form).
2. Single output → `--csvf <artifact>.csv`. Multi output → `short: <artifact>`.
3. Verify the release `asset` name (`gh api repos/<repo>/releases/latest` or the
   API URL) so `setup` resolves it. Pin `sha256` if you can.

Decision rule: **handler when the format is parseable in Python or the reference
tool is Python-2 (won't run on 3.10) — reimplement it natively and credit the
author. Download a binary only for heavy compiled tools.**

---

## 10. Detection profiles (`data/profiles/*.yaml`)

```yaml
id: windows_kape
os: windows
collector: kape
detect:
  any_of: [{ exists: "$MFT" }, { glob: "Windows/System32/config/SYSTEM" }]
machine_name: { strategy: acquisition, regex: "([^_]+)_.*", fallback: dir_name }
```

`detect` uses `any_of`/`all_of` of `exists`/`glob`/`dir_name` clauses (`dir_name`
= regex the candidate FOLDER NAME must match, case-insensitive — for
convention-based drops). `machine_name` strategies:
`parent_dir | dir_name | file | acquisition`.

### Loose drops (`weblogs` / `fortigate` profiles)

Logs don't always arrive inside an acquisition (a hosting export, a firewall
export a sysadmin hands over). Convention: drop them in a folder named
**`<kind>`** or **`<kind>-<label>`** at the case root; each folder becomes its
own machine and consolidates into its own `.db`/`.xlsx`:

```
C:\Cases\mi-caso\
  uac-server1-.../                  <- normal acquisition
  weblogs-www.client.com\           <- Apache/nginx access logs
    www_client_com.log              <- any file name works
    vhost-ssl\access.log.1.gz       <- subdirs + rotations too
    EXPORT_2026.zip                 <- zipped exports (any name) auto-extracted
  fortigate-fw-perimetral\          <- FortiGate/FortiOS key=value logs
    LOGS_FW_2019.zip
```

- **weblogs**: `web_access` (full timeline) + `huntweb` (attack hunt) +
  `web_metrics` (audit aggregations) + `web_sigma` (SigmaHQ web ruleset) run over
  EVERY file (non-CLF lines parse to 0 rows). Format = Apache/nginx CLF/combined
  (IIS W3C would be a new parser). **X-Forwarded-For**: behind a reverse proxy /
  CDN the connecting `%h` is the frontend, so a trailing `X-Forwarded-For="…"`
  field (when logged) is parsed and its leftmost hop becomes the record `ip` (the
  real client) — the proxy is kept in a separate `edge_ip` column. Every consumer
  attributes to the client automatically; without XFF the connecting host is used
  as before. (`_webcommon.parse`; XFF is client-settable, extracted only from the
  tail after the combined fields so a URL/UA can't spoof it.)
  `huntweb` fires the built-in payload signatures on served (200) requests **and**
  the analyst-editable `assets/web_suspicious.txt` indicators on any status
  (scanner UAs, web-shell / secret paths, miners…). That file is a plain list —
  `label = regex`, one per line, read every run — loaded via
  `handlers/_indicators.py` (reusable by any handler that wants its own IOC list).
  Keep additions low-FP: anchor to a web-executable extension or a specific tool,
  never a bare `shell.` (matches `shell.png`). `web_sigma` scores the same logs
  with the bundled SigmaHQ webserver ruleset (see §Sigma detections).
- **fortigate**: the `fortigate` parser (lin_fortigate) probes each file's
  first line for the FortiOS shape and builds one flagged timeline
  (`fortigate.csv`, category network): `time_utc` from `eventtime` (any FortiOS
  epoch precision), glued records split, and `flag` = utm_<subtype> for
  firewall detections (blocked / high risk), admin_login[_failed], auth_failed,
  sslvpn_session. Two on-disk shapes are read transparently: raw syslog
  (`date=… key="value"`) and the **FortiAnalyzer CSV export** (one record/line,
  each field a quoted `key=value` cell, no header) — the latter parsed with the
  csv module (`csv_ok=True` keeps `.csv` in the fallback; string values keep and
  are stripped of their inner doubled quotes).

Shared plumbing: detection = `dir_name` clause + non-empty (a `fortigate[-label]`
/ `weblogs[-label]` folder, numeric suffix allowed). Zipped exports
(`.zip/.tar.gz/.7z`, any name) inside a drop are auto-extracted in place by
`extractor.extract_drops` (cli phase 1c, one nested level, idempotent);
standalone `.gz` rotations stay compressed and are streamed. File discovery =
`iter_access_files`' fallback: when the evidence has no `[root]/` and the
standard `var/log` bases yielded nothing, the whole tree is offered (`error*`,
configs, containers, non-CLF text and the tool's own outputs excluded; binary
files sniffed out by a NUL-byte check; `.csv` kept for the fortigate parser via
`csv_ok`).

**Input contract (naming is the trigger).** A drop is recognised purely by the
FOLDER NAME matching `(weblogs|fortigate)(<num>|[-_]<label>)?` (case-insensitive:
`weblogs`, `weblogs2`, `weblogs-www.client.com`, `fortigate-fw-edge`). There is
deliberately **no content heuristic** — sniffing arbitrary folders for "looks
like a log" would misfire against the KAPE/UAC detection and raise false
positives; a one-word folder name is a cheaper, predictable contract. The two
delivery shapes converge on the same machine:

- **already a folder** (`weblogs-x/` with loose logs, subdirs, rotations, and/or
  inner `.zip`s): detected directly; inner containers opened by phase 1c.
- **a container at the case root** (`weblogs-x.zip`, `.tar.gz`, `.7z`): phase 1
  extracts it to `weblogs-x/` (dest = stem), which then detects identically.

So a folder named off-convention (`web-logs/`, `apache/`, `access_logs/`) is
**not** picked up — rename it to the convention. This is the whole contract.

**Phase-0 integrity of drops.** Phase 0 runs *before* extraction, so a delivered
`weblogs-x.zip` is hashed as the single container it is (cheap). An *uncompressed*
drop folder is hashed file-by-file — thousands of rotated logs — because those
files ARE the evidence in a web/firewall case and their hashes belong in the
chain of custody (`traces.txt/csv`). Set `traces_include_drops: false` to skip
the files *inside* drop folders when that custody isn't required; only the first
path component is tested, so a real acquisition that merely contains a
`var/log/...` path is never affected, and root-level containers are always
hashed. Default is `true` (custody-first).

---

## 11. Testing

```
python -m pytest -q          # from the repo root
```

The `tests/` tree is kept local (gitignored — not part of the published repo).

`tests/test_parsing.py` covers argv building, idempotency, output-name cleaning,
consolidation, and each native handler; `test_scheduler.py` the pool planning and
topo-order; `test_lateral.py` the logon graph; `test_console.py`/`test_extractor.py`/
`test_hashing.py` the UX, extraction and integrity phases. `test_bundled_parsers_load`
asserts every shipped manifest validates and loads (no duplicate filenames/ids
across OS folders) and key ids are present — **add your new id there** when you add
a parser. Handler tests build fixtures under `tmp_path` and call the handler
directly via `_ctx(evidence, out)`.

---

## 12. Best practices & gotchas

- **Evidence is read-only.** Handlers write only to `ctx.out`. Open SQLite with
  `?immutable=1` (see `win_browser.py`) so no `-wal`/`-journal` is ever created.
- **Filename uniqueness across OS folders.** `registry._load_yaml_dir` dedupes by
  *filename* across `windows/` + `linux/` (that's how cwd overrides work). Two
  parsers with the same filename collide — keep artifact names distinct.
- **Encoding.** Text artifacts (PCA, WER) are UTF-16-with-BOM: decode by BOM, never
  blindly try `utf-16` first (it guesses endianness). Binary carving (WMI) decodes
  the whole blob as `latin-1` (1 byte ↔ 1 codepoint) so NUL-delimited fields survive
  and re-encode losslessly for `struct`.
- **Idempotency.** Success writes `ctx.out/.<id>.done`; a present marker → skip
  unless `--force`.
- **Consolidation: no size filter.** Every CSV goes into BOTH the `.db` and the
  `.xlsx`. Only sheets beyond Excel's hard limits (1,048,576 rows / 16,384 cols,
  e.g. a multi-million-row MFT or USN) are skipped from the `.xlsx` and stay in the
  `.db` (xlsxwriter `constant_memory` keeps big sheets from blowing up RAM). Table/
  sheet names are clamped to 31 chars. Oversized integers (Amcache `uint64` IDs >
  SQLite int64) make `to_sql` fail; the table is retried with all columns as text
  instead of dropped/partial. Genuinely empty CSVs (e.g. a DeepBlue log with no
  hits) have no header → no table.
- **Consolidation: outputs & speed.** `emit_db`/`emit_xlsx` (both default on) pick
  which artifacts to build; each input is read once and fed to whichever output is
  enabled. The `.xlsx` pass dominates — ~68% of consolidation time, as xlsxwriter
  writes cell by cell — so `emit_xlsx: false` is the biggest single speed-up when
  only the `.db` is needed. Across machines the work runs in a **process pool** (the
  `.xlsx` pass is pure-Python/GIL-bound, so threads barely overlap; ~2× on 4 real
  machines), each writing its own `.db`/`.xlsx`. The `.db` is rebuilt every run, so
  it is opened with `synchronous`/`journal` `OFF` (a derived artifact — durability is
  irrelevant; the gain is marginal as `to_sql` is bound by pandas, not disk).
- **Dirty ESE databases.** ESE DBs collected live (SUM `.mdb`, and potentially the
  Search `Windows.edb`) are in a dirty-shutdown state; SumECmd refuses them yet
  exits 0 (a plain command parser would silently produce nothing). The `sum`
  handler copies them to a temp dir and runs `esentutl /r` + `/p` (recover/repair)
  before SumECmd — never touching the evidence. Apply the same recipe if SIDR
  (Windows.edb) hits it.
- **Timeouts.** Set `timeout` realistically (SRUM/Search index/MFT are slow).

---

## 13. Current parsers (run `aeng list-parsers` for the live list)

- **Windows filesystem**: mft_transcode ($MFT, MFTECmd), usn ($J/UsnJrnl), lnk
  (LECmd), jumplists (JLECmd), recyclebin (RBCmd).
- **Windows execution**: amcache, appcompatcache (shimcache), prefetch, srum, pca,
  wer, wmi_ccm_rua (SCCM RUA), timeline (per-user ActivitiesCache.db — apps run,
  files opened, focus duration — parsed natively from the SQLite store), bits
  (BITS transfer jobs carved from qmgr.db/qmgr*.dat — source URL → local path,
  a common download-persistence channel), recentfilecache (Win7), consolehost
  (per-user PSReadLine `ConsoleHost_history.txt` — full interactive PowerShell history).
- **Windows event logs**: evtx_* (security, system, application, powershell[_scripts],
  rdp_auth/in/out/session, tasks, wmi, bits, defender, sysmon), chainsaw_sigma
  (Chainsaw+Sigma hunt), hayabusa (Sigma detection timeline + logon summary +
  base64 extraction), deepblue (DeepBlueCLI).
- **Windows registry**: reg_bamdam, reg_services, reg_userassist, reg_runmru,
  reg_scheduledtasks, reg_profilelist, reg_users, reg_shellbags,
  reg_rdp_outbound (per-user Terminal Server Client MRU — where each user RDP'd
  TO), reg_explorer_input (WordWheelQuery Explorer searches + TypedPaths).
  (Run-key autoruns are folded into the reg_persistence detector below.)
- **Windows persistence**: wmi_persistence (FilterToConsumerBindings from
  OBJECTS.DATA), tasks_disk (every task XML under `System32/Tasks` — independent
  of the TaskCache registry and the task event log), sysvol (domain-controller
  `Windows/SYSVOL`: Group Policy Preferences — scheduled tasks/groups/services
  pushed domain-wide, with the GPP cpassword decrypted per MS14-025 — and
  logon/logoff/startup/shutdown script assignments; `requires: Windows/SYSVOL`
  scopes it to DCs, `on_vss: false`).
- **Windows other**: browser (Chrome/Edge/Brave/Firefox history+downloads),
  search_index (SIDR), sum (SumECmd, server UAL), win_machine_info (hives →
  `machine_info.json`, feeds report.txt and lateral).
- **Windows detections**: yara (bundled + signature-base); rmm -- RMM / remote-
  access tools (AnyDesk, TeamViewer, ScreenConnect, DameWare, ...) seen on disk via
  Amcache, fingerprints curated from LOLRMM (dual-use, surfaced for the analyst to
  confirm authorisation); byovd -- known vulnerable/malicious kernel drivers matched
  by Amcache SHA1 against the LOLDrivers hash set (exact hash, near FP-free; flags a
  renamed sample); lolbas -- a LOLBAS binary (certutil, mshta, ...) found via Amcache
  in a user/attacker-writable staging dir (relocation out of System32; in-place
  command-line abuse is caught live by the LiveResponse LOLBIN check); reg_persistence
  -- native hive scan (python-registry) of the registry ASEPs (Run/RunOnce across
  SOFTWARE + every user's NTUSER.DAT, Winlogon Userinit/Shell, AppInit/AppCert DLLs,
  IFEO debuggers, LSA packages, BootExecute, Command Processor AutoRun, netsh helpers,
  time providers, COM hijacks, logon scripts, Active Setup), the Windows sibling of
  lin_persistence -- superseding the old Run-only RECmd AutoRuns batch. Run keys are
  surfaced in full but flagged only on staging/cradle; fixed-default ASEPs only on
  deviation.
- **Windows (Velociraptor live response)**: the volatile state disk parsers can't
  see -- processes, netstat, listening ports, services, tasks, drivers, WMI,
  DNS/ARP, sessions, local admins/shares/hosts -- normalised to `JSONs/` and
  per-row flagged (low-FP), with a derived `suspicious.json`. netstat carries
  offline ASN/country/origin context columns and flags an ESTAB peer only when it
  is Tor or a documented bulletproof AS (major clouds stay context, not flags).
- **Linux logs / timelines**: auth (sshd/sudo/su/useradd from
  auth.log/secure/messages), wtmp + btmp (login history / failed attempts,
  epoch→UTC), logins (last/lastb/lastlog incl. failed), sudo_log (every sudo
  invocation when sudoers logs to a file), cron_log (what cron actually RAN —
  the `cron` parser covers what is *scheduled*), pkg_history (apt/dpkg/zypp/dnf
  install/remove timeline, flags offensive tooling), bodyfile (UAC mactime →
  filesystem MAC timeline, streamed), bash (per-user shell history incl.
  zsh/sh/ash), cron (crontab/cron.d/user spools).
- **Linux system state (UAC live response)**: network (ss/netstat + owning
  process), sessions (active logins at acquisition + unix sockets in
  world-writable temp), known_hosts (outbound SSH targets per account —
  lateral-movement map), processes (ps + PIDs hidden from ps), proc_anomalies
  (memfd/temp-dir exes, rootkit/fileless hunt), machineinfo
  (hostnamectl/os-release → machine_info.json, enriches report.txt), users
  (/etc/passwd), ssh (authorized_keys per user), packages (dpkg/rpm inventory +
  `-V` integrity), hashes (executable md5/sha1 for IOC), anomalies (hidden
  files/dirs, capabilities, unknown owners), kernel (lsmod + taint decode, flags
  rootkit-relevant taint), netconfig (hosts/resolv/hosts.allow-deny, flags
  sinkholes), auditd_config (audit coverage + weakened settings), log_integrity
  (anti-forensics: emptied/truncated logs, present/missing inventory), ebpf
  (loaded programs + pinned objects — eBPF implant persistence), suid
  (SUID/SGID inventory, flags GTFOBins-exploitable).
- **Linux persistence**: persistence (systemd units, init.d, rc.local, shell
  profiles, autostart, ld.so.preload, sudoers, PAM, motd, …), services (runtime
  list-units/list-timers, flags not-found units).
- **Linux web** (also the `weblogs` drop, §10): web_access (full request
  timeline), huntweb (attack hunt + `web_suspicious.txt` indicators), web_metrics
  (the classic audit queries as ready-made CSVs, one streaming pass:
  `web_ip_stats` per-IP volume/status/odd-methods/payload-hits ranking,
  `web_404_paths` recon-target ranking, `web_auth_fail` 401/403 brute-force
  clusters per ip+path). The same pass also emits `web_metrics.html` at the
  machine root: a self-contained cross-filtered panel (KPIs, daily timeline,
  volume×error scatter, Natural Earth choropleth from `assets/world_map.json`,
  sortable IP table with per-IP detail: daily sparkline, captured payload
  samples, own 404s and auth failures). One shared filter state (search
  ip/ASN/country, flag+origin chips, country click, day click) recomputes every
  panel; zero external requests, opens on an air-gapped box (template in
  `handlers/_web_report.py`). Full detail: [WEB_METRICS.md](WEB_METRICS.md).
- **Linux detections** (→ Detections/): yara (bundled + signature-base over
  staging dirs); gtfobins -- GTFOBins abuse in shell history, matching the
  exploitation fragment that turns find/awk/vim/tar/python/... into a shell
  escape, reverse shell or privesc (a plain `find` or `sudo vim file` stays
  quiet; the sudo column marks root privesc); webshells (web-root scan for
  webshell/backdoor patterns: PHP/JSP/ASP/CGI, .htaccess handlers); mdatp
  (Defender for Endpoint state: health, threats/quarantine, exclusions); sigma
  (SigmaHQ Linux ruleset over raw auditd + syslog); web_sigma (SigmaHQ webserver
  ruleset over access logs, aggregated per rule+source IP). Both sigma engines
  in §14.

EZ Tools coverage is complete for disk triage: EvtxECmd, RECmd, AmcacheParser,
AppCompatCacheParser, PECmd, SrumECmd, MFTECmd ($MFT + $J), SBECmd, LECmd, JLECmd,
RBCmd, SumECmd, RecentFileCacheParser. Deliberately excluded: bstrings / rla
/ VSCMount / iisGeoLocate (utilities, not artifact parsers) and SQLECmd (generic
map-driven framework, not a single artifact).

---

## 14. Next steps / open items

**Current state**: 92 parsers (54 Windows / 38 Linux), 4 detection profiles, full
suite green. Windows disk + live-response, Linux/UAC and the web/firewall drops are
shipped and validated on real evidence (§13). Waves beyond the original "close
Windows" P1 (all done): LOL detections (rmm / byovd / lolbas / reg_persistence /
win_yara); the Velociraptor live-response layer with per-row flags, a derived
`suspicious.json` and cross-artifact `correlation.json` (process ↔ tree ↔
connections/listeners ↔ launching service/task); the cross-machine lateral-movement
graph (Security + source-side RDP-MRU / TypedPaths / rdpOut, multi-DC); the F1
console/RDP-MRU/on-disk-tasks/WordWheel/sudo/cron parsers; and the loose-drop
machines (`weblogs`, `fortigate`). Pipeline hardening: per-parser `.done`
fingerprint (only a changed parser re-runs on `aeng run`), streamed `.xlsx`.

Genuinely still open (need evidence or are nice-to-have):

- **Validate timeline/pca/wer/search** (needs evidence): re-collect with
  a KAPE target that includes ActivitiesCache.db, `appcompat/pca/PcaAppLaunchDic.txt`,
  `ProgramData/.../WER`, and `Windows.edb`/`Windows.db` on a Win11 22H2+ host with
  Search indexing + WMI (e.g. `!SANS_Triage` + `WindowsSearchIndex`). Binaries (incl.
  SIDR) are present; the parsers are wired and unit-tested, only un-exercised on real
  artifacts.
- **WMI CCM RUA**: the null-delimited binary-header path (timestamps/launch-count via
  `struct`) is ported but unit-tested only on the XML path — validate against a real
  Vista+ `OBJECTS.DATA` sample.
- **PCA**: optionally also parse `PcaGeneralDb0.txt` (schema is less documented — only
  add if confident, wrong columns are worse than none).
- **Browser**: Firefox downloads (moz_annos / `downloads.sqlite`) not yet parsed.
- **SIDR**: confirm the produced report CSV names on real evidence; `short: search`
  normalizes them but the subtypes are unverified.
- **Integrity**: pin `sha256` on the downloaded tools (EZ, chainsaw, SIDR) once known.

### P2 — Linux/UAC coverage (in progress)

Validated on 3 real UAC acquisitions (SUSE 15 and Ubuntu 22.04 / 24.04):
10 parsers/machine, 29 ok / 1 skipped / 0 errors, `.db`/`.xlsx` parity holds. The
one skip (`users`) is correct — that collection did not capture `/etc/passwd`.

Wave 1 shipped (highest IR value, all text, distro-agnostic): **network, logins,
processes, machineinfo, anomalies** (see §13). `machineinfo` now produces
`machine_info.json`, so `report.txt` shows OS/IPs/Users for Linux too.

Wave 2 shipped: **auth, packages (+integrity), hashes, bodyfile**. Re-validated
on the same 3 UACs: 14 parsers/machine, 41 ok / 1 skipped / 0 errors,
`.db`/`.xlsx` parity holds (a `bodyfile` of 1.7 M rows is `.db`-only by the Excel
row limit, like Windows `$MFT`/`$J`). Distro coverage proven on both Debian/Ubuntu
(dpkg, auth.log) and SUSE (rpm, sudo in `messages`).

Review polish (post wave 2): `bash` now uses `_lincommon`, covers zsh/sh/ash and
drops HISTTIMEFORMAT markers; `wtmp.type` is a name not a number; `anomalies` has
a `suspicious` column (world-writable/web paths sorted first); `auth` reads
rotated `.gz`/`.xz`/`.bz2` logs (`_lincommon.iter_log_lines`); `machineinfo` adds
timezone/boot_time/cpu/memory and `report.txt` shows them.

### Sigma detections (`lin_sigma` + `core/sigma_engine.py`)

Runs the bundled SigmaHQ Linux ruleset (`data/sigma/linux/`, snapshot pinned in
`data/sigma/VERSION`) over the **raw UAC logs** — not the consolidated `.db`:

- `core/sigma_engine.load_rules()` compiles every rule to a SQLite query with
  `pysigma` + `pysigma-backend-sqlite` (cached). Rules route by logsource:
  auditd / process_creation / network / file → the **auditd** table; everything
  else → the **syslog** table. Unbound "keywords" are mapped onto a `message`
  column as `LIKE` substrings (a small pipeline); syslog rules that name a
  `service` are constrained by the parsed `proc` so a broad keyword (cron's
  `REPLACE`) can't match unrelated daemons.
- `lin_sigma` flattens auditd (groups records by serial, decodes hex EXECVE
  args, maps syscall number→name, synthesises `Image`/`CommandLine`/
  `CurrentDirectory`/`User` so process_creation rules match) and loads syslog
  (auth/syslog/messages/secure incl. `.gz`; dated `.xz` archives skipped) into
  in-memory SQLite, runs each rule, writes `sigma_detections.csv` (level-sorted)
  → `Detections/`. Syslog is the most RECENT 500 k lines (read from EOF via
  `_lincommon.tail_lines`), smallest files first so a multi-GB `messages` can't
  crowd out auth.log/secure.

Validated on 4 UACs (one with 6.3 GB of logs): 6 hits on one (auditd ADD_USER
+ remote-file-copy), 3 on another, 0 on the rest — clean after the service
constraint removed the cron-on-kernel FPs. `sigma` and `bodyfile` are the
heaviest Linux parsers; per-machine sigma is ~2-20 s in isolation but ~90-115 s
wall-clock under a thread pool (CPU-bound work + the GIL). A full 4-UAC
run is ~4 min. Going faster needed a process pool for the parse phase (the GIL
serialises pure-Python parsers) — since shipped and on by default (`parse_processes`),
the same lever later applied to consolidation.

**Coverage depends on the collected logs.** auditd rules need auditd with execve
auditing (only one host had auditd here, and without execve rules); syslog rules
need the relevant service logs. To get more out of Sigma, collect auditd (execve) and
/ or Sysmon-for-Linux in UAC.

**Web ruleset (`web_sigma` + `sigma_engine.load_web_rules()`).** The same engine
runs the bundled SigmaHQ `rules/web` snapshot (`data/sigma/web/`, same pinned
commit) over Apache/nginx access logs — the UAC's `var/log/apache2|httpd|nginx`
and the loose `weblogs` drop, via the shared `iter_access_files`. Only the
**webserver** rules are bundled (13 `category:webserver` + 3 apache/nginx
`service`): the 29 `category:proxy` rules target OUTBOUND forward-proxy logs and,
on inbound access logs, their exact-UA matches false-positive on legit old
browsers / Googlebot — so they are excluded (and the loader also skips any
`category:proxy` rule defensively). sqlmap/scanner UAs are covered by huntweb's
`web_suspicious.txt` instead. Each request is loaded into an in-memory `web`
table whose columns are named after the Sigma webserver field taxonomy
(`cs-method`, `cs-uri-query`, `cs-user-agent`, `sc-status`, …) so the back-quoted
rule SQL binds directly — no field-mapping pipeline; `keywords` map onto
`message` = the raw request URI (rules already list both encoded and decoded
payloads). Absent UA/referer (`-`) → NULL (so `IS NULL` filters like ReGeorg
work), status stored as INTEGER (so `sc-status=404` compares). Rows stream in
100 k batches (bounded memory on multi-GB logs); matches aggregate to ONE row per
(rule, client IP) — hits, first/last seen, sample URI, offline IP origin —
because the triage unit is "rule X fired N times from source Y", not every
scanner request (that's huntweb's per-request view). Output `web_sigma.csv`
→ `Detections/`. Validated on a mixed scanner corpus (bWAPP/DVWA + acunetix/
netsparker/w3af exports): 14 detections — SQLi, XSS, SSTI, Windows-webshell,
path-traversal, source-code enumeration — no proxy-UA FP flood.

Deferred (with rationale):
- **journal** — systemd `*.journal` is a binary format (LZ4/XZ objects, hash
  tables); a pure-Python reader is a large, higher-risk effort and most of its
  security content (sshd/sudo/su) is already captured by `auth` from the text
  logs. Pick this up as its own focused task.
- **mdatp threat path** — the `mdatp` parser shipped (health/exclusions/threats),
  but the available UACs have MDATP installed with **no threats**, so the
  threat/quarantine branch is exercised only by unit fixtures. Re-validate when an
  acquisition with real detections is available.
