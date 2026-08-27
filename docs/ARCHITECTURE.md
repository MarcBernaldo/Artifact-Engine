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
aeng sweep -p <dir> -q <value>         # find a value across every machine already consolidated
aeng list-parsers          # every loaded parser (id, os, cmd/py, description)
aeng list-profiles         # every loaded detection profile
```

`aeng` == `artifact-engine` == `python -m artifact_engine`. Flags: `-c config.yaml`,
`-v` verbose.

**Where the config comes from** (`config.config_candidates`): the tool's own folder
first, then the current directory, each reading `config.yaml` then
`config.local.yaml`, with later files overriding earlier ones key by key.
Searching only the cwd — what it did until v0.6.3 — made the settings depend on
where you were standing: launched from a case folder, or from the right-click menu
whose working directory is not yours, the file beside the tool was never found and
the run fell back to defaults whose `avoid_vss` is the opposite of a typical
config. That is a different acquisition, not a different preference, so
`cli._log_config` now names every file applied and the flags they resolved to, and
`aeng setup` writes its starting config beside the tool rather than wherever it was
invoked. The tool folder is identified by the `pyproject.toml` next to `src/`, so
an installed wheel never adopts whatever sits above `site-packages`.

---

## 2. Pipeline (cli.py `cmd_run`)

| Phase | Module | What it does |
|------|--------|--------------|
| 0 Integrity | `core/hashing.py` | SHA256 of every original file → `traces.txt` (before touching anything). |
| 1 Extraction | `core/extractor.py` | Decompress acquisitions (zip/tar/7z, nested up to `extract_depth`), parallel. Phase 1c (`extract_drops`) additionally unpacks containers dropped inside loose-drop folders (`weblogs*`/`fortigate*`/`evtx*`, see §10) in place. **A destination is never re-extracted destructively**: the `.aeng_extracted_ok` sentinel skips it, and a destination that lacks the sentinel but already holds run output (`CSVs/`, `JSONs/`, `report.txt`, `.db`/`.xlsx` — at its root or one level down per volume) is *adopted* and marked. The clear-and-retry-with-7-Zip path re-checks the same condition and refuses to clear such a destination. Markerless finished cases are real (extracted before the sentinel existed, or it was lost), and without those two guards one failed re-extraction deletes the evidence tree and every result under it. Since v0.7.20 the sentinel also *records how the extraction went* (`ok` / `warnings` / `partial`, plus the 7-Zip detail), because extraction is the one phase a re-run skips: a truncated acquisition whose verdict lived only in the run that extracted it would be reported once and then never again. `extractor.incomplete_acquisitions` turns that into the list the run summary and the exit code are built from — see §2. |
| 2 Detection | `core/detector.py` | Walk the tree, match `data/profiles/*.yaml`, produce `Machine` objects (OS, collector, volumes). VSS snapshots are pruned, optionally attached as their own machines. Console labels encode provenance so a hostname is never shown bare-and-repeated: `HOST` (live disk), `HOST-VSS<n>` (shadow-copy snapshot), and a `-LR` tag when the host also carries Velociraptor LiveResponse (parsed on the live volume, not a separate machine); same-host collisions fall back to the acquisition date. A LiveResponse shipped **without** KAPE artifacts beside it matches no profile, so a reconciliation pass registers it as its own `-LR` machine (`windows_liveresponse`) — otherwise a whole host's live state would be dropped in silence. |
| 3 Parsing | `core/scheduler.py` + `core/runner.py` | One global pool runs every (machine × volume × parser) task, interleaved across machines, ordered by `depends_on` level. Pure-Python handlers run in a process pool (`parse_processes`, real parallelism past the GIL); external-tool parsers stay on threads, because Ctrl+C needs `procs.cancel_all` to reach their `Popen`s. **A worker cannot write to the run log.** `setup_logging` runs in the parent and a spawned child starts from an empty logging config, so until 0.7.14 a handler's log call there reached a logger with no handlers at all — at best one unformatted line on stderr, never `aeng-run.log`. The runner now installs a collecting handler around the parser (only when the logger has none, which is the worker signature) and the diagnostics travel back as data on `ParserRun`: `trace` for a failure, `logs` for everything the handler chose to say. The parent replays them at the level they were raised, so `ctx.log` behaves for a handler author exactly as if it had worked there. |
| 4 Consolidation | `core/consolidate.py` + `core/report.py` | Parallel across **units** (process pool when >1 unit + `parse_processes`, else threads; live per-unit progress bars): every `CSVs/**/*.csv` (excluding any nested `VSS<n>/` subfolder -- VSS snapshots are their own machines) and LiveResponse `JSONs/*.json` → `<machine>.db` (SQLite) and `<machine>.xlsx` (same set, except sheets past Excel's row limit → `.db` only), selectable via `emit_db`/`emit_xlsx`, plus `report.txt`. A *unit* is one machine, or — with `merge_vss` — a host's live volume together with all its shadow copies folded into a single `<coll>/HOST.db`/`.xlsx`/`report.txt` with the rows the volumes share collapsed (see §12). Then a root-level `run-summary.{txt,json}` rolls up all machines. |
| 5 Lateral movement | `core/lateral.py` | Cross-machine logon correlation (Security 4624/4625/4648, Kerberos 4768/4769) → `lateral_movement.csv` (full edge list) + `lateral_movement.html` (self-contained force-directed graph, no libraries). Hosts matched by IP/name from `machine_info.json`; RDP / explicit-cred / failed / case-to-case / anonymous-logon edges flagged; external sources kept. Account labels are canonicalised (`<NETBIOS_UPPER>\<user_lower>`, so `CORP\Administrator` / `corp\administrator` / `CORP.LOCAL\Administrator` merge into one edge/actor, while a different domain stays distinct). A null-session network logon (`ANONYMOUS LOGON`) gets reason `anonymous_logon` (enumeration / SMB-relay IOC). Off-case graph nodes split by role — `server` (reached by NAME, an internal box the admin hit) vs a bare source IP, itself split into `public` (globally routable — attacker origin / internet-facing access) and `external` (private RFC1918/CGNAT) — so targets, internal sources and internet sources read apart; the HTML has a **public-IP-only** filter to isolate the last group in one click. The top-`_MAX_EXTERNAL` volume cap never culls an external that authenticated SUCCESSFULLY on a high-signal edge (`_HIGH_SIGNAL`: anonymous / pivot / chainsaw / explicit-cred / untrusted-cert / `rdp_public` / `brute_success`), so a one-shot attacker IP always stays; a peer seen only on FAILED logons never got in, so past `_MAX_BRUTE` only the loudest of a spray campaign are drawn and the rest are COUNTED in the page header (the CSV stays complete). A **routine successful inbound RDP carries no reason at all** — like a routine inbound SSH — because flagging every session on a Windows estate put 89% of edges under `suspicious=yes`; only `rdp_public` (globally-routable source) and `case_to_case` make one notable, while failures/chainsaw/anonymous/chains add their own reasons. RDPClient dial-outs (1024/1102) attribute their account by resolving the event's `UserId` SID through the machine's ProfileList (`reg_profList.csv`) — the channel logs in the user's session, so `UserName` is always empty. Edges are enriched with matching **chainsaw** rule verdicts (e.g. "Account Brute Force", "RDP Logon") from the per-machine `chainsaw_*` CSVs (`chainsaw` column), and a 4769 service ticket for a host SPN (`HOST$`) is drawn source→that host rather than source→DC. **Pivot chains**: an inbound logon onto an acquired host paired with outbound activity from it by the same account within a window (X→B→Y) marks both edges `chain` and is listed in the graph's "Attack paths" panel. The HTML is interactive: direction arrows on curved edges, search by user/host, filter by mechanism (colour-coded explicit/rdp/runas/kerberos/network) and, on a separate axis, by outcome (ok/failed, a failure drawn dashed) and a time-range slider with chronological playback, wheel zoom + pan, per-edge username + date labels, and a chronological timeline sidebar. VSS snapshots are skipped (point-in-time copies of the live host would duplicate every edge). Full detail: [LATERAL_MOVEMENT.md](LATERAL_MOVEMENT.md). |

Per-parser failures are isolated: one crash never aborts the run; it is recorded
in `run.json`, the machine's `report.txt`, and the root `run-summary.{txt,json}`
(per-machine ok/skip/err, slowest parser, full error list).

**An acquisition that did not extract whole is reported separately from those
counts, and changes the exit code (`2`).** It has to be, because it is the one
failure that produces no error to count: a parser whose input was cut out of the
archive does not crash, it finds nothing, self-gates, and lands in `skipped` —
beside every artifact the machine's distro genuinely does not have. A run over
half a tarball therefore ends `OK 2 | skipped 37 | errors 0`, `Errors: none`,
exit `0`, which is indistinguishable from a clean triage of a quiet host. Phase 1
records the verdict in the extraction marker (so a re-run, which skips extraction
entirely, still knows), `extractor.incomplete_acquisitions` collects it, and
`cmd_run` names the archives at the END of the run — phase 1 of a 60-machine
triage has scrolled away by then, and what gets acted on is the last screen.
Warnings alone do not count: 7-Zip finishing the job with complaints is a
different claim, and a flag that fires on the ordinary case stops being read.

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
    pipeline.py          the phase steps `run` and `lateral` share, so a command
                         calls the sequence instead of restating it
    sweep.py             search every machine's .db for a value, and report the
                         machines that could NOT be searched
    lateral.py           phase 5: cross-machine logon graph (csv + html)
    sigma_engine.py      compile SigmaHQ rules to SQLite queries (pysigma)
    downloader.py        fetch_tool() + asset fetchers for `aeng setup`
    procs.py             subprocess wrapper (timeouts, Ctrl+C cancel)
    progress.py          live per-machine bars; degrades to one line when not a TTY
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
tests/                   pytest suite; _preview/ renders synthetic HTML for the browser
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
provides: [logical_node]        # DOCUMENTARY ONLY - a label for what it emits (see below)
depends_on: [other_id]          # parsers that must finish first - THE ordering mechanism
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

**`provides` and `outputs` are documentary — nothing reads them.** Ordering comes
from `depends_on` alone (`scheduler._topo_order` / `_levels`; `registry.
_check_dependencies` warns about an id that doesn't exist). So declaring
`provides: [amcache_csv]` and expecting another parser to wait for it does
*nothing* — name the producing parser in `depends_on` instead, as `byovd` /
`lolbas` / `rmm` do with `depends_on: [amcache]`.

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
- `_local` — passthrough of a tool or device that renders in its own local zone with
  no offset in the string: `last`/`lastb`/`lastlog` (`logins.{start,end}_local`,
  `lastlog.latest_local`), `ps` (`processes.started_local`), package logs
  (`pkg_history.time_local`), the sudo log (`sudo_log.time_local`) and the
  FortiGate's own `date`+`time` fields (`fortigate.time_local`, alongside the
  `time_utc` computed from `eventtime`).
- No suffix when the basis is source-dependent or the offset is already in the
  value: `web_access.time` / `huntweb.time` (the `+ZZZZ` offset is kept in every
  value by `_webcommon._iso_time`) and, inheriting that same basis, the aggregate
  web columns `web_ip_stats.{first_seen,last_seen}`,
  `web_auth_fail.{first_seen,last_seen}` and `web_sigma.{first_seen,last_seen}`;
  `auth.timestamp` and `cron_log.timestamp` (syslog local **or** RFC3339 with
  offset — as-logged, and classic syslog carries no year either), `sigma.timestamp`
  (raw passthrough of the matched log). `machineinfo.boot_time` stays as-is: it is
  a key/value row sitting next to the `timezone` field, and its JSON key is a
  `core/report.py` contract.

A full sweep of the ~35 `lin_*` handlers confirms these are the only date-bearing
columns; the rest (anomalies/services/persistence/etc.) carry no timestamp column.
Re-run it after adding a parser — regex every CSV header in `handlers/` for a name
containing `time|date|seen|stamp|visit|exec|modif|creat|instal|latest`, and check
each hit appears in one of the three lists above.

The same sweep over the `win_*` handlers gives:

- `_utc` — `browser_history.last_visit_utc`, `browser_downloads.{start,end}_time_utc`
  (WebKit/PRTime epochs), `timeline.{start,end,last_modified}_utc` (Unix epoch),
  `wer.event_time_utc` and `wmi_ccm_rua.{timestamp1,timestamp2}_utc` (FILETIME,
  whose 1601 epoch is UTC), `wmi_ccm_rua.last_used_time_utc` (CIM_DATETIME — its
  trailing `sUUU` offset from UTC is *applied*, not discarded), and
  `{byovd,lolbas,rmm}.first_seen_utc` (AmcacheParser's `FileKeyLastWriteTimestamp`;
  EZ tools render UTC and this engine passes no `--dt` offset anywhere).
- `_local` — `pca.last_executed_local` (Windows writes `PcaAppLaunchDic.txt` in the
  host's zone with no offset in the string) and `tasks_disk.created_local`
  (Task Scheduler `RegistrationInfo/Date`, stamped in the registering user's local
  zone). Both are verbatim passthroughs; convert via `machine_info.json`'s timezone
  before comparing them with a `_utc` column.

### The `suspicious` column: `yes` or empty, never `no`
Twenty-eight parsers carry a `suspicious` column and every one of them writes the
literal `yes` or the empty string — nothing else. The empty value is what makes
"show me everything flagged in this case" a single filter (`suspicious` is not
blank) across every CSV at once, and it is what the `rows.sort(key=lambda r: r[N]
!= "yes", ...)` idiom in each handler sorts on. A parser that wrote `no` for the
negative case (`auditd_config` did, alone, until v0.5.3) would put every one of its
rows into that filter's results.

`lateral_movement.csv` follows the same rule (`first_seen_utc` / `last_seen_utc`),
and `lateral_movement.html` states "all times UTC" in its header — its JS anchors
every value to UTC before parsing so the viewer's own zone can never shift the
displayed hours.

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

**Buffer or stream?** `_lincommon.write_csv(out, name, header, rows)` takes a list
and is right when the row count follows the *machine* (accounts, services, cron
entries, packages). Use `_lincommon.stream_csv(out, name, header)` — a context
manager yielding an `emit(row)` callable, same no-rows-no-file contract — when the
row count follows a *log*, because on an internet-facing host that means it follows
the attacker: one row per failed SSH attempt (`auth`), per failed login record
(`btmp`), per request (`web_access`), per cron execution (`cron_log`). Nothing that
grows with those may be held whole — including a de-duplication set, which is why
`lin_auth` reads rotations oldest-first (`_lincommon.sort_rotations`) and
de-duplicates through a bounded window instead of remembering every event.
`sort_rotations` knows both logrotate conventions, and each of them breaks a
plain sort differently: numbered (`auth.log.2.gz`) is not monotonic past nine
rotations, and `dateext` (`messages-20260519.xz`, the SUSE and RHEL default)
sorts the file being written now *ahead* of every archive. Where an aggregate genuinely must be
kept in memory, cap it and *report* what the cap dropped (`lin_web_metrics`,
`lin_sigma`).

**Parsing XML?** Use `handlers/_xml.fromstring`, not `ElementTree` directly: it
refuses documents that declare entities. See the module docstring — SYSVOL and the
task store are written by whoever owns the DC.

---

## 7. Categories → output folders (`scheduler._CATEGORY_DIR`)

```
filesystem→Filesystem  execution→Execution  eventlogs→EventLogs
registry→Registry  shellbags→FilesystemAccess  systeminfo→SystemInfo
shell→Shell  browser→Browser  persistence→Persistence  search→Search
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
(DFIR defensibility), without blocking updates. It is written **after** every fetch
and also covers the binaries obtained outside the manifests (`cli._EXTRA_BINARIES`,
today hayabusa): its parser is a Python handler with no `tool:` section, so walking
the manifests alone left the one downloaded executable we run unrecorded.

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

### Loose drops (`weblogs` / `fortigate` / `evtx` profiles)

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
  evtx-dc01\                        <- loose Windows event logs
    Security.evtx                   <- canonical channel names
    rdp\Microsoft-Windows-...%4Operational.evtx    <- subdirs too
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

- **evtx** (os `windows`): loose Windows event logs when there is no acquisition
  around them. The **whole event-log toolchain runs unchanged** — EvtxECmd once
  per channel, chainsaw, hayabusa, DeepBlueCLI — because those 17 parsers are all
  wired to `<evidence>/Windows/System32/winevt/Logs` and `detector.
  prepare_evtx_drops` (cli, right after detection) synthesises exactly that path:
  every `*.evtx` in the drop is **hard-linked** into it (copied only if linking is
  refused) and its original path is then removed, so the drop holds each log exactly
  once. That loses nothing — a hard link is a second NAME for one set of bytes, and
  an original is unlinked only once its bytes are confirmed at the staged path (same
  inode, or identical size on the copy fallback); an unstaged file, e.g. a basename
  collision, is always left alone. Emptied subfolders are kept: pruning directories
  out of an evidence tree is not worth the tidiness. Idempotent — after the first
  pass there is nothing left outside the staging dir to re-stage. Keep the canonical channel file names (`Security.evtx`,
  `Microsoft-Windows-Sysmon%4Operational.evtx`, …): EvtxECmd selects by name,
  while chainsaw/hayabusa/DeepBlueCLI sniff content and read renamed files too.
  Two logs sharing a basename (a drop mixing several hosts — use one folder per
  host) are reported, never overwritten. Unlike the other drops this one **is** a
  host: event logs are logon evidence, so the machine is renamed from the folder to
  the host its events name (`Computer` field) and it joins the lateral-movement
  graph on that host's node. The rename (`detector.name_evtx_drops`) runs **as soon
  as phase 3 finishes** — before anything is named after the machine — so `run.json`,
  `<machine>.db`/`.xlsx`, `report.txt`, `run-summary` and the graph all carry that one
  name. It is idempotent and repeated at the top of `lateral.build`, because
  `aeng lateral` re-detects from scratch and would otherwise see the folder name; since
  0.7.12 `pipeline.detect` also does it, so the machines are already named correctly
  when they reach the graph rather than being repaired on arrival.

Shared plumbing: detection = `dir_name` clause + non-empty (a `fortigate[-label]`
/ `weblogs[-label]` / `evtx[-label]` folder, numeric suffix allowed). Zipped exports
(`.zip/.tar.gz/.7z`, any name) inside a drop are auto-extracted in place by
`extractor.extract_drops` (cli phase 1c, one nested level, idempotent);
standalone `.gz` rotations stay compressed and are streamed. File discovery =
`iter_access_files`' fallback: when the evidence has no `[root]/` and the
standard `var/log` bases yielded nothing, the whole tree is offered (`error*`,
configs, containers, non-CLF text and the tool's own outputs excluded; binary
files sniffed out by a NUL-byte check; `.csv` kept for the fortigate parser via
`csv_ok`).

**Input contract (naming is the trigger).** A drop is recognised purely by the
FOLDER NAME matching `(weblogs|fortigate|evtx)(<num>|[-_]<label>)?`
(case-insensitive: `weblogs`, `weblogs2`, `weblogs-www.client.com`,
`fortigate-fw-edge`, `evtx-dc01`). There is
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

**Phase 4 is cached per unit.** `build_unit` hashes the CONTENT of every CSV and
JSON the unit would read, plus the consolidation code's own import closure and the
settings that change what is produced, and writes the digest to
`.<unit>.consolidated` beside the outputs. A later run with the same inputs skips
the unit entirely; `--force` rebuilds anyway, and a missing `.db`/`.xlsx` rebuilds
regardless of the marker, so deleting an output is never papered over. Content is
hashed rather than size+mtime because "almost always right" is the wrong standard
for a forensic deliverable. It matters because consolidation measured ~29% of a
53-minute run with 99.9% of that in a single merged host, which does not change
between runs unless its parsers did.

**Phase 0 is append-only.** It hashes the originals that are not in `traces.csv`
yet and appends them under their own dated `Added:` section, because a later
delivery was received at a different moment and the record should show that.
Lines already written are never touched. Until v0.7.2 the phase bailed out the
moment `traces.txt` existed, so evidence arriving into an open case was
extracted, parsed and reported on while the custody record still claimed to
describe the whole case — a record that is incomplete without saying so.

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

## 10b. Staying current (`aeng update`)

`setup` and `update` answer different questions. **`setup` fills gaps**: every
fetcher returns early when the file is already there, which is what makes a second
`setup` cheap — and what makes it useless for picking up a new rule. **`update`
refreshes what has gone stale**, which is why the fetchers grew a `force` flag
rather than a second copy of themselves.

- **The engine** fast-forwards the checkout (`cli._update_engine`). It is
  deliberately timid: dirty tree, detached HEAD or local commits ahead of origin
  all stop it with an explanation and no change. The checkout may be somebody's
  working copy, and resolving that is not an update command's job. `git` runs with
  `GIT_TERMINAL_PROMPT=0` so a missing credential fails visibly instead of hanging
  on a prompt nobody is watching. The version is re-read **from the file** after
  the pull — `__version__` in memory is the pre-pull value.
- **A rule set is synced, not downloaded.** `fetch_yara_rules` deletes what
  upstream withdrew, because a retired rule is usually retired for firing on
  benign files: keeping the copy reproduces exactly the false positive that was
  removed. Only files a previous sync wrote are eligible — they are listed in
  `.aeng-signature-base.json` beside them — so an analyst's own rules in the same
  folder survive. Same reasoning purges `hayabusa/rules` and `chainsaw/{rules,sigma}`;
  `hayabusa/config` is spared, being what an analyst tunes.
- **Destructive steps happen after the download, never before.** The archive is
  fully in hand before the old exe or rule tree is removed (`fetch_tool`'s
  `purge_dirs`, `fetch_hayabusa`), so a fetch that fails leaves a working install
  rather than a gutted one.
- **Compare before fetching.** hayabusa's version is on its exe name, chainsaw's
  comes from `chainsaw --version`, both against the GitHub release tag — one small
  API call decides whether tens of megabytes are worth moving. An unknown local
  version counts as out of date. db-ip is re-cut monthly and stamps the cut it
  wrote (`<db>.mmdb.ym`), so a same-month refresh is skipped.
- **Report what moved, not what was attempted.** The geo row hashes before and
  after and says `current (unchanged)` when the bytes came back identical. In a
  tool whose output is evidence, a status that overstates is worse than no status.

---

## 11. Testing

```
python -m pytest -q          # from the repo root
python -m ruff check .       # must be clean
```

The `tests/` tree is published, and CI runs both gates on every push and pull
request (`.github/workflows/ci.yml`) — on Windows, against Python 3.10 and 3.13.
Both ends of the supported range are not redundant: a CPython wording change
between those two versions silently disabled the unraisable-hook filter once
already, and only a run on both would have caught it. Every fixture is
synthesised; nothing out of a real case belongs in the suite.

**Linting.** The rule set is ruff's own default, so `dev` pins a **minor range**
(`ruff>=0.16,<0.17`) rather than a floor: that default moves between versions, and
the same unchanged tree reported 126 findings on one and 75 on the next — "ruff is
clean" only means something when everyone runs the same range. Bumping the range
is a deliberate act with a visible diff. `pyproject` ignores only `S110`/`S112`
(try-except-pass/continue), which are the shape of best-effort parsing over
evidence rather than a smell; everything else that stays is an inline `noqa` with
the reason on the line above it.

On top of the default the config adds **`E501`**, so the `line-length = 110` that
had been declared since the beginning is finally checked — it is not in ruff's
default set, so until now the number was decorative. Two files are exempt via
`per-file-ignores`: `_web_report.py` and `lateral_report.py` emit HTML/CSS/JS as
literal strings, and 42 of their 56 overlong lines carry markup. The second used to
be `lateral.py`, where the waiver covered a thousand lines of correlation logic as
well as the template; splitting the page out means the limit applies to the logic
again and is waived only where a wrapped line would change what the analyst sees. Re-wrapping those is not
formatting — it edits the text that becomes the page the analyst opens, and a
split inside a tag or a CSS declaration changes the output with no test to catch
it. Widening `select` beyond this is still a separate decision: the full families
report 310 findings.

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
  unless `--force`. The marker holds a fingerprint of the manifest core plus, for a
  Python handler, the source of its **whole transitive first-party import closure**
  (`runner._handler_closure`, walked with `ast`) — so editing a shared helper
  re-parses everything that reaches it, with no `--force` needed. Before v0.7.0
  only the handler's own module was hashed, which left every already-processed case
  serving output from a version known to be broken. The closure reaches `core.runner`,
  `procs`, `models` and `logging_setup`, so a cosmetic edit to any of those
  invalidates the whole set: batch core changes rather than paying a full re-parse
  per commit. Asset files (indicator lists, rule sets) are NOT in the digest — see
  CUSTOM_DETECTIONS.md. A parser writes into a private `.work_<id>` dir which is then
  merged into the category folder; if a file cannot be moved there — the analyst has
  last run's CSV open in Excel, which holds a Windows lock — the run is reported
  `error` naming the file and **no marker is written**, so the next run retries
  rather than trusting a result that never landed. Consolidation degrades the same
  way: a locked `.db` still produces the `.xlsx`, a locked `.xlsx` still produces the
  `.db`.
- **Never build a shell string.** Parsers get an argv list, which `procs.run` passes
  straight to `CreateProcess` — no quoting to get wrong. `win_deepblue` is the one
  exception (it needs a PowerShell pipeline) and it must route every path through
  `_ps_quote`: a case folder whose name carries an apostrophe (`Web d'Exemple
  compromesa`) is ordinary here, and an unescaped one ends the PowerShell literal
  early, so the command fails and that machine's logs are silently never analysed.
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
- **A parent that vanishes mid-parse is a CPython bug, not ours.** On Python 3.10
  for Windows the parent can die with `0xC0000005` and no traceback. The faulting
  instruction is `--self->mbuf->exports` in `_memory_release()`
  (`Objects/memoryobject.c`) with `self->mbuf == NULL`: the cyclic GC runs
  `memory_clear()` on a `memoryview` that still has a buffer exported,
  `_memory_release()` returns -1, `memory_clear()` casts it to `(void)` and
  `Py_CLEAR`s `mbuf` regardless — leaving a view that is NOT flagged
  `_Py_MEMORYVIEW_RELEASED` but has no buffer, so the next release dereferences
  NULL. Reproduced on 3.10.11 (`BufferError: memoryview has 1 exported buffer`
  raised from `tp_clear`, then the same `0xC0000005`). The views come from the
  process pool's pipes: `multiprocessing.connection._send_bytes` calls
  `_winapi.WriteFile(..., overlapped=True)`, which holds a `Py_buffer` on the
  source until the write completes; an exception there puts the frame — and the
  pending view — into a traceback cycle for the collector to find. Workaround is
  `parse_processes: false` (no pool, no pipe traffic). `gc.disable()` is NOT a
  workaround: it only defers the collection, and the crash then lands at
  interpreter shutdown instead. Diagnose these from
  `%LOCALAPPDATA%\CrashDumps\python3.10.exe.<pid>.dmp`.
- **Never capture a tool's output through a pipe.** `procs.run` redirects stdout and
  stderr to temp files. `Popen.communicate()` on Windows starts a reader thread per
  pipe, so capturing both cost **two threads per tool** — ~64 in the parent at
  `max_workers: 32`, on top of the task threads (measured: 32 concurrent tools took
  +97 threads with pipes, +33 with files). The parent was seen dying on a null
  dereference inside the interpreter — same instruction in every dump, always at
  ~128 live threads. The fault is below this code and unproven, but the thread count
  is the one thing that correlates and two thirds of it came from here. Files also
  keep a chatty tool's output off the heap. Decode the bytes here, never via
  `text=True`: EZ tools emit non-UTF8 and a strict decode turns a good parse into a
  crash.
- **Never write a sheet with `DataFrame.to_excel`.** The workbook is opened in
  xlsxwriter's `constant_memory` mode, which flushes a row the moment a later one is
  touched and drops anything written back into it. pandas emits cells **column by
  column**, so `to_excel` fills column 0 for every row and then loses every other
  column on every row but the last — silently, in the file the analyst opens.
  `_sheet_open` + `_append_rows` write whole rows in order instead. Hand xlsxwriter
  Python natives (`.item()` off numpy scalars): it falls back to `float()` for types
  it does not know, which rounds a `uint64` Amcache ID, and refuses NaN outright.

### Merging a host's shadow copies (`merge_vss`)

With `avoid_vss: false` every `VSS<n>` is its own machine, so a host with ten
snapshots produces eleven databases — and finding one logon means opening all
eleven. `merge_vss` (default **on**) folds them into one unit per host:
`consolidate.plan_units` groups machines by *(collection folder, host name)*,
and `_build_merged` writes `<coll>/HOST.db` beside `C/` and `VSS1/` instead of
inside either. The per-volume `CSVs/` are never touched — merging produces a
consolidated *view*, not a rewrite of the evidence, and `lateral.py` keeps
reading the CSVs per volume exactly as before.

- **Artifacts are paired by their path under `CSVs/`** (`EventLogs/evtx_Security.csv`),
  not by basename: two different artifacts sharing a basename in different
  categories must stay two tables.
- **Deduplication happens in SQLite**, not in Python: the volumes are appended to a
  staging table and collapsed with `GROUP BY <every non-provenance column>`, which
  is bounded by disk rather than RAM (a set over 2.6M rows is not). Set
  `temp_store=FILE` for that sorter — the default `MEMORY` would spike by GBs.
- **The key is the whole row, deliberately.** An identifier key would be cheaper,
  but a cleared log restarts its record IDs, and then two genuinely different
  events collide. Whole-row means the worst case is "a duplicate survives", never
  "an event is lost".
- **Provenance columns are excluded from the key**, sniffed from the data (a value
  embedding the volume's own path) rather than a name list. EZ tools write the
  parsed file's full path into every row; leaving `SourceFile` in the key made a
  whole-row match find **zero** duplicates across eleven volumes.
- **`volumes`** records which volumes carried each surviving row, normalised into
  volume order (`group_concat` emits in scan order). `WHERE volumes='VSS3'` is the
  "what does only this snapshot still hold" query, and `report.txt` gains a
  contribution table with that count per volume — which is what tells the analyst
  which snapshot is worth opening.
- **VACUUM at the end.** Dropping the staging table only frees its pages to the
  free list, so the file would keep the high-water mark of the biggest artifact it
  staged (measured: 214 MB of file for 94k surviving rows → 30 MB after).
- Merging is also **faster** than not merging — the `.xlsx` pass runs once per host
  rather than once per snapshot (measured on a synthetic 11-volume host, 627k rows:
  24.8s/34.5 MB merged vs 49.7s/208 MB per-volume).
- Outputs a previous *unmerged* run left inside `VSS<n>/` are **reported, never
  deleted** — removing files from inside a case is the analyst's call. But a count
  and one example are not something anyone can act on: `write_stale_list` puts the
  **exact** paths in `<case>/stale-outputs.txt`, one per line and nothing else, so
  the list feeds a pipeline as it stands. Deriving it by hand is where it goes
  wrong — the same folders hold outputs the run *does* rebuild, and the two differ
  only by which volume directory they sit in, so a hand-written filter comes out
  too broad (catching a live machine's current `report.txt`) or too narrow (missing
  the per-snapshot `.db` files, which are the ones holding the gigabytes). The file
  is rewritten every run and truncated once nothing is stale, so it never outlives
  the files it names.
- **Dirty ESE databases.** ESE DBs collected live (SUM `.mdb`, and potentially the
  Search `Windows.edb`) are in a dirty-shutdown state; SumECmd refuses them yet
  exits 0 (a plain command parser would silently produce nothing). The `sum`
  handler copies them to a temp dir and runs `esentutl /r` + `/p` (recover/repair)
  before SumECmd — never touching the evidence. Apply the same recipe if SIDR
  (Windows.edb) hits it.
- **Timeouts.** Set `timeout` realistically (SRUM/Search index/MFT are slow).
  It is applied to `command:` parsers only — `runner._run_handler` does not
  enforce it, so a pure-Python handler has no timeout and a hang shows up as the
  scheduler heartbeat naming it while the run waits.

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
  auth.log/secure/messages, every rotation of the family that exists), wtmp +
  btmp (login history / failed attempts, epoch→UTC, rotations included — btmp is
  what the lateral graph builds `brute_success` from, so a spray that rotated out
  would otherwise never reach it), logins (last/lastb/lastlog incl. failed), sudo_log (every sudo
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
  list-units/list-timers, flags not-found units). Per-user locations are scanned in
  every home declared by `/etc/passwd`, not just `/root` + `/home/*`: SERVICE
  accounts are where a web compromise persists (Debian's `www-data` lives in
  `/var/www`), while placeholder homes (`/`, `/nonexistent`) are rejected so the
  scan can't swallow the whole tree.
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

**Current state**: 95 parsers (56 Windows / 39 Linux), 5 detection profiles, full
suite green. Windows disk + live-response, Linux/UAC and the web/firewall drops are
shipped and validated on real evidence (§13). Waves beyond the original "close
Windows" P1 (all done): LOL detections (rmm / byovd / lolbas / reg_persistence /
win_yara); the Velociraptor live-response layer with per-row flags, a derived
`suspicious.json` and cross-artifact `correlation.json` (process ↔ tree ↔
connections/listeners ↔ launching service/task); the cross-machine lateral-movement
graph (Security + source-side RDP-MRU / TypedPaths / rdpOut, multi-DC); the F1
console/RDP-MRU/on-disk-tasks/WordWheel/sudo/cron parsers; and the loose-drop
machines (`weblogs`, `fortigate`, `evtx`). Pipeline hardening: per-parser `.done`
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
  (auth/syslog/messages/secure incl. `.gz`; dated archives skipped — unlike
  `lin_auth`, which reads them: this handler spends a fixed line budget from the
  newest line backwards, so more archive buys no more window, only more
  decompression. Lifting it needs a time window, not a wider pattern) into
  in-memory SQLite, runs each rule, writes `sigma_detections.csv` (level-sorted)
  → `Detections/`. Syslog is the most RECENT 500 k lines (read from EOF via
  `_lincommon.tail_lines`), smallest files first so a multi-GB `messages` can't
  crowd out auth.log/secure. **auditd has the same 500 k ceiling** and reads
  `audit.log*` newest rotation first (each file parsed on its own — the audit serial
  that groups an event's records is only unique within one file). It was uncapped
  until v0.5.3, which on a host with audit rules loaded meant every line of a
  hundreds-of-MB `audit.log` became a dict, then a row, then an in-memory SQLite
  row — the one path in this handler that had no bound while its syslog twin did.

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
