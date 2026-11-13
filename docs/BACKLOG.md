# Backlog

The single list of work for Artifact Engine: every task from the chat, a
background session or an automation goes here before it starts. No case data:
describe a problem by its shape, never by a host, user, address or path from a
case.

**States:** `pendiente` · `en_curso` · `bloqueada` (say on what) · `aplazada` ·
`hecha` · `descartada`.
**Rules:** a new task is written down before work starts; a task cut short records
the exact point it stopped; a finished task is closed with its result in one line
and moves to *Closed*. Informational questions with no change are not recorded.
Closed entries older than the last few releases are dropped: git holds them.

Format: `### AE-NNN · state · title`, then dated notes (`- YYYY-MM-DD: ...`).

## Open

### Correctness

### AE-006 · hecha · Alert tables the report's Findings leave out
- 2026-11-11: found while building `v_alerts` (AE-045). `findings.py` reads a
  `suspicious` or a `level`/`severity` column, and six `alert_` tables carry
  neither (`alert_rmm`, `alert_lolbas`, `alert_suspicious_tools`,
  `alert_suspicious_commands`, `alert_remote_access_domains`, `alert_mem_yara`):
  report.txt lists them among the tables it does not cover and `findings.csv`
  has none of their rows, though every row of an `alert_` table is a finding.
  `v_alerts` already includes them as `flagged`. Decide: the report reads an
  `alert_` table with neither column whole, or those parsers write a `level`.
- 2026-11-13: done in v0.7.201: every row of an alert_ table with neither column is `flagged`.

### Code review of 2026-11-12 (AE-100 to AE-110)

Asked by the user: is the code of the main processes correct, and where can it
be faster or cleaner. Two fresh-context reviewers read custody/extraction and
CLI/reporting; the scheduler, the runner and the consolidation were read and
measured in the session. Every entry was reproduced on synthetic files or traced
in the code; none is fixed. Order: custody and evidence first.

### AE-100 · hecha · A custody record that cannot be indexed is overwritten
- 2026-11-12: `hashing.generate_traces` opens `traces.txt` and `traces.csv` for
  append only when the csv index gave rows (`append=bool(known)`). An index that
  cannot be read -- re-saved by a spreadsheet with another separator or a BOM,
  deleted, locked -- makes both files start again and the earlier deliveries are
  gone. Decide append from the files existing; with a record and no usable index,
  stop loudly or append a section that says so.
- 2026-11-13: done in v0.7.201 (CustodyError, exit 1; the index opened before the record is written).

### AE-101 · hecha · The extractor writes into, and clears, a destination it did not create
- 2026-11-12: three shapes of one fault, a destination this engine does not own.
  - A folder already at the destination name, unmarked and never parsed, is
    extracted into; when the native reader fails, the 7-Zip retry clears it,
    files of the analyst included (phase 0 had just recorded them).
  - A destination name that is a FILE (`x.log` beside `x.log.zip`) raises out of
    `_extract_one`: the run aborts, the pool is not shut down.
  - Two archives folding to one destination (`logs.zip`, `logs.tar`) are
    submitted together on a first run and come out spliced, both `ok`.
- Fix: clear only what the engine created (AE-103's note); every exception of
  one archive is that archive's failed result; group a level by destination
  before submitting.
- 2026-11-13: done in v0.7.201 (phase 1 and 1c group by destination).

### AE-102 · hecha · A 7-Zip that was killed, or waits for a password, leaves a `warnings` marker
- 2026-11-12: exit code 1 is read as "read to the end, with complaints", and a
  killed process exits 1: Ctrl+C during a 7-Zip extraction marks a half tree
  `warnings`, and no later run names it. 7-Zip also inherits stdin with no
  timeout, so a password-protected archive waits for a password nobody is asked
  for. Fix: `stdin=DEVNULL` in `procs.run`; cancellation reported by `procs.run`
  and never followed by a marker; code 1 with no detail is `partial`.
- 2026-11-13: done in v0.7.201 (procs.Cancelled, also for Volatility's own launcher).

### AE-103 · hecha · Nothing on disk says an extraction is in progress
- 2026-11-12: a process killed mid-extraction leaves a tree with no marker and
  no note; the next phase 0 hashes its files as originals (the v0.7.49 defect by
  another door). An empty marker reads as `ok`, a cut one as not partial, and a
  marker that could not be written is logged at debug. Fix: write the failed
  note as "in progress" before the first member and remove it on success; marker
  through a temp file and `os.replace`; an empty or unknown status is `partial`.
- 2026-11-13: done in v0.7.201.

### AE-104 · hecha · An original that cannot be hashed aborts phase 0 or is left out in silence
- 2026-11-12: a locked file raises out of `generate_traces` with nothing written
  for the files that did hash; a directory that cannot be listed is skipped by
  `os.walk` without a line. Fix: a `NOT HASHED: <reason>` row per file, `onerror`
  on the walk, both into the run's verdict.
- 2026-11-13: done in v0.7.201 (schema 5, `not_hashed`).

### AE-105 · hecha · An EVTX drop deletes a log it never staged
- 2026-11-12: `detector.prepare_evtx_drops` removes the dropped file when a file
  of the same name and SIZE is already staged, and event logs grow in fixed
  chunks, so a second export of one channel often matches. Remove the source only
  when this call staged it or both are one inode; otherwise warn, leave it.
- 2026-11-13: done in v0.7.201 (same inode or the same bytes).

### AE-106 · hecha · Extraction guards that hold on one path only
- 2026-11-12:
  - The zip-bomb refusal is caught by the generic retry and 7-Zip extracts the
    archive in full; a tar has no bound at all. A dedicated exception that is not
    retried, bytes written counted against a total and the free space; decide
    whether the ratio fails or warns.
  - A file whose name folds onto a directory fails the whole acquisition instead
    of being dropped and reported: claim directories too.
  - A second run opens containers inside trees a first run extracted (the drop
    walk does not stop at the marker), so two runs parse different trees.
- 2026-11-13: done in v0.7.201; the ratio alone is a warning. Left: the 7-Zip BINARY fallback has no size bound but the disk (it writes the members itself).

### AE-107 · hecha · A run that dies leaves the previous verdict on disk
- 2026-11-12: `run-summary.json` is written last and never invalidated: after an
  abort (a dead worker, a phase-0 error, Ctrl+C) it still says what the run
  before said, and `aeng mcp` reports it beside the new exit code. A consolidation
  worker that dies is not handled at all (no reports, no summary, pool left up).
  Fix: an `incomplete` stub at the start of `cmd_run`; every exit path logs the
  exception and writes a summary naming the phase; a pool failure becomes broken
  units and the run goes on to its summary. In the scheduler, `fut.result()` of a
  task that raised becomes that task's error, and a dead parse worker costs the
  tasks in flight, not the run.
- 2026-11-13: done in v0.7.201, except one part: a dead parse worker (BrokenProcessPool) still ends phase 3; the stub names it.

### AE-108 · pendiente · Outcomes that never reach the verdict
- 2026-11-13: one more (AE-105 review): a second export of an EVTX log already
  staged is left in the drop, unparsed, said only as a warning.
- 2026-11-12: a lateral graph that could not be written (the csv open
  elsewhere), a memory image detection did not reach, `sweep --csv` that could
  not write its file, and a manifest dropped for bad YAML, a failed validation or
  a duplicate id (its parser then runs on no machine): each is one log line and
  the run ends `complete`. Each becomes an input of the status.

### AE-109 · pendiente · Configuration: unchecked, and read from the working directory
- 2026-11-12:
  - The working directory is trusted for `parsers/`, `profiles/` and
    `config.yaml`, and it can be the case folder; a manifest's `command` is run
    as written. Ignore it when it is the case root or inside it, and say so.
  - No validation: a `-c` file that does not exist, an unknown or mistyped key
    and a mistyped boolean all keep the default in silence; an empty or
    non-numeric value is a raw traceback; `extract_depth` 0 is accepted. A strict
    pydantic model, as the manifests have.
  - `max_workers` above 61 ends phase 3 on Windows (`ProcessPoolExecutor`
    refuses it; the ceiling is 64 and `aeng setup` writes the CPU count).
  - The config is read before logging starts, so its warnings are not in
    `aeng-run.log`, which also omits half the settings; `lateral` logs none.

### AE-110 · pendiente · A shadow copy is any folder whose name starts with VSS
- 2026-11-12: an acquisition folder named that way is pruned and never
  detected; with two volumes each snapshot is attached to both. Match `VSS<n>`
  beside a detected Windows volume only (`core/memory.py` has the same test).

### Detection and triage

### AE-010 · aplazada · Known-benign publisher allowlist
- 2026-11-05: security agents, remote-support clients and vendor updaters trip the
  service and path rules everywhere. Key on Amcache publisher + install path +
  ImagePath; downgrade with the reason, never drop the row.

### AE-011 · aplazada · Linux package integrity rules and verification count
- 2026-11-05: judge `art_packages` verification rows (a PAM module under
  `security/` failing its checksum; one hash in both 32- and 64-bit library
  paths), and report the verified-file count beside any "clean" verdict.

### AE-012 · aplazada · BITS download URLs on the front page
- 2026-11-05: unflagged `art_bits_jobs` URLs and `art_evtx_bits` are never
  summarised; they belong beside the browser downloads.

### AE-013 · aplazada · Remaining awesome-lists catalogues
- 2026-11-05: double extensions, Hijacklibs against MFT DLL paths, suspicious
  ports, hostnames, DynDNS and TLDs. User-agent and DoH lists only as an opt-in.

### AE-016 · aplazada · cmd_hunt reads Security 4688 command lines
- 2026-11-05: still excluded (user instruction 2026-10-11); revisit if asked.

### AE-017 · aplazada · Linux memory findings
- 2026-11-05: no alert_mem equivalent for Linux images (malfind, modxview,
  hooked syscalls, ptrace, bash history).

### AE-018 · aplazada · Sudoers flags never reviewed for false positives
- 2026-11-05: five flags on one host were not reviewed.

### AE-019 · aplazada · Last run for anacron and periodic scripts
- 2026-11-05: `art_tasks` last-run matches exact crontab commands only.

### AE-027 · en_curso · Adapt SigmaHQ's Windows rules to the engine's tables
- 2026-11-08: fork github.com/MarcBernaldo/sigma, branch `aeng`, read by alert_win_sigma
  (v0.7.194). Method, tools and phases: sigma-fork skill. Not adaptable, noisy or
  duplicate -> listed in `aeng/not-adaptable.txt`; the engine skips every
  rule listed there.
- 2026-11-08 done:
  - Phase 2: 19 file rules adapted, 67 not adaptable.
  - Phase 3:
    - v0.7.195 reads every hive value, less a clean-install baseline.
    - 30 registry rules adapted.
    - 23 rules not run: they fire on a clean Windows or on every host.
  - Phase 4: v0.7.196 names netstat connections from the live DNS cache.
  - Phase 5, first part: v0.7.197 runs the process rules over the saved command lines
    (PowerShell history, tasks, services).
  - Duplicates: 23 rules only repeat alert_rmm, alert_suspicious_tools or
    alert_remote_access_domains, so they are not run. The check against every
    other alert table on the real case (hayabusa, web, defender...) left nothing
    else repeated. One custom rule was retired from artifact-engine-sigma for the
    same reason.
  - Real case end to end, 4 hosts: 656 s. alert_win_sigma is the slowest task
    (max 361 s, of which the MFT pass is most); it was already 382 s on v0.7.190.
  - 118 lines in not-adaptable.txt.
- 2026-11-10 done:
  - Museum overlap (21 readable volumes): no rule repeats another alert; the
    only partial one (Public folder binaries, 4 of 16 in alert_exfil_commands) adds
    the rest.
  - Phase 5 variants: one, Sysnative (`*_image_only.yml`, `related: derived`, only
    rows with no command line). The other candidates lose their meaning with the
    command line, or match drivers, DLLs, AppX and 8.3 installer paths.
  - Registry rules with Image in a selection: the hidden SAM user adapted, 6 listed.
  - File rules over VanillaWindowsReference: EVTX in SystemTemp filtered.
  - Web through the fork (v0.7.198); one rule listed as a `scanner_ua` duplicate.
  - v0.7.198 also reads Windows 7 prefetch paths (`\DEVICE\HARDDISKVOLUMEn`) with
    their drive: "System File Execution Location Anomaly" fired on 5 museum hosts.
  - Seen on the museum, not changed: a collector writing its output to the same
    disk (a temp folder on C:) makes EVTX/hive copies fire; XP profile paths (`Documents
    and Settings`) trip the hive-staging rule.
- Next: Linux (lin_sigma over auditd, syslog, history, ps).
- 2026-11-11: proposed in the project review, and agreed by the user with the
  rest of it: the Linux phase waits for AE-045 to AE-048.

### AE-043 · pendiente · Keep or drop the local LLM in the Sigma adaptation
- 2026-11-08: measured (local-llm/sigma-triage/README.md).
  - Phase 2: the models scored 46-79% on 86 rules labelled by hand, while always
    answering "not adaptable" already scores 78%.
  - Phase 5: 57-77% of their "adapt" votes fire on a clean Windows.
  - The deterministic measurements decided every rule.
  - Proposal:
    - drop it as a judge;
    - try it once for a narrow, checkable job: drafting the `# aeng:` comment
      and the variant from a rule already chosen, with the measurements in the
      prompt;
    - if that does not save review time either, drop it entirely.

### Analyst workflow

From the 2026-11-11 review of the project: the engine finds things, the analyst's
way into a case is the weak side. The user works in the `.db` with a SQLite
browser; the `.xlsx` is hardly used.

### AE-045 · hecha · Indexes and views in the machine `.db`
- 2026-11-11: the `.db` has no index and no view. Measure first (rows per table,
  size, build time on a real case), then: an index on the time column of the big
  tables, and a few views a SQLite browser shows as tables (every alert of the
  host in one, logons with the type spelled out). An index does not speed up a
  "contains" filter; say so in the docs.
- 2026-11-11 measured on copies of four real `.db` (1.4 to 12.6 GB): an index
  costs about 1 s and 27 MB per million rows; by hour, by exact value and
  "newest 100" went from 1.5-6 s to none; "contains" 2 to 5 times faster.
- 2026-11-11 built, not committed (the v0.7.198 release is still uncommitted on
  `dev/web-sigma-fork`; this is the next version): `core/dbnav.py`, called at the
  end of both builds; config `db_indexes`; views `v_alerts` and `v_logons`;
  README "Working in the `.db`". The four `.db` grew 20-29% and took 10-77 s
  more; both views answer in hundredths of a second. 21 tests, each proven by
  undoing its guarantee. Left: a full run over the real cases (AE-075, with the
  user), then the release.
- 2026-11-12: the five findings of the correctness review are fixed, each with
  its test (28 guarantees proven by undoing them); the suite passes on 3.13
  (1756). Still not run on 3.10: uv's interpreter loses its python.exe on this
  host after every reinstall.
- 2026-11-13: released in v0.7.199 after a run over the 4 real cases (every engine
  `.db` has the views; the 2 parser errors are art_mem_info on two old lab memory
  images Volatility cannot read, not this change). scripts/check.py (AE-058) in
  the same release.
- Ideas kept out of this cut: a table of what each table is (name, rows,
  description from the manifest) readable in the browser; the MCP `list_tables`
  naming the views.

### AE-046 · hecha · One timeline per machine
- 2026-11-11: only logons and web requests have one. A `timeline` table of
  time, source table, rowid and a short summary over the small sources (alerts,
  execution, logons, persistence, service and task installs, downloads). The MFT,
  the USN and the full EVTX channels stay out: the timeline points at an hour and
  the indexes of AE-045 take it from there.

### AE-047 · hecha · One database of every host's alerts
- 2026-11-11: one `.db` per machine cannot be joined across hosts and `sweep`
  only searches values. A case-level database holding the `alert_` tables (and
  the timeline of AE-046) with a `host` column.

### AE-048 · hecha · A way into the case: findings per host
- 2026-11-11: `run-summary` counts parsers, not findings, so nothing says which
  of many hosts to open first. Findings per host and level in the summary, and a
  self-contained HTML page for the case like the lateral and web ones.

### AE-049 · hecha · `emit_xlsx` off by default
- 2026-11-13: AE-046 to AE-049 released in v0.7.200. AE-046 is a view
  (`v_timeline`), not a table: nothing stored, and case.db (AE-047) copies it.
  case.db and case.html each had a fresh-context correctness review; the eight
  findings are fixed, each with a test proven by undoing it.
- 2026-11-11: the `.xlsx` pass dominates consolidation and the user does not
  open it. Default to `false`; say in the README how to turn it on.

### Engine and performance (measure first)

### AE-111 · pendiente · The scheduler hashes the rule sets once per task, in the parent
- 2026-11-12 measured (30 synthetic machines with nothing to parse, the real
  parser set): the parse phase takes 32.6 s, 29.4 s of it in 2,100 calls of
  `asset_state.digest` -- one per cached task before dispatch and one per task in
  `_pump`, which is the loop that hands work to the pools. The largest set is
  4,436 files (0.8 s warm, 8 s cold). Kept per parser for the pass: 9.1 s.
  The rest is tasks dispatched only to answer "artifact missing": the `requires`
  test for 1,830 of them takes 0.07 s in the parent. Do both; the second replaces
  AE-033.

### AE-112 · pendiente · Phase durations in run-summary.json
- 2026-11-12: the summary has the wall time and the slowest parsers, not how
  long hashing, extraction, parsing, consolidation and the graph took: what
  consolidation costs on a real case cannot be read from anything a run leaves.

### AE-113 · pendiente · Per-member overhead in extraction
- 2026-11-12 measured by the reviewer: a `mkdir` per member (about 77 s per
  million), a collision key built a character at a time (9.3 us against 0.6),
  `tarfile` keeping every member's record (about 460 MiB per million, per
  worker), and `is_container` calling `stat` before it looks at the suffix.

### AE-114 · pendiente · Serial and doubled work around the pools
- 2026-11-12: the per-unit report loop runs in the parent one unit after another
  and each opens its `.db` (1.8 s for one synthetic 627 MiB database); the two
  parse pools together reach twice `max_workers` (20 + 20 on 20 cores) while
  hayabusa and EvtxECmd use several threads each. Measure before changing; the
  second belongs with AE-032.
- Judged, not worth it: loading the CSVs without pandas is 1.4 times faster
  (5.0 s against 3.5 s for 142 MB) and loses the type inference.

### AE-044 · pendiente · alert_win_sigma's MFT pass
- 2026-11-08: the slowest task of a real 4-host run (max 361 s of 656 s wall), and on
  the critical path after the MFT parse. Measure which file rules cost the most
  over the MFT/USN before changing anything.

### AE-031 · aplazada · Overlap consolidation with the remaining parse tasks
- 2026-11-05: start a machine's consolidation when its tasks finish.

### AE-032 · aplazada · Longest-first scheduling and per-tool caps
- 2026-11-05: dispatch long parsers first, semaphores for heavy tools, a
  slowest-pairs report.

### AE-033 · aplazada · Cache artifact-missing skips under the fingerprint
- 2026-11-05: skipped tasks re-dispatch every run (not missing-tool skips).
- 2026-11-12: measured and given a simpler fix in AE-111.

### AE-034 · aplazada · MFT.csv memory during parallel consolidation
- 2026-11-05: pandas reads the whole file; not seen since v0.7.115.

### AE-035 · aplazada · Web case hot spots
- 2026-11-05: web_access gzip-bound, web_metrics post-step, consolidation time.

### AE-036 · aplazada · Console for many-machine runs
- 2026-11-05: per-machine parse lines, blank screen after parsing, duplicate
  summary, counters.

### AE-037 · aplazada · Pin the downloaded tools' hashes
- 2026-11-05: EZ tools and SIDR, once known.

### AE-038 · aplazada · Port `aeng mcp` to mcp 2
- 2026-11-05: 2.x renamed `FastMCP`; the extra is capped `<2` and Dependabot
  ignores the major until the port is done.

### AE-039 · aplazada · Batch rename of Linux handler modules to current names
- 2026-11-05: renaming changes fingerprints; do it together with another
  re-parse.

### AE-040 · aplazada · Hayabusa extract-base64 panics on a corrupt EVTX
- 2026-11-05: an upstream panic makes one parser error on every run; decide
  warning vs. upstream report.

### AE-041 · aplazada · Default settle time for archives still being sealed
- 2026-11-05: with settle 0, an archive is opened before its seal lands.

### AE-042 · aplazada · Linux Volatility plugins failing upstream
- 2026-11-05: linux.elfs and linux.malfind fail inside Volatility on two images;
  reported, no fix.

### Repository and process

### AE-115 · pendiente · Functions too long to test, and one verdict expression
- 2026-11-12: `scheduler.run_all` (348 lines, complexity 52), `report.
  build_run_summary` (268, with the status decided inline), `consolidate.build`
  and `_build_merged` (two copies of one structure). Cut the verdict into a pure
  function first: it is where AE-107 and AE-108 land. Also: the run statuses are
  bare strings in 68 places (`Literal`), the summary is an untyped dict built in
  three places (`TypedDict`), `_q` exists four times and `_file_digest` twice.

### AE-116 · pendiente · A type checker and wider lint in CI
- 2026-11-12: no mypy or pyright; 84% of `core` and 60% of `handlers` functions
  are fully annotated. Ruff runs its default set: the families that find bugs
  (`B`, `PERF`, `SIM`, `RUF`) report a few hundred lines, to be taken one family
  at a time. `tests/test_parsing.py` is 5,720 lines and 237 tests in one file.

### AE-054 · aplazada · SECURITY.md, CONTRIBUTING.md, package metadata
- 2026-11-05: rules live only in the gitignored CLAUDE.md; pyproject description
  still says KAPE/UAC only, no URLs or keywords.

### AE-055 · aplazada · web_metrics CSV export named after a removed table
- 2026-11-05: still `web_ip_stats`.

### AE-058 · pendiente · A local process for developing and testing the tool
- 2026-11-11: asked by the user in the review session, scope still to be agreed.
  Today: pytest + ruff by hand, the hooks at commit, the py310-venv and
  verify-real-cases skills, CI after the push. Candidates: one command that runs
  what CI runs (ruff, pytest on 3.13 and 3.10, the atlas check) before a push; a
  synthetic case built by a script so the whole pipeline runs end to end with no
  real evidence; the procedure written down in CONTRIBUTING.md.

### AE-056 · pendiente · Documentation for the person using the tool
- 2026-11-11: the README (916 lines) serves the user, the contributor and the
  design record at once. Wanted by the user: easier to reach and to follow.
  - README of about 150 lines: what it is, install, first run, where to go next.
  - `docs/GUIDE.md`: the run is over, what to open and in which order; a
    cookbook of SQL queries; the statuses (`cached`/`skipped`, `partial`/`damaged`)
    in one glossary; `sweep` and the MCP server as ways to investigate.
  - A reference page: configuration keys, outputs, exit codes.
  - `aeng run --help` with examples; `atlas.html` readable from GitHub (Pages).
  - Ask the user whether the guide is wanted in Spanish.

### AE-057 · pendiente · ARCHITECTURE.md says how it works today
- 2026-11-11: 23,000 words, 138 version mentions, one table cell of 5,373
  characters. Move the history and the measurements to the CHANGELOG (or ADRs)
  and keep what a contributor needs; it is also what every session reads.

### Waiting on the user

### AE-070 · bloqueada (usuario) · Close Dependabot PRs #7 and #8 on GitHub
### AE-071 · bloqueada (usuario) · Install and log in to `gh` here
- 2026-11-05: lets a session read failed CI logs.
### AE-072 · bloqueada (usuario) · GitHub settings: Dependabot alerts, secret scanning, CodeQL, main ruleset
### AE-073 · bloqueada (usuario) · Drop Chainsaw leftovers and obsolete tool folders under tools/
### AE-074 · bloqueada (usuario) · Delete scratch evidence copies on the Linux VM and WSL
- 2026-11-05: 14 copies, one about 50 GB; each deletion confirmed by the user.
### AE-075 · bloqueada (usuario) · Re-run all real cases with the user present
- 2026-11-05: a full re-parse is owed since v0.7.171; the KAPE case was re-run on
  v0.7.187 (0 errors).
### AE-076 · bloqueada (usuario) · Populate the YARA-Forge assets locally
- 2026-11-05: `aeng setup` / `aeng update`; host AV may need an exclusion.

### Waiting on evidence

### AE-090 · bloqueada (evidencia) · PCA on a real Windows 11 22H2+ collection
- 2026-11-05: also confirms `art_pca_general`'s community field order.
### AE-091 · bloqueada (evidencia) · WMI CCM RUA binary-header path of OBJECTS.DATA
### AE-092 · bloqueada (evidencia) · MDATP threats and quarantine branch

## Closed

### AE-026 · descartada · Sigma prefilter keeps one literal per AND
- 2026-11-08: measured on the largest host: checking every AND side would pass 0.06% of
  rows instead of 59%, but a per-rule second gate in Python costs more (158 s) than
  the SQLite scan it saves (~125 s). The cause is one rule over a full Windows\Temp;
  adapting that rule (AE-027) fixes it without touching the shared prefilter.

### AE-030 · descartada · Skip VSS snapshot runs whose inputs match the live volume
- 2026-11-08: VSS are not parsed by default (avoid_vss), no local case has them, and the
  costly inputs (MFT, USN, EVTX, hives) always differ between snapshots. If VSS
  cases appear, a "present in the snapshot, not live" table is the useful feature.

### AE-014 · hecha · YARA score as `level` for disk hits
- 2026-11-08: v0.7.193: alert_yara / alert_yara_linux write `level` from the rule's
  score (75+ high, as alert_mem; 40+ medium; below, low). No score (the bundled
  rules): empty, the row stays flagged.

### AE-015 · hecha · Re-scan when the YARA rules change
- 2026-11-08: already done by asset_state (v0.7.160): `assets/yara` with
  signature-base and YARA-Forge inside is digested per run; the entry was stale.

### AE-025 · hecha · alert_win_sigma cost
- 2026-11-08: v0.7.192: measured, the file rules over the MFT/USN were the cost; rules
  that need a field the disk never fills (Image on a file event) are dropped before
  the gate (sigma_prefilter.never_true). Real case, four hosts: 41-306 s -> 26-248 s,
  identical rows. Rest: AE-026.

### AE-023 · hecha · Missing hack-tool names in suspicious_tools.txt
- 2026-11-08: v0.7.192: the binary names of SigmaHQ's HackTool process rules that the
  list missed (Impacket `*_windows.exe`, winPEAS builds, potatoes, wce, PCHunter...);
  generic Windows binaries the rules also name are left out.

### AE-022 · hecha · Machine-readable rejections in sigma-inbox
- 2026-11-08: the session summary gives the acceptance rate and the rejected
  categories; below 50% it suggests a separate LLM reviewer.

### AE-024 · hecha · Windows Sigma over the engine's own tables
- 2026-11-08: v0.7.191: alert_win_sigma (prefetch, amcache, shimcache, LiveResponse,
  MFT, USN, registry, netstat). Real case: 50 rows over four hosts after calibration.
  Found on the way: `|re` rules never matched in any Sigma parser (fixed).

### AE-021 · hecha · Harder gate in the public rules repository
- 2026-11-07: the daily-brief model writes rules and grades them with its own
  tests. tools/validate.py gains: at least 2 test-match and 1 test-nomatch, each
  nomatch sharing a field value with a match (a legitimate use of the same tool),
  no IP or hash in detection, no "unknown" false positives, status experimental,
  a benign corpus (tests/benign/) no rule may match, and an overlap check against
  the rules already in the repository. The model then runs this validator only.
- 2026-11-08: done in the rules repository (not an engine version): `validate.py --fix` does id/date/status/order/name; checks fields per source, Sysmon-only categories, near-miss tests, benign corpus, field=value overlap; loopback is not an IOC. First inbox run: 9 accepted, 1 merged, 1 rejected.

### AE-077 · hecha · Force-push the squashed history of artifact-engine-sigma
- 2026-11-07: local main is one clean commit; the guard hook blocks force-push, so the user runs it.
- 2026-11-08: the user force-pushed; the public history is one clean line.

### AE-020 · hecha · The user's own Sigma rules (from the wiki) as detections
- 2026-11-07: user asked to use the Sigma rules they write, kept in the wiki, as
  new detections. Survey format and logsources, then decide how they ship.
- 2026-11-07: survey: 6 rules, embedded as ```yaml blocks in daily notes (5
  windows/process_creation, 1 windows/system). The engine has no analyst Sigma
  folder today; EVTX rules run only through hayabusa's fixed rules folder; rule
  files are outside the parser fingerprint (a new rule re-scans nothing).
  Proposed design sent to the user: `aeng sigma sync` (wiki -> validated local
  rules folder, outside the public repo), routing per logsource, rules hash in
  the fingerprint of the parsers that use them, `aeng sigma coverage` report,
  a writing guide in the wiki. Waiting on the user's OK.
- 2026-11-07: user: NO sync command (too specific to them). Instead an inbox on the
  NAS (ArtifactEngine-sigma: inbox/accepted/rejected, README, an LLM prompt
  tuned to our evidence) reviewed at session start (skill sigma-inbox). Still
  needed in the engine: read an analyst rules folder (config path, outside the
  repo) in hayabusa, lin_sigma, lin_web_sigma and mem_sigma, with the rules'
  hash in those parsers' fingerprints so new rules re-scan parsed cases.
- 2026-11-07: v0.7.190: config key `sigma_rules_repo` (default: the public
  artifact-engine-sigma repository, "" turns it off). `aeng update` mirrors its
  rules/ into assets/sigma_custom and hayabusa's rules/aeng_custom; lin_sigma,
  lin_web_sigma, mem_sigma and hayabusa read them, and a change re-runs them.


### AE-005 · hecha · Linux host with no /var/log gets no log-coverage table
- 2026-11-07: v0.7.189: a KAPE, UAC or evtx machine with a .db and no coverage table now says `Log coverage: NOT MEASURED` in report.txt.

### AE-002 · hecha · A re-run hashes the engine's own outputs as originals
- 2026-11-07: v0.7.189: the only engine output missing from the root exclusions was web_metrics.html at a machine detected at the root; added for that layout only.

### AE-004 · descartada · A bare Velociraptor folder is opened mid-copy
- 2026-11-07: already fixed in v0.7.129: arrival.delivered surveys <root>/Velociraptor/LiveResponse.zip; only LiveResponse.zip is extracted at all.

### AE-003 · descartada · Leftovers of a failed extraction are parsed as a machine
- 2026-11-07: already labelled: a failed or partial extraction is named in the machine's report and makes the run incomplete (v0.7.128). The one unlabelled case, a machine detected at the case root with its own failed sibling archive, is left out by design to avoid flagging every host of a multi-host case.

### AE-001 · hecha · Case identifiers left in a test and the README
- 2026-11-05: v0.7.188, placeholders (three names) in the test and the docs; both strings added to the commit hook's blocklist.

### AE-050 · hecha · CHANGELOG.md, written at each release
- 2026-11-05: CHANGELOG.md started (v0.7.187 + Unreleased); written at each release by the documentalista.

### AE-051 · hecha · Archive the history in .claude/NEXT.md
- 2026-11-05: history moved to .claude/archive/; NEXT.md is now 9 lines of session state.

### AE-052 · hecha · Skills for the repeated procedures
- 2026-11-05: skills py310-venv, rename-table and verify-real-cases, each with a script.

### AE-053 · hecha · Backup of what git does not hold
- 2026-11-05: release-version step 7 runs scripts/backup.py; first backup taken for v0.7.187.

### AE-000 · hecha · v0.7.187 alerts and artifacts
- 2026-11-05: tables are `alert_` or `art_` with a matching `kind:`; atlas in two
  tables; all descriptions rewritten. Released `1968584`.

## Judged, not built

| Artifact | Why not |
|---|---|
| ThumbCache | answers "this image existed"; the MFT already has the name |
| RDP bitmap cache | output is image tiles, a manual deep dive after the graph points at a session |
| `Syscache.hve` | only with a registry pass that happens anyway |
| ETL traces (WMI, WDI, SleepStudy, DeliveryOptimization) | needs an ETL decoder; only DeliveryOptimization has clear triage value |
| `$LogFile`, `$SDS`, `$Boot`, `$T` | `$LogFile` analysis is specialist and spans hours; `$SDS` answers only ACL questions |
| .NET CLR usage logs | Prefetch and Amcache usually carry the same execution |
| P2P / torrent / IRC clients | not in `!SANS_Triage` |
