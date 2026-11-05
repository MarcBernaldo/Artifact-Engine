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

### AE-002 · pendiente · A re-run hashes the engine's own outputs as originals
- 2026-11-05: on a re-run, phase 0 hashes `run-summary.*` and `stale-outputs.txt`
  into `traces.txt` as new originals. Confirmed bug (custody: needs a
  diff-correctness review).

### AE-003 · pendiente · Leftovers of a failed extraction are parsed as a machine
- 2026-11-05: the detector ignores the extraction marker, so a failed archive's
  partial tree is parsed and reported like a clean machine.

### AE-004 · pendiente · A bare Velociraptor folder is opened mid-copy
- 2026-11-05: delivered alone, it is not surveyed for arrival; `delivered()`
  needs to widen its scope to it.

### AE-005 · pendiente · Linux host with no /var/log gets no log-coverage table
- 2026-11-05: truncated Linux acquisitions get no coverage statement; the parser
  skips silently although its docstring promises a row saying so.

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

### AE-014 · aplazada · YARA score as `level` for disk hits
- 2026-11-05: `alert_yara` has `score` but no `level`, so its rows reach Findings
  unrated.

### AE-015 · aplazada · Re-scan when the YARA rules change
- 2026-11-05: the assets are outside the parser fingerprint, so new rules do not
  re-run the scan on a parsed case.

### AE-016 · aplazada · cmd_hunt reads Security 4688 command lines
- 2026-11-05: still excluded (user instruction 2026-10-11); revisit if asked.

### AE-017 · aplazada · Linux memory findings
- 2026-11-05: no alert_mem equivalent for Linux images (malfind, modxview,
  hooked syscalls, ptrace, bash history).

### AE-018 · aplazada · Sudoers flags never reviewed for false positives
- 2026-11-05: five flags on one host were not reviewed.

### AE-019 · aplazada · Last run for anacron and periodic scripts
- 2026-11-05: `art_tasks` last-run matches exact crontab commands only.

### Engine and performance (measure first)

### AE-030 · aplazada · Skip VSS snapshot runs whose inputs match the live volume
- 2026-11-05: probably the largest win on hosts with many snapshots.

### AE-031 · aplazada · Overlap consolidation with the remaining parse tasks
- 2026-11-05: start a machine's consolidation when its tasks finish.

### AE-032 · aplazada · Longest-first scheduling and per-tool caps
- 2026-11-05: dispatch long parsers first, semaphores for heavy tools, a
  slowest-pairs report.

### AE-033 · aplazada · Cache artifact-missing skips under the fingerprint
- 2026-11-05: skipped tasks re-dispatch every run (not missing-tool skips).

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

### AE-054 · aplazada · SECURITY.md, CONTRIBUTING.md, package metadata
- 2026-11-05: rules live only in the gitignored CLAUDE.md; pyproject description
  still says KAPE/UAC only, no URLs or keywords.

### AE-055 · aplazada · web_metrics CSV export named after a removed table
- 2026-11-05: still `web_ip_stats`.

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
