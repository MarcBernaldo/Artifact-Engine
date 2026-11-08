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
  (v0.7.194, rules untouched: same alerts on the real case). Phases and method in
  the sigma-fork skill: 2 file_event/file_delete (86 rules need a field the disk
  lacks), 3 registry (45 + state-only), 4 network (24), 5 process_creation from
  prefetch/amcache/shimcache (~1030 need more than Image). Not adaptable ->
  `aeng/not-adaptable.txt` in the fork.

### Engine and performance (measure first)

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
