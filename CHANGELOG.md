# Changelog

One entry per release, newest first. The detail of each change is in its commit
messages; open work is in [docs/BACKLOG.md](docs/BACKLOG.md).

## Unreleased

## v0.7.200 — 2026-11-13

- `case.html` at the case root says which host to open first: every host with
  its findings per level, most severe first, links to its `report.txt` and `.db`,
  and its fifteen most severe findings. `run-summary` carries the same counts
  (`findings_per_host`).
- `case.db` at the case root: every host's alerts and timeline, and each alert
  table of every host as one table, with a `host` column, so a question about
  the whole case is one query.
- The machine `.db` has a third view, `v_timeline`: alerts, logons, prefetch
  runs, Amcache programs, service and task installs, downloads, shell history,
  sudo, cron and package installs in one UTC order.
- The `.xlsx` is off unless asked for (`emit_xlsx: true`): the analyst works in
  the `.db`, and the `.xlsx` pass dominated consolidation.

## v0.7.199 — 2026-11-13

- The machine `.db` is built to be worked in a SQLite browser (`core/dbnav.py`):
  its tables of 100,000 rows or more are indexed on their time columns and on the
  column they are asked by (`EventId`, the MFT's `FileName`, the USN's `Name`, the
  web log's `source_ip`), and it holds two views, `v_alerts` (every finding of the
  machine, most severe first, with the table and rowid of the full row) and
  `v_logons` (Windows and Linux logons in one shape, the logon type as a word).
  Measured on four real hosts: 20 to 29% more `.db` and 10 to 77 s more
  consolidation; a question by hour over 17 million rows went from 4 s to none.
  `db_indexes: false` leaves the indexes out. Every case is consolidated again on
  its next run, without re-parsing.
- `scripts/check.py` runs before a push what CI runs after it (ruff, the suite on
  this Python and on 3.10), and with `--real` the engine over the real cases,
  printing only counts. CONTRIBUTING.md describes the loop.

## v0.7.198 — 2026-11-10

- `alert_web` reads SigmaHQ's web rules from the fork: `aeng update` mirrors its
  `rules/web` into `assets/sigma_disk_web`, with the web lines of its
  `not-adaptable.txt`, and the bundled copy is only the fallback. The one rule the
  fork added on the real web case repeated `scanner_ua`, which gains the five
  User-Agents only that rule had (commix, wfuzz, recon-ng, ffuf's own UA, GIS AppSec).
- `alert_win_sigma` reads Windows 7 prefetch paths (`\DEVICE\HARDDISKVOLUMEn\`) with
  their drive, so System32 programs no longer trip the "outside System32" rules.

## v0.7.197 — 2026-11-08

- `alert_win_sigma` runs the process rules over the command lines the host kept:
  every PowerShell console history line, scheduled task and service ImagePath
  becomes a process row with `CommandLine`, the `Image` it starts (its first word;
  a cmdlet, alias or expression in a history line runs in powershell.exe, which is
  then the parent of a program a history line starts) and the account. The
  command-line rules -- most of process_creation -- had only the live process list
  to match. The PowerShell and Sysmon event logs stay hayabusa's. The leading path
  is expanded as Windows runs it (`%SystemRoot%`, `\SystemRoot\`, `system32\...`,
  `%ProgramData%`, ...: unexpanded, every service was a "system file outside
  System32"), a bare name resolves to System32 when the volume or a clean install
  holds it there (the fork's `aeng/system32_names.txt`, mirrored by `aeng update`),
  and a script runs in its host (wscript.exe, cmd.exe). Real case: 3 new process
  alerts over four hosts, all findings.

## v0.7.196 — 2026-11-08

- `alert_win_sigma` names a connection: a netstat row gets `DestinationHostname`
  from the live response's DNS cache (the address an A/AAAA record resolved to; the
  alias a CNAME leads from wins, being the name the program asked for). The domain
  rules of network_connection (tunnels, file-sharing and messaging APIs) could not
  match before: the field was always empty.

## v0.7.195 — 2026-11-08

- `alert_win_sigma` reads every value of every hive (SYSTEM, SOFTWARE, SAM,
  SECURITY, each user's NTUSER.DAT and UsrClass.dat) with python-registry, Details
  written as Sysmon writes them, instead of the RECmd batch tables: those held a few
  hundred SOFTWARE values and no Run key, so the registry rules were blind, not
  quiet. The tables are still read when no hive is. Measured on the four hosts of
  a real case: 0.5-1.2 million values per host, a few seconds to walk.
- Over a hive's state a rule written for a change event fires on Windows' defaults.
  Two files of the fork, mirrored by `aeng update` into `assets/sigma_disk/aeng/`,
  take that out: `registry_baseline.tsv`, the values a clean install holds and a
  rule matches (built from VanillaWindowsRegistryHives: Win10/11 22H2, Server
  2019/2022), dropped before the rules run; and `not-adaptable.txt`, rules that are
  not run. New registry alerts per real host: about 35 without them, 6-10 with.

## v0.7.194 — 2026-11-08

- `alert_win_sigma` reads its rules from a fork of SigmaHQ where they are adapted to
  the engine's own tables: new config keys `sigma_disk_repo` (default
  github.com/MarcBernaldo/sigma) and `sigma_disk_branch` (default `aeng`). `aeng
  update` mirrors its Windows process, file, registry and network rules (a shallow
  sparse clone) into `assets/sigma_disk/`; `""` turns it off and the parser reads
  SigmaHQ's bundled and hayabusa copies as before. Hayabusa keeps the originals for
  the EVTX. The branch starts as SigmaHQ itself: same alerts on the real case, now
  with SigmaHQ's own rule ids.

## v0.7.193 — 2026-11-08

- `alert_yara` and `alert_yara_linux` gain a first column `level`, from the matching
  rule's `score` (75 and up high, the threshold `alert_mem` uses; 40 medium; below,
  low), so disk matches sit in their tier on the report's front page. A rule with
  no score (the bundled ones) leaves it empty and its match stays flagged.
- The memory YARA scan re-runs once on the next run of a parsed case: it shares
  the rule-loading module, whose code changed.

## v0.7.192 — 2026-11-08

- `alert_win_sigma` is faster: a rule that needs a field the disk tables never fill
  (a process `Image` on an MFT/USN file event, say) is dropped before the prefilter
  instead of letting most of the MFT through it. Same rows on the real case, 1.2-2x
  faster per host.
- `suspicious_tools.txt` names the SigmaHQ HackTool binaries it missed (Impacket's
  Windows builds, winPEAS builds, the potato family, wce, PCHunter, UACMe, htran/lcx,
  hashcat...). They reach `alert_suspicious_tools` and the command-line hunts.

## v0.7.191 — 2026-11-08

- New table `alert_win_sigma` (alerts only, the Linux Sigma header): SigmaHQ Windows
  rules over the engine's own tables -- process_creation over Prefetch, Amcache,
  ShimCache and the LiveResponse process list; file_event/file_delete over the MFT
  and the USN journal; registry rules over the RECmd tables; network_connection over
  the process-network table. Not EVTX (hayabusa) and not memory (`alert_mem_sigma`).
- Calibrated on a real case (about 100 rows down to 50 over four hosts): paths
  without their folder are not evaluated, USN folders come from the MFT, WinSxS,
  Windows\servicing and the collector's copy are skipped, and over registry state a
  rule must need the value, not only the key.
- Sigma `|re` rules now match in every Sigma parser. SQLite has no REGEXP, so they
  had silently matched nothing (7 Linux rules, 44 Windows process rules).

## v0.7.190 — 2026-11-07

- Extra Sigma rules from a git repository: new config key `sigma_rules_repo`,
  by default the public artifact-engine-sigma repository (`""` turns it off).
- `aeng update` mirrors its `rules/` into `assets/sigma_custom/` and hayabusa's
  `rules/aeng_custom/`, withdrawn rules included, and reports new, withdrawn and
  edited files. A failed git call keeps the last rules; an empty
  `sigma_rules_repo` removes them.
- The Linux, web and memory Sigma passes and hayabusa read those rules; a change
  re-runs only those parsers on cases already parsed.

## v0.7.189 — 2026-11-07

- A re-run no longer records `web_metrics.html` as a new original in
  `traces.txt` when the machine was detected at the case root.
- `report.txt` says `Log coverage: NOT MEASURED` for a KAPE, UAC or evtx host
  whose logs could not be measured (a Linux host with no `/var/log`), instead
  of printing nothing above a quiet findings section.
- v0.7.188's entry said two case identifiers were replaced; it was three.

## v0.7.188 — 2026-11-05

- `docs/BACKLOG.md` is the single work list (ids, states, dated notes); it
  replaces `docs/IMPROVEMENTS-BACKLOG.md`.
- Two identifiers from real cases left in a test and in a documentation example
  replaced with placeholders.

## v0.7.187 — 2026-11-05

- Every table is an alert (`alert_`, every row a finding) or an artifact
  (`art_`); the manifest key `kind: alert|artifact` replaces
  `alert: detect|flag|context`, and a test holds kind and prefix together.
- Twelve tables renamed to `alert_` (the hayabusa timeline and the Volatility
  checks that list only hits); `alert_collection` is now `art_collection`. Old
  tables are retired from parsed cases on the next run.
- The atlas lists Alerts and Artifacts in two tables; every parser and profile
  description rewritten in plain English, alerts with their fields and artifacts
  with what they flag.
