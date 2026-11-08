# Changelog

One entry per release, newest first. The detail of each change is in its commit
messages; open work is in [docs/BACKLOG.md](docs/BACKLOG.md).

## Unreleased

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
