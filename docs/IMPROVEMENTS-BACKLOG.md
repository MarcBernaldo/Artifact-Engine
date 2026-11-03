# Improvements backlog

What is still open, one entry each with the reason it is worth doing. Items that
were built or dropped are not kept here: git holds every earlier version of this
file, with the reasoning that closed them. What each parser does today is in
[`atlas.html`](atlas.html) and `aeng list-parsers`.

## Detection and triage

- **Known-benign publisher allowlist.** Security agents, remote-support clients
  and vendor updaters trip the service and path rules on every host. Key it on the
  Amcache publisher + install path + service ImagePath and downgrade, never drop:
  the row stays, with the reason it was downgraded.
- **Package integrity, reasoned over (Linux).** `art_packages`' verification rows
  are parsed and nothing judges them. Two cheap rules: a package-owned shared object
  under a `security/` path failing its checksum (a PAM module replaced), and the
  same hash in the 32- and 64-bit library paths (impossible for a genuine library).
- **Uneven package-verification coverage.** Full verification finished on some
  hosts and covered a few dozen files on others; until the cause is known (a
  timeout, the collector profile, a silent failure), report the file count beside
  any "clean" verdict drawn from it.
- **BITS download URLs on the front page.** A BITS job `art_bits_jobs` flags
  reaches the findings like any flagged row; the unflagged URLs, and the
  `art_evtx_bits` channel, are never summarised. BITS is a standard download
  channel and its URLs belong beside the browser downloads.
- **The rest of the timeline.** The `timeline` view takes every table with one UTC
  time per row. MFT/USN, Prefetch, Amcache and registry key times carry several
  times per row, or times under other names; a windowed super-timeline over them
  needs a rule for which time is "the" event, per table.

## Sources collected and not read

- **PowerShell transcripts** (`Documents\20*\`, `C:\PSTranscript\`): the commands
  with their output and per-command times, surviving `Clear-History`; same shape and
  flags as `art_consolehost`.
- **Windows Firewall log** (`LogFiles\Firewall\pfirewall.log`): connection records
  on a host with no Sysmon; the parser should say "not enabled" rather than nothing.
- **osquery and chkrootkit results** (Linux, when collected): already findings;
  a few hours of text-to-rows, INFECTED rows flagged.
- **Configuration-management job caches** (Salt/Uyuni-class): which target got
  which job when, in directory metadata alone -- an operator's fan-out (many
  targets in one second) against an attacker's burst (one target, many jobs).
- **Storage the bodyfile did not walk** (Linux): `art_storage` reads `mount`, `df`
  and `blkid`; `findmnt`, `lsblk`, `zfs/zpool` and `lvs/pvs/vgs` are not read, so a
  pool or volume group blkid does not list stays invisible.
- **Firewall front-ends and the neighbour cache** (Linux): `ufw status` and
  `firewall-cmd` are not read, and `art_arp_cache` does not feed the lateral graph
  (layer-2 neighbours that never produced a log line).
- **Firefox downloads** (`moz_annos` / `downloads.sqlite`).
- **PCA's `PcaGeneralDb0.txt`**: only if its schema can be confirmed; wrong columns
  are worse than none.
- **Community lists not yet matched** (mthcht/awesome-lists): double extensions,
  `/Hijacklibs/` against MFT DLL paths, suspicious ports, hostnames, DynDNS and TLDs.
  The named-pipe, mutex, USB-id and firewall-rule lists need data disk triage does
  not collect. The large user-agent and DoH lists would change the web hunt's
  character: an opt-in second file at most.

## Validation waiting on evidence

- **PCA** is wired and unit-tested but never run on a real artifact: needs a Win11
  22H2+ collection with `C:\Windows\appcompat\pca`. The museum has none.
- **WMI CCM RUA**: the binary-header path of `OBJECTS.DATA` is unit-tested only on
  the XML path.
- **MDATP threats**: the threat/quarantine branch of `art_mdatp` is exercised only
  by fixtures; the acquisitions at hand had none.

## Engine

- **Pin the downloaded tools' hashes** (EZ tools, SIDR) once known.
- **Glob over evidence paths.** A directory name holding `[` or `]` is a character
  class to `glob`, which then matches nothing without an error. Audit the evidence
  walks for glob patterns built from evidence paths and move them to literal APIs
  (`iterdir`, `os.scandir`).

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
