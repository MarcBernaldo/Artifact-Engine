# Improvements backlog — lessons from Windows/Linux triage runs

Everything here comes from analysis work where the tool was the bottleneck: a finding that
took manual SQL to reach, a conclusion that a coverage gap almost inverted, or noise that
cost an hour. Values are shapes and placeholders (`HOST-01`, `10.0.0.5`, `evil.example`),
never case content.

Each item says what to build, where it plugs in, and why it earns its place. Verified
against the tree: items marked **(exists)** are already there and the gap is elsewhere.

---

## P0 — Evidence integrity: things that change conclusions

### 1. Windows log-coverage map (per channel, per day, with gap classification)

**Symptom.** Two hosts in one case had a security channel that was dark exactly across the
interesting window. On one, the channel held only the last ~10 days, so a connection three
weeks earlier had no logon/process context at all. On the other, the channel went silent for
five days while its sibling channels kept logging normally. Both times the honest answer was
*"no coverage"*, and both times it took manual `group by substr(TimeCreated,1,10)` queries to
discover that — after already drafting a conclusion that assumed the silence meant nothing
happened.

`lin_log_integrity.py` already argues this exact point in its docstring:

> *"how far back does this host's logging actually reach? A host holding a day and a host
> holding a year both produce an auth.csv, and only one of them has anything to say about an
> intrusion from last month."*

The Windows side has no equivalent.

**Build.** `win_log_integrity.py` + `log_integrity.yaml` (windows), computed at consolidation
from the already-parsed `evtx_*` tables — no new extraction needed.

`log_coverage` table: `channel, first_event_utc, last_event_utc, event_count, days_covered,
max_gap_days, gap_start_utc, gap_end_utc, verdict`.

Gap classification is the valuable part:
- **capacity** — channel is full/rotating and simply doesn't reach back (uniform density, gap
  only at the start of the window);
- **unexplained silence** — channel dark while sibling channels on the same host keep logging
  through the same period. This is the one worth an analyst's attention.

Also surface explicitly, as their own rows: `1102` (security log cleared), `104` (log cleared),
`4719` (audit policy changed). Their *absence* is evidence too — say so, rather than leaving
the analyst to infer it.

**Report.** A section in `report.txt`, always printed, even when clean. The point is that a
reader sees the coverage before they read the findings.

---

### 2. Collection self-artifacts must be identified and excluded

**Symptom.** The collection tool's own output tree lives inside the image it collected, so every
collected path appears twice in the MFT. Searches returned dozens of duplicate hits under the
operator's download folder. Separately, the operator's local profile is created minutes before
acquisition and their admin logons land in the security log — which read as an intrusion until
correlated with the acquisition timestamp.

**Build.** `collection_artifacts` table, detected from:
- a directory tree whose layout mirrors the collection output (a `result/`-shaped subtree
  containing the same volume roots as the acquisition);
- user profiles created within N minutes of the acquisition timestamp;
- logons inside the acquisition window.

Exclude from MFT/bodyfile queries **by default**, with `--include-collection` to override, and
list them in `report.txt` under "collection artifacts, not host activity".

---

### 3. Timestomp detection (ctime vs mtime)

**Symptom.** An attacker copied a reference file's timestamps onto their own artifacts
(`touch -r`-style). Every dropped file then carried a years-old mtime. What gives it away is
that `ctime` cannot be set this way: on the tampered files, ctime was the real drop time and
mtime was years earlier. This turned a confusing "magic date" observation into a durable rule,
but it was derived by hand every time.

**Build.** A `timestomp` table, populated for both OS families:
- Linux `bodyfile`: `ctime_utc - mtime_utc > threshold` (start at 30 days), excluding known
  package-install patterns;
- Windows MFT: the same delta on `$SI`, plus the existing `SI<FN` column — which the MFT parser
  already computes and nothing currently reports on.

Rank by delta; a multi-year delta on an executable in a temp or system directory is close to a
finding on its own.

---

## P1 — New parsers and detectors with proven value

### 4. Defender Operational: parse it properly (`win_defender.py`)

**Symptom.** `evtx_defender.yaml` is a bare EvtxECmd dump — no handler. Yet on a host with no
Sysmon and no process-creation auditing, the Defender Operational channel was the **only
surviving record of process execution**: events 1116/1117 carry the offending **command line**
in the payload, prefixed `CmdLine:_`, together with the action taken. An entire intrusion chain
— connectivity check, payload download, credential-access command — was recoverable only from
there, and only after decoding JSON payloads by hand.

**Build.** `defender_detections` table:

| column | source |
|---|---|
| `time_utc`, `detection_id` | event header (detection_id groups retries of the same attempt) |
| `threat_name`, `severity`, `category` | payload |
| `path` / `command_line` | split the payload's path field — a `CmdLine:_` prefix means it is a command line, not a path |
| `process_name`, `detection_user`, `detection_source` | payload |
| `action_id`, `action_name`, `remediation_user`, `error_code` | payload |

Two things that mattered and are invisible today:
- **whether the detection was acted on.** "Detected" and "removed" are different incidents.
  Action id 9 (*not applicable*) next to action id 2/3 (*quarantine*/*remove*) on the same
  `detection_id` tells you which attempt in a retry sequence actually got cleaned — and, by
  omission, which one succeeded.
- **tamper events**: 5001/5007 (real-time protection disabled, settings changed) belong in the
  same table as first-class rows.

### 5. Service installation analysis → remote-execution detector

**Symptom.** The actual entry mechanism on one host was a burst of ephemeral services, each
running `cmd /c <temp>\<random>.bat > <temp>\<same>.txt 2>&1` under LocalSystem, service names
being 8 random uppercase letters, all deleted after running. That is the classic
remote-execution-over-SMB signature. It surfaced only as generic *medium* sigma hits buried in
a 1,500-row table, and was found by reading dumps by hand — nine days of attacker presence that
the first pass over the host had missed entirely.

**Build.** `service_installs` from `7045`, joined against `reg_services`, plus a
`remote_exec_services` detector scoring these rules:

1. ImagePath matches `cmd(.exe)? /c <path>.bat` **with stdout/stderr redirected to a sibling
   `.txt`** (the tool reads the output back over SMB — this redirect is the tell);
2. service name high-entropy / matches `^[A-Z]{8}$`;
3. **present in `7045` but absent from current `reg_services`** → created and deleted. The
   engine already has both sides of this join and does nothing with it;
4. ImagePath under a temp/staging directory;
5. service name mimics a system component while ImagePath sits in a temp directory.

Confidence = rules matched. Three or more is a finding, not a hint.

### 6. SMB client connectivity parser + outbound-SMB detector -- **DONE** v0.7.34 (`smb_client`)

**Symptom.** A server attempted outbound SMB to an external address. The only record was in
`Microsoft-Windows-SMBClient/Connectivity` (event 30803), which no parser reads — it was found
via a generic sigma sweep, under a rule name that named a CVE the host could not even be
vulnerable to (no such application installed). The rule name misleads; the underlying behaviour
is the finding.

**Build.** `smb_client_connections` from the SMBClient `Connectivity` / `Security` /
`Operational` channels:
- decode `RemoteAddress` (sockaddr hex) → IP + port. Add a reusable `sockaddr_from_hex()`;
- decode `Status` (decimal NTSTATUS) → symbolic name. Add `ntstatus_name()`. A refused
  connection and a completed one are very different findings and today both are an opaque
  10-digit integer;
- keep `ServerName` as given.

Detector: **a host initiating outbound SMB to an address outside the configured internal ranges**
(see §9). For a server whose role is to *receive* SMB, that inverts the expected direction and is
high signal for hash-capture / relay / C2.

### 7. Credential-access detector (no IOCs required) — **DONE** v0.7.31 (`credential_access`)

Windows only, over the transcoded `$MFT`. The Linux twin is not built: the families differ
enough (`/etc/shadow` copies, `.aws/credentials`, kubeconfig, keytabs) that it is its own
list of names and homes, while the staging heuristic and the archive pass carry over
unchanged. Worth doing next time the bodyfile side is open.

**Symptom.** A credential harvest staged a directory tree containing copies of SSH `known_hosts`,
browser credential databases, DPAPI master-key material and registry hives, then archived and
deleted it. Every piece was visible in the MFT and none of it was flagged; it was found by
manually listing a temp directory.

**Build.** A `credential_access` table, name-and-location based:

- registry hive names (`SAM`, `SYSTEM`, `SECURITY`, `NTDS.dit`) **anywhere outside their
  legitimate path** — trivial rule, very high signal;
- DPAPI material outside its own user profile (`Protect\CREDHIST`, `Protect\S-1-5-21-*`);
- browser credential stores (`Login Data`, `Login Data For Account`, `Web Data`, `key4.db`,
  `logins.json`) outside a browser profile;
- SSH material outside `~/.ssh` / `%USERPROFILE%\.ssh`;
- **staging heuristic**: a single directory holding ≥2 of the families above → report the whole
  tree as one finding, not N unrelated rows;
- an archive created within minutes of such a directory, **including deleted ones**
  (MFT `InUse=0`) → packaging for exfiltration.

The staging heuristic is what turns a dozen scattered file rows into a single sentence an
incident lead can act on: *these credential classes left this host*.

### 8. Recover IOCs for executables that are no longer on disk

**Symptom.** The payload deleted itself. Its SHA1 survived in Amcache, and that hash is the only
distributable IOC the case produced for it — but finding it meant knowing to look.

**Build.** `recovered_iocs`: Amcache/Shimcache entries whose path no longer resolves in the MFT
(or resolves to `InUse=0`), with `path, sha1, size, version, product_name, first_seen`.
Add a `report.txt` section — "executables seen running that are not on disk now" — which is
directly pasteable into an EDR hunt.

Add a masquerade check while there: a **file-version or product string inconsistent with the
host OS build**, or a system-binary name living outside its system path. A payload named after a
system utility, carrying a version string from a different Windows generation, is a rule that
costs ten lines and catches a whole technique class.

---

## P2 — Noise reduction (this is analyst hours)

### 9. `internal_networks` config — **DONE** (v0.7.32 `core/netclass.py`, v0.7.35 `sigma_sources`)

Built: the classifier, the `internal_networks` config key (validated at load, unreadable
entries reported and ignored), and the lateral graph — a declared source is reclassified from
`public` to `internal`, loses `rdp_public`, and gets a `src_scope` column in
`lateral_movement.csv`. Nothing is deleted, and the run summary reports how many hosts the
declaration actually matched.

v0.7.34 added `ParserContext.internal_networks` -- the only channel configuration has into a
handler -- because §6's outbound-SMB detector needed it, and paid the re-fingerprint of every
python parser once.

v0.7.35 closed the rest as `sigma_sources`: hayabusa's timeline aggregated to one row per (rule,
source address), carrying the scope of that source, and DOWNGRADED with the reason written beside
it where the rule's own premise is that the source is public. Two decisions worth keeping:

- the downgrade markers were read off the shipped ruleset, not guessed. Of 4,959 rules the ones
  whose premise is a public SOURCE all phrase it "Logon from Public IP" / "Logon from External
  Network"; a substring match on `public ip` would also have quietened `Outbound Network
  Connection To Public IP Via Winlogon`, which is about a DESTINATION and where an internal
  source means nothing. Everything else keeps its level -- a rule firing from an internal address
  is lateral movement, the last thing to quieten.
- hayabusa's own CSV is never rewritten. A tool's verdict is evidence and the engine's reading of
  it is not the same thing, so this is a second table beside it, and the detections that name no
  source are counted and reported rather than quietly excluded.


Organisations with publicly-routable internal address space (universities, large enterprises)
make generic sigma rules fire constantly — "external logon from public IP" on every ordinary
internal file-share access, hundreds of high-severity rows that are all noise. Triaging them by
hand, per host, is pure waste, and the real risk is that the analyst starts ignoring the rule
class.

Add a case/org-level CIDR list. Apply it to: sigma/hayabusa post-filtering (**downgrade with a
reason, never delete**), lateral-graph classification, and the outbound-SMB detector in §6.
`core/lateral.py` already carries private-range logic — generalise it into `core/netclass.py`
and share it.

### 10. Known-benign publisher allowlist

Security agents, remote-support clients, PC-maintenance utilities and vendor updaters trip
"suspicious service name/path" rules on every host. Key an allowlist on Amcache `Publisher` +
install path + service ImagePath; downgrade to informational **with the reason shown**. Never
silently drop — the analyst must be able to see what was suppressed and why.

### 11. `report.txt`: a ranked "top anomalies" section

The findings from §4–§8 need a front page. Today the high-value rows live inside generic
detection tables of one to two thousand rows each, and reaching them means reading dumps.
Rank by detector confidence, print the evidence pointer (table + rowid) so the analyst can go
straight to the underlying row.

### 12. Host timezone in `machine_info`

Available from the registry (`TimeZoneInformation`) and from system log events. Without it,
multi-host cases mix UTC and host-local reasoning across reports — an error source that has
already caused one wrong timestamp claim mid-analysis. Record it once, render both.

### 13. `aeng sweep` — **DONE** v0.7.33 (the feature existed; discoverability was the gap)

`aeng sweep -p <case> -q <value>` already does the cross-machine, all-table search that got
hand-rolled in ad-hoc Python a dozen times during this investigation, including for the exact
IOC-check-across-the-estate task. The feature was not the gap; **discoverability was**.

- print a pointer in every `report.txt`: *"to check a value across the whole case:
  `aeng sweep -p <case> -q <value>`"*;
- add `--ioc-file` for bulk lists (an IOC list from a partner arrives as twenty values, not one);
- add CSV output so results feed a bitácora directly;
- consider extending the sweep to raw evidence text files, not only the per-machine databases.

**Built in v0.7.33.** The report.txt pointer was already there (v0.7.23) and now names the bulk
forms too. `--ioc-file` reads a list the way people actually paste one (quotes, trailing commas,
`#` headers) and an unreadable file is an ERROR, not zero values -- a sweep of nothing reads
exactly like a clean case. `--csv` writes the whole sweep, not the hits: the values that matched
nothing, the machines that could not be opened, and the rows held back as the collection's own
copy. The LIKE terms are batched, because one OR per needle per table stops being something
SQLite plans well past a couple of hundred values.

**Still open: the raw-text sweep.** It is a different feature, not a flag on this one. Searching
the evidence tree means walking every extracted file, deciding which are text, and paying a full
read of the acquisition -- the .db sweep is seconds and that would be minutes to hours -- so it
needs its own command, its own progress reporting and its own answer to "what did I not
search". Worth doing; not worth bolting onto a command whose whole promise is that it is cheap
enough to run every time the case learns something.

---

## P3 — Larger pieces

### 14. Configuration-management job-cache parser (Salt/Uyuni-class)

A config-management master's job cache encodes, in directory metadata alone, which target
received which job and when. Distinguishing an operator's scheduled fan-out (many targets in one
second) from an attacker's targeted burst (one target, many jobs, minutes apart) is what scoped
an estate-wide compromise — and it took five throwaway scripts. The job metadata files also
carry the function, arguments, target and invoking user.

Worth a first-class module: `cm_jobs` table + a burst/fan-out classifier. Note the retention
window in the output, because it bounds every conclusion drawn from it.

### 15. systemd journal reader (binary)

The persistent binary journal reached months further back than the rotated text logs on the same
host and carried the literal privileged command lines. Extracting them meant binary `grep` over
90 MB files. Even a strings-based `COMMAND=` extractor is a large win over nothing; a real reader
is better.

### 16. Feed auditd records into the `auth` table

A privileged account's entire session history existed in auditd records (`LOGIN`, `USER_LOGIN`,
`USER_START`, `CRED_ACQ` — with `auid`, `acct`, `addr`, `exe`, `res`) and **not** in the text auth
logs, so the `auth` table missed the account completely. First pass over that host concluded
there was no such access. Merge auditd into the same table with a `source` column.

### 17. Reason over `package_verify` — PAM / security-module integrity

`package_verify` is parsed and nothing consumes it. Two rules, both cheap:

- a **package-owned, non-`%config`** shared object under a `security/` path failing checksum
  verification. On RPM/DEB hosts this is among the highest-signal findings available;
- the **same hash in both the 32- and 64-bit library paths** — impossible for a genuine library,
  and a reliable tell for a dropped-in replacement.

This class of finding explained the credential-theft mechanism in a case where nothing else did.

### 18. Investigate uneven package-verification coverage

Full verification completed on a minority of hosts (thousands of files) while others produced
only dozens. If that is a timeout, a collector-profile difference, or a silent failure, then every
"clean" verdict drawn from `package_verify` on the short hosts is weaker than it looks — and
nothing currently says so. Find the cause; until then, report the file count next to the verdict.

### 19. systemd unit persistence gap

Unit files dropped in `/etc/systemd/system/` with a `WantedBy` link were not flagged by
`persistence` — the third occurrence of the same miss. Review `lin_persistence.py` coverage for
unit files *and* their `.wants` symlinks.

### 20. Windowed super-timeline

A merged, time-bounded view (MFT/USN + evtx + prefetch + amcache + registry) would replace most
of the manual per-table querying that every analysis so far has consisted of. The existing
`timeline` output is very sparse relative to the data available.

### 21. Prefetch: per-execution rows

`LastRun` plus `PreviousRun0..6` should each be a timeline row. A payload's *return visit* four
days after the initial intrusion was visible only in those secondary timestamps. Verify whether
`prefetch_Timeline` already expands them; if it does, the gap is that `report.txt` never surfaces
it.

### 22. Bracketed paths are glob character classes — audit for it

Collection roots containing `[` `]` in a directory name silently break `glob.glob` and
PowerShell `Get-ChildItem -Path`: a character class matches nothing, so the call returns zero
results and no error. This has already produced a wrong "zero records" conclusion mid-analysis.

Audit the codebase for glob usage over evidence paths, switch to literal-path APIs
(`Path.iterdir()`, `os.scandir`, `-LiteralPath`), and add a regression test whose fixture
directory name contains brackets.

### 23. Surface BITS download URLs

`bits_jobs` / `evtx_bits` are parsed but never summarised. BITS is a standard living-off-the-land
download vector; the URLs belong in the report next to the browser downloads.

### 24. Named-tooling lists reach only the command histories

**Symptom.** `assets/suspicious_tools.txt` holds sixteen categorised regexes for named offensive
tooling — credential theft, Kerberos abuse, C2 frameworks, AV kill, tunnelling. It is read by
exactly two handlers, `lin_bash` and `win_consolehost`, so a tool is detected only if somebody
TYPED it into a shell whose history survived. A binary dropped and run from a service, a
scheduled task or Explorer is invisible to that list, and on Windows that is the normal case.

The lists that do reach disk are matched against Amcache only: `rmm_tools.yaml` (`win_rmm`),
`lolbas.yaml` (`win_lolbas`), `loldrivers_hashes.json` (`win_byovd`). Nothing matches a tool name
against Prefetch, Shimcache, service names, task names or the `$MFT`.

**Open decision, deliberately not taken here.** Applying the same list to Amcache/Prefetch/
Shimcache is a small change and a large widening — but a tool NAME in a shell history is
intent, while the same name in Amcache can be a sysadmin's installer. If it is done, the two
must not share a `suspicious` flag: history stays flagged, disk presence gets a row and a
`source` column saying where it was seen.

**Also.** These four lists are frozen. `aeng update` refreshes db-ip, the Tor exit list,
signature-base and hayabusa/chainsaw; it refreshes no tooling list at all.

---

### 25. mthcht/awesome-lists — the lists the engine has tables for and no data

**What it is.** `github.com/mthcht/awesome-lists`, MIT, actively maintained, auto-updated. CSVs
with `metadata_severity`, `metadata_tool_type` (`offensive_tool` / `greyware_tool`) and
`metadata_reference` columns — which map onto this engine's own conventions almost exactly:
flag `offensive_tool`, report `greyware_tool` unflagged, and let `findings.py` rank by
selectivity.

**Direct fit — the table exists here and there is no list to match it against:**

| List | Size | Against | Today |
|---|---|---|---|
| `suspicious_windows_services_names_list.csv` | 41 KB, ~300 rows | `reg_services` + 7045 | **DONE** v0.7.27 — `service_installs` |
| `suspicious_windows_tasks_list.csv` | 27 KB, ~180 | `tasks_disk`, `reg_scheduledtasks` | **DONE** v0.7.29 — `task_installs` |
| `ransomware_notes_list.csv` + `ransomware_extensions_list.csv` | 47 KB, ~450+ | filenames in `$MFT` / bodyfile | **DONE** v0.7.30 — `ransomware_mft` / `ransomware_bodyfile` |
| `suspicious_file_double_extension.csv` | 28 KB | the same | — |
| `/Hijacklibs/` | dir | DLL paths in `$MFT` | no sideloading check |
| `/RMM/`, `/Drivers/` | dirs | a refresh path for `rmm_tools.yaml` and `loldrivers_hashes.json` | both frozen (§24) |

**Medium value.** `suspicious_ports_list.csv` (the LiveResponse backdoor set is nine hardcoded
ports), `suspicious_hostnames_list.csv` (4 KB of attacker-VM names → lateral-graph nodes),
`dyndns_list.csv` + `suspicious_tlds_list.csv`, `/VPN/` + `/PROXY/` (enrich the `public`
classification of external sources).

**Not usable from disk triage, and worth writing down so it is not re-proposed:**
`suspicious_named_pipe_list.csv` (107 KB) and `suspicious_mutex_names_list.csv` (62 KB) need
live handle enumeration — neither UAC nor the Velociraptor LiveResponse collects it.
`suspicious_usb_ids_list.csv` would need a USBSTOR parser; there is none.
`suspicious_windows_firewall_rules_list.csv` likewise has no parser to feed.

**Two cautions.** `suspicious_http_user_agents_list.csv` is 431 KB and
`dns_over_https_servers_list.csv` 243 KB; `web_suspicious.txt` is sixty-two curated low-FP
lines, and merging the first would change the character of the web hunt — opt-in second file at
most. And a large share of the entries are `greyware` (PDQ, RMM): on a managed estate that fires
constantly, so `metadata_tool_type` has to be used, not ignored.

**Build.** Fetch in `aeng update` the way signature-base already is — these lists auto-update and
a frozen copy ages badly — plus a shared `handlers/_awesome.py` that translates the `*foo*`
wildcard syntax to a regex and yields `(pattern, tool, category, type, severity, reference)`.
MIT requires attribution: a row in README's third-party table.

---

## Suggested order

1. §1 log coverage, §3 timestomp, §2 collection artifacts — evidence integrity first; they change
   what the other findings *mean*.
2. §4 Defender, §5 services, §7 credential access — the three that each independently carried a
   case-defining finding that manual work had to recover.
3. §9 internal networks, §13 sweep discoverability, §11 report ranking — cheap, and they pay back
   on every host from then on.
4. §6 SMB, §8 recovered IOCs, §12 timezone.
5. P3 as capacity allows; §17 and §16 are the highest-value of that group.

§25 is not a step of its own: it is the data half of §5 and of the ransomware/task work, so it
lands with whichever of those is built first (`_awesome.py` + the update fetch, then the first
consumer). §24's open decision blocks nothing and can be answered when a second consumer needs
it.
