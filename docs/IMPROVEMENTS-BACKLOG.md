# Improvements backlog — lessons from Windows/Linux triage runs

Everything here comes from analysis work where the tool was the bottleneck: a finding that
took manual SQL to reach, a conclusion that a coverage gap almost inverted, or noise that
cost an hour. Values are shapes and placeholders (`HOST-01`, `10.0.0.5`, `evil.example`),
never case content.

Each item says what to build, where it plugs in, and why it earns its place. Verified
against the tree: items marked **(exists)** are already there and the gap is elsewhere.

---

## P0 — Evidence integrity: things that change conclusions

### 1. Windows log-coverage map (per channel, per day, with gap classification) — **DONE** (`log_coverage`)

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

### 2. Collection self-artifacts must be identified and excluded — **DONE** (`collection_artifacts_mft` / `collection_artifacts_bodyfile`)

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

### 3. Timestomp detection (ctime vs mtime) — **DONE** (`timestomp_mft` / `timestomp_bodyfile`)

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

### 4. Defender Operational: parse it properly (`win_defender.py`) — **DONE** (`defender_detections`); the files are §27

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

### 5. Service installation analysis → remote-execution detector — **DONE** (`service_installs`)

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

---

## P4 — Acquisition coverage: what the collectors bring and no parser reads

Measured on 2026-09-29 against the two collections actually used in this shop, not against a
catalogue of everything a triage *could* take:

- **Windows** — KAPE `!SANS_Triage` (23 compound targets, 130 tool groups, 821 path rules).
- **Linux** — UAC 3.4.0, `full` profile (`live_response/*`, `files/*`, `system/*`, `bodyfile`,
  `hash_executables`, `ssh`, `packages`, `osquery`, `chkrootkit`).

Everything below is already **inside the evidence tree** when a case lands. The cost is a
parser, never a change to the acquisition — which is what makes this group cheap relative to
its value, and what separates it from P3. Each item says what arrives, what it would become,
and whether it is worth building; the ones that are not worth it are written down anyway, so
they are not re-proposed every six months.

> **Dropped on 2026-09-29.** The user read the measured list and took these out of scope:
> §26 remote-access logs, §27 Defender's files, §29 exfil channels, §30 and §44 browsers,
> §31 network scanners, §32 USB, §36 messaging. The entries stay as written so the
> decision is visible and the measurement does not have to be repeated to re-open one.

---

### 26. Remote-access / RMM tool logs — the strongest single gap — **dropped** (user, 2026-09-29)

**What arrives.** The SANS target collects ~25 remote-access products: AnyDesk
(`%APPDATA%\AnyDesk\*.trace`, `connection_trace.txt`, `*.conf`, plus the `ProgramData`
copies), TeamViewer (`Connections*.txt`, `TeamViewer*_Logfile.log`, the MRU config), RustDesk,
ScreenConnect (session database + client config), Radmin, Splashtop, ZohoAssist, Kaseya,
MeshAgent, LogMeIn, QuickAssist, UltraViewer, Supremo, ISLOnline, DWAgent, Action1, Level,
Xeox, ITarian, mRemoteNG, RemoteUtilities, NetMonitor, UEMS — and Remcos, which is not
dual-use at all.

**What we do today.** `rmm` names the *binaries* found in Amcache (LOLRMM fingerprints). That
answers "was AnyDesk ever on this host", which is the weakest question of the three. The logs
answer the other two: **who connected, from which peer id, when, and in which direction**.

**Build.** One normalised `remote_access.csv` — `tool, direction (in/out), peer_id, peer_name,
user, time_start_utc, time_end_utc, result, source_file` — with a per-tool reader behind a
common shape, starting with the three that cover most real cases (AnyDesk, TeamViewer,
ScreenConnect) and a registry of the rest. `connection_trace.txt` alone gives incoming session
id, timestamp and the local user that accepted it.

**Why it is first.** These rows are *edges*: an external peer id, a host, a user and a time
window. They belong in the lateral-movement graph beside RDP and SMB, and today the graph is
blind to the channel that most hands-on-keyboard intrusions actually use. It is also the one
artifact class here that nothing else in the tree substitutes for — no evtx channel records an
AnyDesk session.

---

### 27. Defender's own files: MPLog, DetectionHistory, Quarantine — **dropped** (user, 2026-09-29)

**What arrives.** `ProgramData\Microsoft\Windows Defender\Support\MPLog-*.log`,
`Scans\History\Service\DetectionHistory\*`, `Quarantine\`, plus the legacy
`Microsoft AntiMalware\Support` path.

**What we do today.** §4 is **done** for the *channel* (`defender_detections`). The files are
a different source with two properties the channel does not have: MPLog holds **process
command lines and scanned paths** (`EstimatedImpact`, `Lowfi`, `DetectionEvent` lines) going
back months — far past the Operational channel's rotation — and `DetectionHistory` keeps the
detection record when the evtx has already rolled over. Quarantine holds the sample itself.

**Build.** `defender_mplog.csv` (time, kind, path/command line, source line) feeding the same
flag vocabulary as `consolehost`, and `defender_detection_history.csv` merged into the
existing `defender_detections` table with a `source` column (`channel` / `history`). Do **not**
decrypt quarantine payloads; record that a sample exists and its metadata.

---

### 28. Third-party AV logs → one `av_detections` table

**What arrives.** Twenty-five endpoint-security products, counting the enterprise suites (one
of them alone contributes 15 path rules and a separate management-agent target), the EDR
agents' quarantine directories, and the on-demand scanners and clean-up tools an operator may
have run on the host before the acquisition. The vendor roll-call is deliberately not written
out here; `Targets/Antivirus/*.tkape` in the KAPE tree is the current list and it changes.

**Why.** On a managed estate the endpoint product is often the only thing that saw the first
stage, and it saw it *at the time*, with a name and a path. A detection at T on file F is the
cheapest pivot in the case. Today all of it is discarded.

**Build.** `av_detections.csv` — `product, time_utc, threat_name, path, action, user,
source_file` — with a per-product line reader. Deliberately **incremental**: ship the format
plus the three products this shop actually meets, and let the rest fail closed (a row in
`report.txt`: "AV logs present for <product>, no reader"). A half-parsed vendor log is worse
than an honest gap.

---

### 29. Exfil channels: cloud sync, FTP/SCP clients, rclone — **dropped** (user, 2026-09-29)

**What arrives.** OneDrive `logs\` (the ODL files name the synced items) and `settings\`,
Dropbox / Google Drive / Box / Megasync metadata, FileZilla client `sitemanager.xml` +
`recentservers.xml`, FileZilla Server logs, WinSCP, Robo-FTP, FreeFileSync, and
**`rclone.conf`** — which is a written statement of the destination, credentials and all.

**Build.** `transfer_targets.csv` (tool, remote host/bucket, protocol, user, config path,
mtime) and, where the client keeps one, `transfer_sessions.csv`. `rclone.conf` on a server is
by itself a finding; today nothing reads it.

---

### 30. Browser coverage: the other Chromium brands, and the ESE side — cheap — **dropped** (user, 2026-09-29)

**What arrives.** The target collects Chrome, Edge Chromium, Brave, Firefox (all four
supported) **and** Opera, Vivaldi, Arc, Yandex, Supermium, WaveBrowser, CocCoc, UC, QQ, 360,
Puffin, plus IE/legacy Edge `WebCacheV01.dat`.

**What we do today.** `win_browser` maps exactly three Chromium user-data directories and the
Firefox profile directory.

**Build.** (a) Extend the map — the other Chromium brands use the same `History` SQLite schema,
so this is a table of paths plus a `browser` column, and it is the cheapest item in P4;
WaveBrowser in particular is adware and its presence is itself a signal. (b) `WebCacheV01.dat`
is an ESE database and a separate piece of work — it is what holds history for IE and legacy
Edge and part of the WinINet download record.

---

### 31. Network scanners → discovery evidence — **dropped** (user, 2026-09-29)

**What arrives.** Advanced IP Scanner, Advanced Port Scanner, SoftPerfect NetScan — their
configs and result files.

**Why.** These are small files that state **which ranges the attacker scanned and when**. On
top of a graph built from logons, a discovery row explains the shape of what follows. Low cost,
narrow scope, no ambiguity.

---

### 32. USB device history — **dropped** (user, 2026-09-29)

**What arrives.** `Windows\inf\setupapi.dev.log` (first-seen per device, with serial), and the
`USBSTOR`/`SCSI` keys are already inside the SYSTEM hive we parse.

**Why.** Ingress and exfil vector, and §25 already noted that
`suspicious_usb_ids_list.csv` has no parser to feed. `usb_devices.csv` — `first_connect_utc,
vendor, product, serial, friendly_name, last_write_utc, user` — closes both.

---

### 33. PowerShell transcripts

**What arrives.** `Users\%user%\Documents\20*\`, `C:\PSTranscript\20*\`, and the System32
paths, when transcription was ever enabled.

**Why.** `consolehost` gives the commands; a transcript gives the commands **with their output
and per-command timestamps**, and it survives `Clear-History` and a deleted PSReadLine file.
Same table shape and the same flag vocabulary as `consolehost`, so the marginal cost is small.

---

### 34. Windows Firewall log (`pfirewall.log`)

**What arrives.** `Windows\System32\LogFiles\Firewall\`, when logging was enabled.

**Why.** Connection-level records on a host with no Sysmon — the only place an outbound
connection is written down. Also the missing feed for
`suspicious_windows_firewall_rules_list.csv` in §25. Enabled far less often than one would
like, which is exactly why the parser should say "not enabled" rather than nothing.

---

### 35. Group Policy (`Registry.pol`)

**What arrives.** The `GroupPolicy` target: `Registry.pol`, `GPT.ini`, scripts.

**Why.** Policy-level tampering (Defender disabled, logging turned off, a startup script added)
is applied here and is invisible in the live registry hives once a policy is unlinked. Small,
binary, well-documented format. Pairs with `sysvol`, which we already parse.

---

### 36. Messaging clients — **dropped** (user, 2026-09-29; the reason was already written)

Teams, Slack, Discord, Signal, Telegram, WhatsApp, Viber, Skype, Mattermost, mIRC, HexChat,
IceChat, Cisco Jabber all arrive. Their stores are LevelDB / encrypted SQLite, per-app and
per-version, and the investigative question they answer (what was said) is usually out of scope
for an intrusion triage and inside scope for a legal process instead. **Not building.** If it
becomes relevant, the entry point is Teams and Slack only, and a decision about what is safe to
write into a CSV.

---

### 37. Collected, judged, not built — one line each

| Artifact | Verdict |
|---|---|
| ThumbCache (`thumbcache_*.db`) | Defer. Answers "this image existed"; a picture extractor is a different tool, and the MFT already carries the name. |
| RDP bitmap cache (`bcache*.bmc`) | Defer. Reconstructing the tiles is real work and the output is images, not rows; it belongs to a manual deep dive after the graph points at a session. |
| `Syscache.hve` | Build **with** §32/§35 if a registry pass happens anyway — it is another execution record on server SKUs, cheap once a hive reader is open. |
| EventTraceLogs (`.etl` — WMI, WDI, SleepStudy, DeliveryOptimization) | Defer. Needs an ETL decoder; the DeliveryOptimization logs are the only ones with clear triage value (peer-to-peer download of payloads). |
| `$LogFile`, `$SDS`, `$Boot`, `$T` | Not building. `$LogFile` transaction analysis is a specialist task and its window is hours; `$SDS` matters only for an ACL question. We already take `$MFT`, `$J` and `$Extend`. |
| NET CLR usage logs | Defer. Evidence that a .NET assembly ran, which prefetch and Amcache usually already carry. |
| P2P / torrent / Usenet / IRC clients | Not in `!SANS_Triage`; not building. |

---

### 38. Linux containers — `live_response/containers/*` is collected and unread — **DONE in v0.7.84**

**What arrives.** For docker (and the same shape for podman, lxc, containerd, pct, zoneadm):
`docker container ls --all --size`, `docker inspect <id>`, `docker container logs <id>`,
`docker top <id>`, `docker diff <id>`, `docker network inspect`, `docker volume inspect`,
`docker image ls`.

**Why this is the Linux counterpart of §26.** Every host-level parser we have reads the host.
A compromised container is invisible to all of them: its processes are in the host `ps` only as
PIDs with no context, its filesystem is not in the bodyfile in any readable form, and its
own logs are collected here and nowhere else. `docker diff` is the closest thing there is to
"what did this container write since it started" — an MFT-style delta, handed to us for free.
The exfil analysis in memory already hit this as a **blind spot** on an LXD host.

**Build.** `containers.csv` (runtime, id, image, created_utc, status, command, ports, mounts,
privileged, network mode), `container_changes.csv` from `docker diff` (container, change kind,
path — `A`dded/`C`hanged/`D`eleted), `container_procs.csv` from `docker top`. Flags: a
privileged container, a host-network container, a bind mount of `/` or `/etc`, a write under
`/tmp`, `/dev/shm` or a web root. Run the existing staging/webshell indicators over
`container_changes` paths — the detectors already exist, they have simply never been pointed
at this input.

---

### 39. Virtual machines — `live_response/vms/*` — **DONE in v0.7.84**

`virsh`, `virtualbox`, `qm`, `vim-cmd`, `vmctl`, `esxcli`, `vm-support` output arrives. Same
argument as §38 but weaker: a VM inventory is context, not activity. **Build the inventory
only** (`vms.csv`: hypervisor, name, state, disk paths, network), and only alongside §38.

---

### 40. Mounts and storage layout → an honesty table

**What arrives.** `mount`, `findmnt`, `lsblk`, `df`, `blkid`, `zfs/zpool`, `lvs/pvs/vgs`.

**Why.** Exactly the argument of §1, transposed: the bodyfile covers what UAC walked. A network
mount, a second filesystem or an unmounted LV is **not** in it, and today nothing says so. A
`storage.csv` (device, mountpoint, fstype, options, size, in_bodyfile) turns a silent blind
spot into a row — and `noatime` in the options column is the precondition of the whole
atime-based exfil method, so the method's validity becomes visible instead of assumed.

---

### 41. Firewall rules, routing and ARP

**What arrives.** `iptables -L -n -v`, `nft list ruleset`, `ufw status`, `firewall-cmd`,
`ip route`, `arp -a`, `ip neigh`.

**What we do today.** `network` reads `ss`/`netstat` only — sockets, not rules. `netconfig`
reads `/etc/hosts`, `resolv.conf`, `hosts.allow/deny`.

**Build.** `firewall_rules.csv` (table, chain, action, proto, src, dst, dport, comment) with
flags for an ACCEPT of an odd inbound port and for a rule that redirects outbound traffic, plus
`arp_cache.csv` — which gives the graph **layer-2 neighbours that never produced a log entry**,
a source of lateral candidates we currently have no equivalent of.

---

### 42. osquery and chkrootkit results

Both are collected when present (`osquery/osquery.yaml`, `chkrootkit/*`) and both are already
*findings*, not raw data. Parsing them is a text-to-rows exercise of a few hours:
`rootkit_checks.csv` (check, verdict, detail) with INFECTED rows flagged, and osquery's JSON
into whichever tables it already matches. Low effort, and it stops an operator's extra step
from being invisible in the final report.

---

### 43. Interactive-tool histories beyond the shell

`files/applications` collects `.viminfo`, `.lesshst`, `.python_history`, `.mysql_history`,
`screen`/`tmux` state, `wget-hsts`, and the MRU files of a dozen desktop apps. `bash` covers
`.bash_history`/`.zsh_history`/`.sh_history`/`.ash_history` and nothing else. `.viminfo` names
**every file opened and the search terms used**, `.mysql_history` holds the queries — including
the ones that dumped a table. Extend the shell-history handler with a second family of readers
rather than writing a new parser.

---

### 44. Linux browser profiles — cheap, same handler — **dropped** (user, 2026-09-29)

`files/browsers` collects Chrome, Chromium, Brave, Edge, Firefox, Opera, Vivaldi, Safari and
Konqueror profiles on Linux. `browser` is declared `os: windows` and hardcodes Windows paths,
so a Linux workstation case yields no browsing history at all. The SQLite readers are already
written; what is missing is the path map and a second manifest.

---

### 45. systemd journal — §15 confirmed, priority raised

§15 (binary journal reader) was written as a maybe. It is not: `files/logs/journal` is in the
`full` profile, so the binary journals **are already in every UAC collection we take**, and on
a systemd host with no rsyslog they hold everything `auth`, `cron_log` and `sudo_log` look for
in `/var/log` and do not find. Treat §15 as P1 for the Linux side, not P3.

---

### 46. The atlas: generated documentation that cannot drift — **DONE in v0.7.83**

**Symptom.** The overview of every parser — source, output, alert class — was assembled by
hand into an HTML page. It was accurate on the day it was written and starts ageing with the
next parser, and there is nothing in the repository that would notice.

**Build.** Make it an output of the tool instead of a document about it:

1. Two documentary keys per parser manifest, beside `description`: `source:` (where the data
   comes from, in the analyst's words) and `alert:` (`detect` | `flag` | `context` — does this
   parser decide something, does it write a flag column, or is it context). Neither is part of
   `parser_fingerprint`, so adding them re-parses **nothing** — verified against
   `core/runner.py`, which hashes `id/command/handler/short/requires/tool.binary` only.
2. `core/atlas.py` renders the same self-contained page (no external requests, no libraries —
   the rule the two existing reports already follow) from the loaded registry.
3. `aeng atlas [-o path]`, beside `list-parsers`, and the committed copy at `docs/atlas.html`.
4. **The part that makes it stay true:** a test regenerates the page into a temp directory and
   compares it with the committed one — a parser added without regenerating turns CI red — plus
   a test that every manifest carries both keys, so a new parser cannot land undocumented.
   Revert-proof in the usual sense: drop a key and the second test fails; edit a description
   without regenerating and the first does.

**Both open decisions were answered by the user on 2026-09-30:** the page is in **English**,
like the rest of `docs/`, and there is **no per-case copy** — only `docs/atlas.html` in the
repository. No `aeng atlas` subcommand either; `python -m artifact_engine.core.atlas` rewrites
the page, and `tests/test_atlas.py` fails until it is rerun.

**Two things the build changed from the sketch above.** The page carries no version and no
date: every commit here bumps the version, so a stamp would mean regenerating on every commit
and a red CI on every one that forgot — and the page cannot be stale anyway, which was the
point. And it lists no output filenames: 23 of the 113 manifests declare `outputs` and the
rest is known only to the handler, so a column right for a fifth of the rows was dropped in
favour of the folder each table lands in (derived from the category) and the parser id the
table is named after. Revert-proof 7/7, including that writing either key costs no re-parse.

---

## Plan and order — 2026-09-29

This supersedes the order above for everything not yet done. Marked **DONE** while writing it,
verified against the tree: §1 (`log_coverage`), §2 (`collection_artifacts_mft` /
`_bodyfile`), §3 (`timestomp_mft` / `_bodyfile`), §4 (`defender_detections`),
§5 (`service_installs`). The rest of §8-§24 has not been re-checked and should be, once.

**First, close the porting debt** (approved 2026-09-17, unchanged):

1. **v0.7.76** exit-code contract (port of v0.7.53, without preflight/tools).
2. **v0.7.77** extraction robustness (v0.7.46 + v0.7.50 + v0.7.62).
3. **v0.7.78** archive still arriving (v0.7.70 + v0.7.71, without notify).

**Then the atlas, before the parser wave, not after** — §46. It is small, and from that commit
on every new parser below carries its own row in the map as a condition of landing. Building it
afterwards means writing 113 rows by hand a second time.

4. **v0.7.83** §46 atlas generated + drift test.

**What actually landed**, since the numbers above were written before the work started: the
porting debt took v0.7.78 (exit-code contract) and v0.7.79 (the consolidation half of its
review), v0.7.80 (damaged tarball), v0.7.81 (the two host limits) and v0.7.82 (the archive
still arriving), with v0.7.76 and v0.7.77 spent on a dependency break that arrived from
outside. The atlas is **v0.7.83**. The coverage work below starts at v0.7.84 and keeps its
order.

**Then the coverage work that survived the 2026-09-29 cut**, biggest gap first:

5. ~~**v0.7.84** §38 containers (+ §39 VM inventory)~~ — **DONE**: `containers` and `vms`,
   the first two parsers in the new `containers` category, with 18 guarantees proven by
   reverting them. The one deviation from the sketch: the inventory is read from the
   per-container `inspect` JSON, not from `docker container ls --size`, so the size column
   the sketch asked for is not there — `ls` is a human table whose columns hold spaces, and
   column-splitting it mis-attributes a row rather than leaving a cell empty.
6. ~~**v0.7.85** §28 `av_detections`~~ — **DONE**: two tables, `av_detections` and
   `av_products` (the inventory of every product directory found, read or not), with
   `report.txt` keeping three outcomes apart — no reader, a reader that ran and produced
   no row, read. Readers for three products; the rest are inventoried. Two deviations from
   the sketch: the column is `time_local` and not `time_utc`, because these products write
   the host's wall clock with no offset in it and McAfee's date is in the host's locale
   order, and a `time_kind` column beside it says whether the value is a per-detection
   time or one scan start for the whole log. A `detail` column carries the raw line and a
   `suspicious` column marks the rows where the product said the file is still there.
7. ~~**v0.7.86** host state~~ — **SUPERSEDED**, see 7a. Host state is 7b.
7a. **v0.7.86** the run's verdict: read which claim an extraction complaint makes from the
   message instead of from 7-Zip's exit code, and report a damaged member apart from a
   hole. Measured on three real acquisitions: eight of eighteen acquisitions reported
   as not whole were one file an endpoint agent held open, and one whole case was
   `incomplete` on nothing else.
7b. **v0.7.87** host state: §40 mounts and storage, §41 firewall rules / routing / ARP,
   §42 osquery and chkrootkit results.
8. **v0.7.88** §34 Windows firewall log, §35 `Registry.pol` (+ §37's Syscache, since a hive
   reader is open in that commit anyway).
9. **v0.7.89** §33 PowerShell transcripts, §43 histories beyond the shell.
10. **v0.7.90** §45/§15 the binary journal reader.

**Every parser added from here carries `source:` and `alert:`** and its commit regenerates
`docs/atlas.html`, or CI is red. That is what §46 bought.

**Deferred with a measurement against it, not forgotten:** §28's product list does not
match what is deployed. Measured over 18 extracted Windows volumes from three real
acquisitions, the shipped path set for Trend Micro — the previous generation's client
layout — matched on NONE of them, while the current agent's own log directories were
present on 10; a second vendor's full component estate is absent from the list entirely.
Together that is about 2 GB of endpoint-security logs that `report.txt` does not so much
as mark as unread, which is the one thing §28 was built to prevent. The fix is the path
set, deduplication of resolved paths (two patterns differing only in case resolve to one
directory on a filesystem that folds case, and would be inventoried twice), and a local
sidecar so an analyst's additions are not a permanently modified tracked file — the same
problem `suspicious_tools.txt` and `web_suspicious.txt` have.

Not scheduled and deliberately so: everything marked dropped above, the deferrals in §37,
half-hour buckets in the web panel (asked and left open), and the older P3 items, which should
be re-verified against the tree before any of them is picked up again.
