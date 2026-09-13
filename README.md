<p align="center">
  <img src="docs/img/logo.png" alt="Artifact Engine logo" width="240">
</p>

<h1 align="center">Artifact Engine</h1>

<p align="center"><i>DFIR triage &#183; parse &#183; detect &#183; connect</i></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-PolyForm%20Noncommercial-orange.svg" alt="License: PolyForm Noncommercial 1.0.0"></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/forensic%20parsers-113-brightgreen.svg" alt="Parsers">
</p>

Modular DFIR triage engine. It extracts workstation/server acquisitions
(**KAPE** and **Velociraptor live response** on Windows, **UAC** on Linux — plus
loose web-server / FortiGate / Windows event-log drops), detects the system type,
runs **113 forensic parsers** in parallel and consolidates the results into a `.db`
(SQLite) and a `.xlsx` (Excel) per machine for review, with a detection layer
(YARA, Sigma, Chainsaw/Hayabusa, LOLBAS/LOLDrivers/RMM, persistence scans) and a
cross-machine lateral-movement graph on top.

Successor to CyberCrusader, redesigned to be **fast, parallel and easy to
extend**: parsing tools are declared in **YAML**, not in code.

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the internals (pipeline stages,
module layout, how detections and the lateral-movement graph are built).

<p align="center">
  <img src="docs/img/lateral_movement.svg" alt="Cross-machine lateral-movement graph" width="860">
  <br>
  <sub>Cross-machine lateral-movement graph (<code>lateral_movement.html</code>) — who authenticated
  where, with pivot chains highlighted. Illustrative synthetic data.</sub>
</p>

## Contents

- [Pipeline](#pipeline)
- [Where it runs, and what it parses](#where-it-runs-and-what-it-parses)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [How to add a parsing tool](#how-to-add-a-parsing-tool)
- [Detections](#detections)
- [Example outputs](#example-outputs)
- [Output layout](#output-layout)
- [Reporting a bug](#reporting-a-bug)

## Pipeline

```
parent folder with .zip / .tar.gz
   |
   v
[0] Integrity   -> traces.txt + traces.csv  (SHA256 of the originals, BEFORE touching anything)
[1] Extraction  -> recursive (tar.gz in one pass, nested, anti zip-bomb) + containers inside loose drops
[2] Detection   -> profile/OS per machine (profiles/*.yaml)
[3] Parsing     -> parsers (parsers/*.yaml) in parallel, respecting dependencies
[4] Consolidation -> <machine>.db + <machine>.xlsx + report.txt (informative sheet)
[5] Lateral movement -> lateral_movement.csv + .html (cross-machine logon graph)
```

## Where it runs, and what it parses

Two different questions, and the honest answer differs.

**The engine runs on Windows and on Linux.** Same install path, same commands,
same configuration. It is a Python process that is invoked, works and exits — no
service, no daemon, no locking.

**What it can parse there is not symmetric**, because some of the tools it drives
exist on only one side. That is a property of the toolchain, not of the engine,
and no amount of engineering changes it:

| Toolchain | On Windows | On Linux |
|---|---|---|
| Eric Zimmerman tools (14 assemblies) | the bundled apphost | framework-dependent .NET — `dotnet X.dll` runs the same program, so a .NET 9 runtime is the requirement |
| chainsaw | native | native — the Linux build is already inside the archive `aeng setup` downloads |
| hayabusa | `win-x64` asset | `lin-x64-gnu` asset, same release |
| sidr | native | **no Linux build is published at all** |
| DeepBlueCLI | `powershell`, else `pwsh` | **no answer, and `pwsh` is not one** — the script reads every event through `Get-WinEvent`, which PowerShell provides only on Windows |
| `esentutl` (SRUM/SUM repair) | in the OS | **no equivalent exists** |

Measured on a Linux host — this is the *host* question, across both evidence
types: of the 113 parsers, **75 run with nothing extra, 35 more once the .NET 9
runtime is installed, and 3 never will** (`deepblue`, `search_index`, `sum`).
`dotnet` on `PATH` is not enough by itself — `aeng preflight` reads the runtime
version each tool asks for, and names both versions when the host falls short.

Which of them a given run reaches is the other question, and it is decided by the
acquisition rather than by the host: a Linux/UAC case schedules 44 parsers and a
Windows/KAPE case schedules 69. A Linux host runs the Windows ones too — measured,
a KAPE acquisition on Linux schedules all 69 — because what gates them is the .NET
toolchain, not the operating system underneath. So the promise is:

> The engine installs and runs on Linux and on Windows. On **Linux acquisitions**
> both hosts produce the same tables — CI proves it on every push by processing
> one synthetic UAC case on both and comparing the results down to the row count
> of every table. On **Windows acquisitions** the Linux host runs a reduced
> parser set, and the run says exactly which parsers it could not run and why.

That last clause is the requirement, not a consolation. A reduced parser set that
announces itself is triage; one that stays quiet is the failure this whole tool is
built against — *zero rows reading as no attack*. `aeng preflight` answers it
before a case is touched, and every run records it in `run-summary.json`.

Full detail, and how each row above was verified, in
[CROSS-PLATFORM.md](docs/CROSS-PLATFORM.md).

## Installation

**On Linux, first.** Debian, Ubuntu and Kali ship Python without `venv` or `pip` and
refuse a system-wide `pip install` (PEP 668). Measured on a clean Ubuntu 24.04: `pip` is
not found, `python3 -m pip` has no such module, and `python3 -m venv` fails for want of
`ensurepip`. So:

```sh
sudo apt install python3-venv git p7zip-full
```

`p7zip-full` is not optional in practice. KAPE collections are often written with
Deflate64, which Python's own zip reader does not implement, and without a 7-Zip binary
such an acquisition does not extract at all — measured, two of the eleven in one real
case. The Windows-evidence parsers additionally need the **.NET 9 runtime** (the distro's
older `dotnet` does not count; `aeng preflight` checks the version). Without root, a
per-user install works: `dotnet-install.sh --channel 9.0 --runtime dotnet`, then put
`~/.dotnet` first on `PATH` — measured on Kali.

Then, on either system:

```sh
git clone https://github.com/MarcBernaldo/Artifact-Engine.git
cd Artifact-Engine
python3 -m venv .venv         # Windows: py -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .
aeng setup            # downloads binaries + offline assets, prepares the config
```

**The editable install (`-e`) is the intended deployment, not a developer
shortcut.** `aeng update` keeps the tool current by fast-forwarding this git
checkout, so the clone *is* the installation — a plain `pip install .` would copy
the code somewhere else and leave self-update with nothing to update. It also
means a source edit is live immediately, with no reinstall.

Add `[dev]` only to run the test suite (`pip install -e ".[dev]"` — pulls pytest,
ruff and openpyxl). An analyst running cases does not need them.

`setup` fetches the external tools (EZ Tools, chainsaw, hayabusa, SIDR, …) and
the offline enrichment assets: db-ip country/ASN databases + the Tor exit list
(IP origin columns), the YARA signature-base ruleset, and the community detection
lists (mthcht/awesome-lists) that name the tool behind a service or a scheduled
task. Everything is best-effort — a missing asset degrades gracefully (e.g.
country shows `?`, and a parser that has no threat list keeps its own detectors
and loses only the attribution).

If the `aeng` script is not on PATH, use `python -m artifact_engine` instead.

### Keeping it current

```sh
aeng update --check   # what is out of date; changes nothing
aeng update           # engine + detection rules + lookup databases
```

`setup` fills in what is **missing** and leaves the rest alone (on Linux it does
restore the execute bit of a tool already installed, without downloading it), so it
will never pick up a new YARA rule or a new hayabusa release. That is what `update`
is for:

| What | How it is decided |
|---|---|
| **The engine** | Fast-forwards the git checkout to `origin`. Refuses — and changes nothing — on uncommitted work, a detached HEAD, or local commits that are not on origin. The running process keeps the old code in memory, so re-run `aeng` afterwards. |
| **signature-base YARA** | Re-synced every time (there is no version to compare). A rule upstream **withdrew is deleted here too** — rules are usually retired for firing on benign files, so a leftover copy keeps producing the exact false positive upstream removed. Rules you drop in that folder yourself are never touched. |
| **hayabusa / chainsaw** | Compared by version first, downloaded only if the release actually moved. Both bundle a Sigma rule set, and their retired rules are purged the same way. Hayabusa's `config/` is left alone — that is what you tune. |
| **db-ip + Tor** | db-ip re-cuts monthly, so a refresh inside the same month is skipped instead of re-fetching identical bytes. The Tor exit list is re-read every time. |
| **Threat lists** (awesome-lists) | Re-fetched every time and reported by whether the bytes actually moved. Fetched rather than bundled on purpose: a frozen copy of a threat list ages into a false sense of coverage. |
| **Other parser binaries** | Only with `--tools`: EZ Tools ship from rolling "latest" URLs with no version to compare, so knowing whether they moved means downloading hundreds of MB. |
| **The interpreter** | Reported, never changed. On **Python 3.10 for Windows** it is flagged `at risk` and counted as pending: that interpreter ends a *run* with no error at all (see below), and calling every rule current while sitting on it would be a clean bill of health for the wrong patient. |

The run reports `updated` only when bytes actually changed, and rewrites
`tools.lock.json` so the sha256 of every binary that produced your outputs stays
on record. Do not run it while a case is being processed — the log of a run
should name one build, not two.

### Windows right-click integration

Double-click **`INSTALL.bat`** to add a *"Process with Artifact Engine"* entry
to the folder right-click menu (registered for the current user, **no admin
required**). Right-click the parent folder holding the acquisitions and pick it
to run `aeng run -p "<that folder>"` in a console that stays open.

On **Windows 11** the entry lives under **"Show more options"** (Shift+F10), as
do all registry-based context-menu verbs. Run **`UNINSTALL.bat`** to remove it.
Equivalent commands: `aeng install-menu` / `aeng uninstall-menu`.

## Usage

```sh
aeng run -p "C:\path\to\the\evidence"     # parent folder with the .zip / .tar.gz
aeng lateral -p "C:\path\to\the\evidence" # rebuild only the lateral-movement graph
aeng sweep -p "C:\path\to\the\evidence" -q 10.0.0.5 -q bad.exe
aeng sweep -p "C:\path\to\the\evidence" --ioc-file iocs.txt --csv sweep.csv
aeng preflight                            # which parsers this install can actually run
aeng list-parsers
aeng list-profiles
```

`sweep` asks the whole case for something one machine taught you — an address, an
account, a hash, a filename — reading each machine's consolidated `.db` without
re-parsing anything. Cases are worked machine by machine, and going back over the
ones already finished every time the case learns something is the part a person
does badly; by machine seven nobody re-checks machine two.

An IOC list from a partner arrives as twenty values, not one, so `--ioc-file`
reads them from a file -- one per line, tolerating the way people actually paste
a spreadsheet column (surrounding quotes, a trailing comma, `#` header lines).
It combines with `-q`, and duplicates are dropped case-insensitively because the
search is. `--csv` writes the **whole sweep**, not just the hits: the values that
matched nothing (which is most of an IOC list, and is itself the result), the
machines that could not be opened, and the rows held back as the collection's own
copy. A file of hits alone cannot support *"we checked these IOCs across these
machines"* months later.

When the operator pointed the collector at the disk it was collecting, the `.db`
holds every artifact twice — once where it lives, once under the output tree — and
a search returns the real hit next to its duplicate. Those rows are dropped by
default and the number dropped is **always reported**; `--include-collection`
searches them anyway. The tree is identified by shape (a directory whose children
are the volume's own root), and `Windows.old` is deliberately not one of them: an
in-place upgrade leaves the same shape and what it holds is the host before the
upgrade.

It reports **which machines it could not search** separately from the hits, and
exits `2` when any were skipped. "No hits" over a case where a database was locked
or corrupt is not a statement about the case, and a script chaining off it has to
be able to tell. Matching is on value boundaries: `10.0.0.5` does not match
`10.0.0.50`, which is a different host.

**Exit codes**: `0` clean · `1` the command could not run at all · `3` a configuration
state, nothing was processed (`preflight` found a missing tool) · `130` interrupted ·
**`2` the command ran and its answer is incomplete** — for `run` that means a parser
errored *or* an acquisition did not extract whole (both in `run-summary.txt`), for
`sweep` that a machine could not be searched. Not a failure, and not a clean result
either. Until v0.7.15 a run printed its parser errors and still exited `0`, so
anything chained after it could not tell.

A truncated archive is the one worth knowing about, because it is the one that
leaves no trace of itself. Its parsers do not error — the ones whose input lay past the
damage find none, self-gate, and land in `skipped`, beside every artifact the machine's
distro genuinely lacks. (Since v0.7.62 a damaged tarball keeps what came before the
damage and is marked `partial`; before, it extracted to nothing.)
The run then ends `OK 2 | skipped 37 | errors 0`, which is what a clean triage of a
quiet host looks like. Since v0.7.20 the run names those archives at the end, writes
them into `run-summary.{txt,json}`, and exits `2` — and because the verdict is stored
in the extraction marker, a later run over the same case says it again.

Options: `--force` re-parses even if output already exists **and** rebuilds every
consolidation output; `-v` is verbose.

Both phases are cached, on the same principle: a parser reports `cached` when it
already ran and its manifest and code are unchanged, and a machine's `.db`/`.xlsx`
are skipped when
every CSV and JSON feeding them still hashes to what produced them (content, not
size and mtime — a rewrite to the same length would otherwise leave you reading a
database that silently does not contain it). A deleted output rebuilds regardless
of the marker. The run says which units it skipped and how many inputs it checked.

`cached` is its own status and not `skipped`, because they answer different
questions: `skipped` means this machine has no such artifact, `cached` means an
earlier run already parsed it and the tables are on disk. A cached parser counts
as done in the summary — with its own number beside it, so what *this* run did is
still readable.

### Loose log drops (no acquisition needed)

Logs that arrive on their own (a hosting export, a firewall export, a colleague
sending you a host's event logs) can be dropped in a folder named **`<kind>`** or
**`<kind>-<label>`** at the case root; each folder becomes its own machine with
its own `.db`/`.xlsx`. The folder NAME is the whole contract — there is no content
sniffing — and zipped exports inside are unpacked automatically:

```
C:\Cases\my-case\
  uac-server1-...\              <- normal acquisition
  weblogs-www.client.com\       <- Apache/nginx access logs (any file names,
    EXPORT_2026.zip                 rotations and zipped exports included)
  fortigate-fw-edge\            <- FortiGate/FortiOS key=value logs
  evtx-dc01\                    <- loose Windows event logs
    Security.evtx                   keep the canonical channel names
    rdp\Microsoft-Windows-TerminalServices-...%4Operational.evtx
```

| Kind | What runs on it |
|---|---|
| `weblogs` | Full request timeline, attack hunt (built-in payload signatures + your `web_suspicious.txt`), audit aggregations with the interactive `web_metrics.html`, and the SigmaHQ webserver ruleset. |
| `fortigate` | One flagged traffic/event timeline from FortiOS `key=value` logs (raw syslog or a FortiAnalyzer CSV export). |
| `evtx` | The **whole Windows event-log toolchain**, unchanged: EvtxECmd once per channel, Chainsaw+Sigma, Hayabusa and DeepBlueCLI. |

`evtx` is the one drop that is a **host**, not just a pile of logs: event logs are
logon evidence, so once parsed the machine is renamed from the folder to the host
its events actually name (their `Computer` field) and it joins the cross-machine
**lateral-movement graph** on that host's node, like any acquired machine.

Two things to know about it. Keep the **canonical channel file names**
(`Security.evtx`, `Microsoft-Windows-Sysmon%4Operational.evtx`, …): EvtxECmd picks
its channel by name, while Chainsaw/Hayabusa/DeepBlueCLI sniff content and read
renamed files too. And use **one folder per host** — two logs sharing a basename
collide, so the first wins and the rest are reported rather than overwritten (and,
being unstaged, they stay exactly where you put them).

The logs are **hard-linked** into the layout the toolchain expects and then the
original path in the drop root is removed, so the folder ends up holding each event
log exactly once — under `<drop>\Windows\System32\winevt\Logs\`. Nothing is lost:
a hard link is a second *name* for one set of bytes, so dropping the first name
frees a duplicate listing, not data (total size is unchanged). An original is only
ever removed once its bytes are confirmed at the staged path.

Full detail: [ARCHITECTURE.md §10](docs/ARCHITECTURE.md).

## Configuration

`aeng setup` writes a starting `config.yaml` **beside the tool** — the one place
every later run finds it. It is looked up in several places, most general first,
so the later one overrides key by key:

| Where | Purpose |
|---|---|
| beside the tool (the checkout root) | the baseline that ships with the install — found no matter where the run is launched from, including the right-click menu, whose working directory is not yours. This is where `aeng setup` writes |
| `%APPDATA%\artifact-engine\config.yaml` (Windows) or `$XDG_CONFIG_HOME/artifact-engine/config.yaml` (Linux, default `~/.config`) | **what THIS machine was set up with.** Outside any checkout, so copying the tool elsewhere does not carry it — and it is the only baseline a non-editable `pip install` has |
| the current directory | a per-case override; only the keys it names change |
| `ARTIFACT_ENGINE_CONFIG` / `-c <path>` | exactly that file, nothing else. Naming one that does not exist is a warning, not a silent fall back |

`aeng config` prints that list, marks which files applied, and shows the effective
values — the first thing to run when two machines behave differently.

It also names the two logs, because a log nobody can find is not a record:

| Log | What is in it |
|---|---|
| `<case>/aeng-run.log` | the run, in full, JSON lines. Lives with the evidence and stays with it |
| `%LOCALAPPDATA%\artifact-engine\logs\aeng.log` (Windows) or `$XDG_STATE_HOME/artifact-engine/logs/aeng.log` (Linux, default `~/.local/state`) | an **index of invocations**, rotated: one line when a command starts (with the case root, where it takes one), one when it ends, plus anything raised before a case log exists. `ARTIFACT_ENGINE_LOG_DIR` moves it; set empty, there is none |

The second one exists for the run that fails *before* it knows where the case is —
a mistyped path, a preflight refusal — which has nowhere to write, so the only
trace is stdout and a scheduled task discards stdout. It is deliberately an index
and not a copy: a file outside the case directory does not carry the case's
hostnames, accounts and paths. A `started` with no matching `finished` is the only
record a process that was *killed* leaves behind.

Beside the tool and in the current directory, `config.local.yaml` is read after
`config.yaml` and wins, so machine-specific settings (a `tools_dir` on another
drive, a different worker count) can sit next to the shared file without ever
being committed over it. The per-user directory has no `.local` counterpart and
does not need one: it is already this machine's and nobody else's, which is the
whole reason it is there.

Every file actually applied is named in the run log, along with the flags that
change what gets parsed and produced:

```
[=] Config: C:\Tools\Artifact Engine\config.yaml
[=] workers 32 | avoid_vss false | merge_vss true | db true | xlsx false
```

With no file anywhere it says so explicitly — the built-in defaults differ from a
typical `config.yaml` (`avoid_vss` on, `emit_xlsx` on), and that is the difference
between parsing a host's shadow copies and ignoring them.

All keys are optional:

| Key | Default | Effect |
|-----|---------|--------|
| `tools_dir` | `<pkg>/tools` | Where the downloaded tool binaries live (~300 MB). |
| `assets_dir` | `<pkg>/data/assets` | Where the geo databases and the community YARA set live (~250 MB). Point both elsewhere to keep regenerable bulk off the system disk or share it between installs. |
| `max_workers` | CPU count (capped at 32) | Parallel workers (parsing and consolidation). Hard ceiling of **64**: pool sizing can hand back this many process workers AND this many thread workers at once, and the interpreter fault below was reproduced around 128. A higher value is clamped with a warning. |
| `avoid_vss` | `true` | `false` also parses each VSS snapshot as an extra volume (slower). |
| `merge_vss` | `true` | With `avoid_vss: false`, consolidate a host's live volume and all its snapshots into **one** `.db`/`.xlsx`/`report.txt` instead of one per volume: each artifact becomes a single table with the rows the volumes share collapsed and a `volumes` column naming where each survivor was seen. Also *faster* than not merging (the `.xlsx` pass runs once per host, not once per snapshot). `false` keeps a separate database per snapshot. |
| `emit_db` | `true` | Build the queryable SQLite `.db` per machine. |
| `emit_xlsx` | `true` | Build the Excel `.xlsx` per machine. **`false` is much faster** — the `.xlsx` pass dominates consolidation. |
| `parse_processes` | `true` | Use a process pool for CPU-bound work (parsing handlers, and consolidation across machines). `false` = threads only (lower peak RAM). |
| `internal_networks` | *(empty)* | CIDR ranges the organisation owns, however routable they are (`- 203.0.113.0/24`). Without them `is_global` decides what came from outside, which is backwards for an estate holding its own public allocation: every ordinary file-share access between two of their own hosts reads as an internet source. A declared range **reclassifies** an address and never deletes a row — "we own that range" is a claim about ownership, not about innocence. Unreadable entries are reported and ignored, never silently dropped. |
| `extract_depth` | `3` | Levels of nested archives to unpack (zip inside zip). |
| `notify` | `none` | Announce a finished run to something outside the case. `stdout` prints one JSON event and needs no secret; `webhook` POSTs the same event to `notify_url`. **Metadata only, by allow-list**: status, counts, duration, version and blocked parser ids — never a hostname, account, path or archive name. A notifier that fails is a warning and never changes the exit code. |
| `notify_url` | *(empty)* | The webhook destination. It usually carries the token, so it is never printed: `aeng config` and every log line show `scheme://host/...` only. |
| `notify_label` | *(empty)* | What the run is announced **under**. Never derived from the case directory, whose name routinely carries the client or the incident; left empty, the run travels as `case-<8 hex>`, a digest of the case path. |
| `notify_timeout` | `10` | Seconds before the webhook is abandoned — with a warning, and the run's verdict untouched. |
| `traces_include_drops` | `true` | Phase-0 hashes files inside loose-drop folders (`weblogs*`/`fortigate*`/`evtx*`) for chain of custody. `false` skips them (delivered root containers are still hashed) — faster when custody of the raw logs isn't required. |

For the fastest run when you only need to query the `.db`, set `emit_xlsx: false`.

### If the run dies with no error at all

On **Python 3.10 for Windows** the parent process can disappear mid-parse: no
traceback, no last log line, just the prompt back. That is an interpreter crash
(`0xC0000005`), not an engine error — an engine fault raises a Python exception.
It is a null dereference in `_memory_release()` (`Objects/memoryobject.c`): the
cyclic garbage collector runs `tp_clear` on a `memoryview` that still has a buffer
exported, `memory_clear()` discards the error that comes back and clears `mbuf`
anyway, and the next release walks the resulting NULL pointer. The memoryviews come
from the process pool's own pipe traffic (`multiprocessing` holds a buffer export
for the duration of every overlapped write).

**Run it on a newer Python.** That removes the cause rather than avoiding it, and
costs nothing: the whole suite passes on 3.13.14 (with pandas 3.x and numpy 2.x),
and a script that faults 3.10.11 in seconds never even reaches the bad state there.
3.11 and 3.12 were not tested either way. `aeng run` warns when it sees the
combination that is known to break.

If you have to stay on 3.10, set **`parse_processes: false`**: with no process pool
there is no such pipe traffic in the parent. Two things about the cost — the GIL is
the smaller half of it. Measured on a 22-machine Windows case (1208 tasks, 6 hours
of parser time), 65% was command parsers and 96% of the Python-handler time sat
inside `deepblue`, `hayabusa`, `usn` and `sum` blocked on a tool with the GIL
released, so genuinely GIL-bound work was **1.2%** of the run. But the flag also
collapses two pools into one: 32 processes + 32 threads becomes 32 threads, i.e.
**half the tasks in flight**. Raise `max_workers` to compensate — threads are cheap
now that a running tool costs one instead of three.

Nothing is lost to such a crash: parsers write a `.done` marker on success, so just
re-run **without `--force`** and only what is missing is redone. `--force` is not
needed to pick up an engine change that only touches consolidation either: that
phase is cached per unit, but the fingerprint includes the consolidation code
itself, so changing it invalidates every unit on its own.

## How to add a parsing tool

Create a `parsers/<os>/<id>.yaml`. ~85% of cases are declarative (run a binary).
For custom logic use a Python handler. See the examples under
`src/artifact_engine/data/parsers/`.

A command-based parser (most common):

```yaml
id: my_parser
os: windows
category: execution
requires: ["Windows/prefetch"]
tool:
  binary: PECmd.exe
  source: { url: "https://download.ericzimmermanstools.com/net9/PECmd.zip", unpack: true }
command:
  - "{binary}"
  - "-d"
  - "{evidence}/Windows/prefetch"
  - "--csv"
  - "{out}"
```

A logic-based parser (Python handler):

```yaml
id: my_handler
os: linux
category: shell
handler: "artifact_engine.handlers.my_module:run"
```

## Detections

Beyond parsing, a detection layer surfaces what matters (`CSVs/Detections/` per
machine, most-severe first):

- **Windows**: Chainsaw + Hayabusa (Sigma over event logs), DeepBlueCLI, YARA
  (bundled + signature-base), RMM tools on disk (LOLRMM), vulnerable/malicious
  drivers by hash (LOLDrivers), LOLBAS binaries relocated to staging dirs, and a
  native registry ASEP/persistence scan.
- **Linux**: YARA, Sigma (SigmaHQ Linux ruleset over raw auditd + syslog),
  GTFOBins abuse in shell history, webshell scan of web roots, MDATP state —
  plus `flag` columns across the system-state outputs (SUID/GTFOBins, eBPF pins,
  kernel taint, anti-forensics log checks).
- **Web**: the attack hunt (`huntweb`) flags served exploitation payloads
  (SQLi/LFI/cmdi/webshell/log4shell/XSS) plus whatever you add to
  `assets/web_suspicious.txt` — a plain analyst-editable list (`label = regex`,
  one per line, read every run); `web_sigma` scores the same logs with the
  SigmaHQ webserver ruleset, aggregated per rule + source IP. Public IPs carry
  offline origin columns (country, Tor/hosting/foreign, ASN).
- **Velociraptor live response**: per-row low-FP flags over the volatile state
  (processes, netstat, services, tasks, …) with a derived `suspicious.json` and
  cross-artifact `correlation.json`.

## Example outputs

*(All examples below use synthetic data — hosts, IPs and users are made up;
public IPs use the RFC 5737 documentation ranges.)*

A run over a mixed folder of acquisitions (KAPE + UAC + loose log drops):

```text
$ aeng run -p C:\Cases\breach-2026

[+] Extraction     16/16 archives (nested, anti zip-bomb)          195s
[+] Detection      21 machine(s)  (windows/kape, linux/uac, linux/fortigate, linux/weblogs)
[+] Parsing        974 task(s) | 32 proc + 32 thread
[+] Consolidation  <machine>.db + report.txt per machine            65s
[+] Lateral movement: 3150 edge(s), 1053 host(s), 114 suspicious, 4 pivot chain(s)
                      -> lateral_movement.csv + .html
[+] Done in 910s | 21 machine(s) | OK 737 | skipped 237 | errors 0
```

Every artifact lands as a per-category CSV, then all of them roll up into one
queryable `<machine>.db` (and, optionally, `.xlsx`). A detection CSV, for
example `Detections/web_sigma.csv` — the SigmaHQ web ruleset over access logs,
aggregated per rule + source IP and enriched with offline IP origin:

| level | rule | hits | ip | country | origin | status | sample_uri |
|---|---|--:|---|---|---|--:|---|
| high | SQL Injection Strings In URI | 214 | 198.51.100.23 | RU | hosting | 200 | `/app?id=1 UNION SELECT user,pass FROM users` |
| high | Path Traversal Exploitation Attempts | 61 | 203.0.113.9 | NL | hosting | 200 | `/dl?f=../../../../etc/passwd` |
| high | Webshell ReGeorg | 8 | 203.0.113.9 | NL | hosting | 200 | `/uploads/tunnel.php?cmd=read` |
| medium | Source Code Enumeration (.git/) | 33 | 198.51.100.23 | RU | hosting | 404 | `/.git/config` |

…and the `web` attack-hunt (`huntweb`) or the Velociraptor `suspicious.json`
follow the same shape: the interesting rows first, each with the reason it was
flagged.

## Output layout

Per machine, outputs are grouped by DFIR category under `CSVs/` (Filesystem,
FilesystemAccess (shellbags), Execution, EventLogs, Registry, SystemInfo, Shell,
Browser, Persistence, Search, Network, Processes, Web, Detections), plus `JSONs/`
for Velociraptor live response. They are then consolidated into `<machine>.db` and `<machine>.xlsx`
(either output can be turned off in `config.yaml`), plus a `report.txt` per
machine.

`report.txt` opens with a **Log coverage** section: per event channel (Windows) or
per rotated log (Linux), the window the evidence actually spans, and the verdict that
qualifies it — a channel dark while its siblings kept logging is flagged, one that
simply rotated out is not, and the two are never confused. It is printed before the
findings on purpose: a channel that holds ten days cannot report an intrusion from
three weeks ago, and its silence otherwise reads exactly like a quiet host.

Below it, a **Findings** section: every row the parsers flagged
`suspicious`, read back out of the `.db` that was just built, with `table + rowid`
so each one is `SELECT * FROM <table> WHERE rowid = <n>` away. `findings.csv`
beside it carries them for a logbook — capped at 500 rows per table, and the
report says which table it capped. Tables are ranked by how SELECTIVE
each flag is — two flagged rows out of five hundred sit above forty out of fifty,
because a rule that fires on most of its own table is a rule and not a finding.
The section also names the tables it does NOT cover (MFT, the EvtxECmd channels,
hayabusa — external tools with their own schemas and no such column), because a
short findings list over uncovered tables reads as a short case. Some of those
tools are read back by a parser of the engine's own, which then IS covered:
`sigma_sources` aggregates hayabusa's timeline per source address, `timestomp` and
`credential_access` read the transcoded MFT, `service_installs` and
`defender_detections` the EvtxECmd channels.

At the case root you also get `run-summary.{txt,json}` and, when Windows logon
events are present, a cross-machine **`lateral_movement.csv`** (unified logon
timeline) and **`lateral_movement.html`** (self-contained interactive graph of who
authenticated where -- RDP, explicit-credential, failed and inter-host movement
highlighted, plus detected **pivot chains**: user lands on a host and moves on
from it, listed as clickable attack paths). The graph needs no libraries and works
offline: direction arrows, search by user/host, filter by logon mechanism and,
independently, by outcome (succeeded / failed), a
time-range slider with chronological playback, zoom/pan, per-edge username + date
labels, and a chronological timeline sidebar.

With `avoid_vss: false`, each VSS snapshot is parsed as its own volume. Their
consolidated outputs then depend on `merge_vss`: merged (the default), a host's
live volume and all its snapshots produce a single `<host>.db`/`.xlsx`/`report.txt`
in the collection folder, beside `C/` and `VSS1/` rather than inside either;
unmerged, every snapshot keeps its own folder and `.db`.

Switching a case from unmerged to merged leaves the old per-volume outputs behind.
The engine never deletes anything inside a case, but it names what it found: the
warning gives the count and the total size, and the exact paths — one per line,
nothing else — go to **`stale-outputs.txt`** at the case root, so the list can be
reviewed and acted on directly instead of being reconstructed by hand:

```powershell
Get-Content "<case>\stale-outputs.txt" | Remove-Item -Force
```

The file is rewritten every run and emptied once nothing is stale, so it never
outlives the files it names.

## Reporting a bug

**Redact before you paste.** Issue threads are public and this tool reads real
evidence: run output carries hostnames, usernames, IP addresses, domains, file
paths and account or organisation names straight out of a case. Replace them with
placeholders (`HOST-01`, `jdoe`, `10.0.0.5`, `example.local`). Describe the shape
of a value rather than the value — the shape is nearly always the part that
matters to the bug.

The bug report form asks for the four things that decide whether a report can be
acted on at all: the phase the run was in, the `aeng` version, the Python and OS
build, and the relevant lines of `run-summary.txt` (which has carried a failed
parser's traceback since 0.7.9).

A new issue gets an automated first pass that says which phase and module it
points at, whether something in the code already explains the behaviour, and what
is missing to reproduce it. That pass runs with read-only access to the
repository and can do nothing but comment. Changes only ever arrive as a pull
request, opened at the maintainer's request and reviewed like any other.

## Third-party content

The engine itself is PolyForm Noncommercial 1.0.0 (see `LICENSE`). Everything it
*uses* arrives at runtime and keeps its own terms — `src/artifact_engine/tools/`
is not part of this repository, and no external binary is redistributed here.

| What | Where it comes from | Note |
|---|---|---|
| **db-ip country / ASN lite** | download.db-ip.com | **CC BY 4.0 — attribution required.** The `web_metrics` report carries the credit in its footer. |
| **world_map.json** | Natural Earth 110m | Public domain, no attribution required. |
| **Sigma rules** (bundled) | SigmaHQ | Detection Rule License. Upstream commit recorded in `data/sigma/VERSION`; rule `author`/`id` metadata is preserved. |
| **signature-base YARA** | Neo23x0 / Florian Roth | Detection Rule License. Fetched by `setup`/`update`, never redistributed here. |
| **awesome-lists** (service / task names, ransom notes) | mthcht/awesome-lists | **MIT — attribution required.** Fetched by `setup`/`update` into `assets/awesome/`, never redistributed here. Rows that quote a list carry its `metadata_reference` back into the CSV. |
| **hayabusa, chainsaw, EZ Tools, DeepBlueCLI** | upstream releases | Invoked as separate processes, never linked. Fetched at runtime. |

Reports quote YARA **rule identifiers**, never rule text, so a delivered report
is not a redistribution of a rule set.

One obligation is inherited by whoever *runs* the tool rather than by the code:
if you share a `web_metrics.html`, an `.xlsx` or any extract containing the
`country` / `asn` columns outside your own organisation, the db-ip credit has to
travel with it. It is built into the HTML report; for a spreadsheet or an extract
you copy out by hand, add it yourself.

Licence terms above are recorded from each project's published statement and are
not legal advice; check upstream before relying on them commercially.
