# Running the engine on Linux and on Windows

A proposal for making the tool install and behave the same on both systems was reviewed
against this tree. This document is the result: what it got right, what is already built,
what would be a regression if adopted as written, and what it missed. Then the work, in the
order that makes each step verifiable.

Everything below was checked against the code. Where a claim is a measurement, the file and
line are named so the next reader can re-measure instead of trusting this page.

---

## 0. The distinction the whole plan turns on

The proposal asks for one thing that is really two, with very different costs:

**A. The engine installs and runs on both systems.** Achievable, and closer than it looks.
The engine is a Python process that is invoked, works and exits. It has no service, no
daemon, no file locking, no IPC. Across `core/` and `cli.py` there are seven OS checks, two
of them cosmetic.

**B. The same evidence produces the same answers on both systems.** Achievable **for Linux
acquisitions**. **Not achievable for Windows acquisitions**, and no amount of engineering
changes that:

| Toolchain | On Windows | On Linux | Verified |
|---|---|---|---|
| Eric Zimmerman tools (14 assemblies) | the bundled apphost | framework-dependent .NET: `dotnet X.dll` runs the same program | **shape confirmed** (`runtimeconfig.json`: `net9.0`, `Microsoft.NETCore.App 9.0.0`); *whether each tool behaves* is untested — no .NET runtime here to try |
| chainsaw | native | **the Linux build is already inside the archive being downloaded** | **executed**: `chainsaw 2.16.2` runs, and the parser resolves natively |
| hayabusa | `win-x64` asset | `lin-x64-gnu` asset, same release | asset names read off the release API |
| sidr | native | **no Linux build is published at all** | release API: the only asset is `sidr.exe` |
| DeepBlueCLI | `powershell`, else `pwsh` | **no answer, and `pwsh` is not one**: the script reads every event through `Get-WinEvent` | PowerShell 7's own reference: that cmdlet "is only available on the Windows platform" |
| `esentutl` (SRUM/SUM repair) | in the OS | **no equivalent exists.** `win_sum` is simply lost | — |

So the promise this project can honestly make is:

> The engine installs and runs on Linux and on Windows. On **Linux acquisitions** both hosts
> produce the same tables. On **Windows acquisitions** the Linux host runs a reduced parser
> set, and the run says exactly which parsers it could not run and why.

That last clause is not a consolation prize — it is the requirement. A reduced parser set
that announces itself is triage. A reduced parser set that stays quiet is the project's
cardinal failure: *zero rows reading as no attack*. Every portability defect in this document
fails in exactly that direction, which is why the reporting work is not the polish at the end
of the plan but a first-class part of it.

---

## 1. What the audit found

| Proposal | State in the tree | Verdict |
|---|---|---|
| §3 add a console entry point | `artifact-engine` **and** `aeng` already in `pyproject.toml:33-35` | done |
| §3 `requires-python = ">=3.11"` | `>=3.10`, and CI gates 3.10 **and** 3.13 | **reject** — see §3 |
| §3 dependency list | would drop 7 real dependencies | **reject** — see §3 |
| §3 `filelock` replaces `fcntl`/`msvcrt` | **zero** occurrences of either in the tree; no locking anywhere | reject, no problem to solve |
| §4 config via `platformdirs` | install dir + cwd, layered (`config.py:129`); `--config` exists, no env var | partly worth doing — see Wave 4 |
| §4 cases root from config | there is no cases root: `aeng run -p <path>`, per invocation | not applicable |
| §5.1 case-insensitive evidence index | **the blocker, and understated** — see §2 | build, first |
| §5.2 long-path preflight | nothing; the downloader prefixed the extended-length form in one place only | **done** v0.7.50 — probed by behaviour, not read from the registry |
| §5.3 no hardcoded system paths | both were fallbacks already; both are now built only on the platform where the path can exist | **done** v0.7.44 (`esentutl`) and v0.7.46 (7-Zip) |
| §5.4 `shutil.which` + preflight, `.exe` in one place | `.exe` is in **38 parser manifests** and in the download asset names — see §4 | build, bigger than stated |
| §5.5 no `shell=True`, timeouts, capture stderr | `procs.run` takes argv lists, never a shell, `timeout=parser.timeout`, output to temp files, stderr into the error detail | **already done** |
| §5.6 explicit utf-8 | already explicit; the apparent exceptions are registry `.open()` calls and an xlsx helper | **already done** |
| §5.7 safe extraction | `_safe_relpath` rejects `..` and absolute members lexically; non-regular tar members (symlinks, devices, fifos) are skipped outright | **already done, and stronger than the proposal** (`filter="data"` does not exist on 3.10 anyway) |
| §5.8 remove `chmod` on output | there is none | nothing to do |
| §5.9 sanitise names on both platforms | `_sanitize_component` used to return early off Windows, so one archive became two trees | **real finding, fixed** v0.7.43 — the rule is the strictest one everywhere and every changed name is recorded |
| §6 always log to a file | already always, per case, JSON lines, `<case>/aeng-run.log` | gap is narrower — see Wave 6 |
| §7 write a `summary.json` | `run-summary.json` **already exists** (`report.py:226`) | make it a contract, not build it |
| §7 exit codes 0/1/2/3 | conflicts with the codes in use | **reject as written** — see §3 |
| §8/§9 notification layer | new, and not a portability change | separate track — see Wave 7 |
| §10 systemd / Task Scheduler | outside the repo | agreed |
| §12 CI matrix + cross-comparison | Windows-only until v0.7.36; a Linux leg now gates too | **done first**, not last — see Wave 0 |

---

## 2. The blocker, at its real size

`detector.parsers_for` selects a parser when every `requires` path exists:

```python
if all((machine.path / req).exists() for req in p.requires)     # detector.py:393
```

against literal entries like `Windows/AppCompat/Programs/Amcache.hve`. On a case-sensitive
filesystem an acquisition stored as `windows/` matches nothing, the parser is **not selected**,
and it lands in `skipped` — next to every artifact a host genuinely does not have. The run
ends `OK 2 | skipped 37 | errors 0`, which is what a clean triage of a quiet host looks like.
NTFS being case-insensitive is the only reason this has never bitten.

The proposal's `EvidenceIndex` is the right answer, and it is stated too small. There are
**three** surfaces that resolve a cased path against the evidence tree, not one:

1. **`requires` in 101 parser manifests** (67 Windows, 34 Linux) — `detector.py:393`.
2. **`detect` clauses in the profiles** — `detector.py:89` (`exists`) and `:91` (`glob`).
   These decide whether a machine is detected *at all*; getting 1 right and leaving this
   wrong means the case has no machines rather than no parsers.
3. **37 `command:` templates that embed a cased path and hand it to an external tool** —
   `{evidence}/Windows/AppCompat/Programs/Amcache.hve`. An index over `requires` alone makes
   the parser fire and then hands AmcacheParser a path that does not exist. Plus ~10 handlers
   that build one in Python (`win_persistence.py:242`, `win_tasks_disk.py:96`,
   `win_systeminfo.py:142`, `win_sysvol.py:204`, `win_yara.py:33`, …).

So the resolver has to be reachable from `_build_argv` **and** from `ParserContext`. That
second half has a known, measured price: `ParserContext` is in every handler's import closure,
so adding a field re-fingerprints all 75 Python parsers and forces a full re-parse of every
open case. That cost was paid deliberately once, in v0.7.34, for `internal_networks`. It
should be paid **once** here too — one context change carrying the resolver, not three.

---

## 3. What must not be adopted as written

**`requires-python = ">=3.11"`.** Nothing in the plan needs 3.11. CI gates 3.10 and 3.13
precisely because a CPython wording change between two versions silently disabled the
unraisable-hook filter once already. Raising the floor drops a tested configuration in
exchange for nothing.

**The dependency list.** Read as a replacement it deletes `pydantic`, `PyYAML`, `pandas`,
`XlsxWriter`, `python-registry`, `pysigma`, `maxminddb` and `cryptography` — i.e. the manifest
loader, the consolidation layer, the registry parsers and the Sigma engine. `platformdirs` is
a reasonable *addition*. `filelock` solves a problem this codebase does not have.

**The exit-code table.** The proposal wants `1 = partial`, `2 = failed`. In the tree today:

| Code | Meaning now |
|---|---|
| 0 | ran, nothing to report |
| 1 | **refused to start** — bad path, unreadable IOC file, no needles, wrong interpreter |
| 2 | `EXIT_INCOMPLETE` — the run finished, output is on disk, and it had parser errors or an acquisition that did not extract whole |
| 130 | Ctrl+C |

Swapping 1 and 2 would make "refused to start" and "finished with errors" trade places for
anyone already scripting this, and the comment at `cli.py:410-417` explains why they were
separated in the first place. **Keep them. Add `3` for a preflight abort** (which is genuinely
new: the run did not touch evidence) and document all four in the README.

**`pipx install artifact-engine`.** The package is not on PyPI, and the editable install is
the deployment model on purpose: `aeng update` fast-forwards the git checkout, so the clone
*is* the installation. A pipx install from an index would leave self-update with nothing to
update. If a non-git install path is wanted it is a separate decision with its own
consequences — not a line in a portability plan.

---

## 4. What the proposal missed

**Path *flavour*, which turned out to be the defect actually in the tree.** §5.3 asks for a
grep for literal backslashes and frames the answer as "use `pathlib`" — but `pathlib` is the
problem here, not the fix. Evidence paths from a Windows host are Windows paths on whatever
machine reads them, and `Path` is the *reader's* flavour. Measured in Wave 0: two parsers were
already wrong, one of them silently. See ARCHITECTURE §5 for the convention and Wave 0 for
what it cost.

**The `.exe` is not a suffix decision.** §5.4 asks for the suffix to be decided "in a single
point". But the manifests do not name a logical tool, they name a file:
`chainsaw/chainsaw_x86_64-pc-windows-msvc.exe`, whose Linux counterpart is a different asset
in a different release archive with a different internal layout. What is needed is a
**per-platform `source` and `binary` in the tool section**, resolved by one resolver — not a
conditional `+ ".exe"`.

**fork vs spawn.** `scheduler.py` runs a `ProcessPoolExecutor` alongside thread pools. On
Windows that means spawn; on Linux, fork — and forking a process that already has threads
running is a documented deadlock hazard. Nothing in the proposal mentions it. Pin
`mp_context=get_context("spawn")` so both platforms use the path the code was written and
crash-tested against. It also makes `_worker_init` behave identically, which the comments at
`scheduler.py:162` and `:193-195` already assume.

**The README says nothing about where the tool runs.** The `platform-Windows | Linux` badge
today describes the *evidence* it parses. A reader installing it will read it as the host OS.
That is a documentation defect the moment Linux is a declared target, and it is the one piece
of this plan that must land with the last code change, not after it.

**`esentutl` has no Linux equivalent**, so `win_sum` cannot run there. Not a bug to fix — a
row in the coverage table.

---

## 5. The work

Each wave is one shippable version, verified on both systems before the next opens. Waves 1
and 2 are the plan; everything after is smaller than it looks.

### Wave 0 — Measure. One CI change. **DONE** v0.7.36

An `ubuntu-latest` leg on the matrix, and the suite run against a genuinely case-sensitive
ext4 filesystem before it was added — on `/mnt/c` the measurement would have been worthless,
because drvfs is case-insensitive and the one thing being tested is what happens when the
filesystem stops forgiving.

This went first because every wave below was sized by inference. What it replaced that with:

**The engine installs and imports on Linux with no source change.** Python 3.12, dependencies
resolved, `python -m artifact_engine --version` answers. `ruff` clean.

**639 of 641 tests passed on the first run.** Not the expected outcome, and it re-sizes the
rest of this document: the suite's Windows assumptions turned out to be almost entirely
imaginary. The 12 files that reference `os.name` or a drive letter do so in ways that hold on
both.

**The two failures were one real defect, in a class this document had not named.** Not case
sensitivity — *path flavour*. `win_collection` parsed `$MFT` paths with `pathlib.Path`, which
is `PosixPath` off Windows, so `Path(r".\Users\jdoe\Desktop\KAPE").name` came back as the
whole string and the collector was never identified. The same defect sat unnoticed in
`win_lolbas`, where no test was watching: the Amcache basename never matched the LOLBAS list,
so that table would have come out **empty on every case** run from a Linux host. Fixed with
`PureWindowsPath`, documented as a convention in ARCHITECTURE §5, and enforced by
`tests/test_portability.py` — a meta-test rather than a platform test, so it bites on Windows
too and cannot regress the way the original did.

**The gate was collecting 14 tests that are not this project's.** `pytest` from the repo root
walked into `src/artifact_engine/tools/`, where `aeng setup` had downloaded chainsaw, and ran
SigmaHQ's own rule-lint suite. So the gate's size and colour depended on which chainsaw
release had last been fetched into a gitignored directory — 655 tests on this machine, 641 on
a clean checkout, and nothing in the output saying so. `testpaths = ["tests"]` in
`pyproject.toml` pins it. The engine's own suite is 642.

So the Linux leg is **blocking from day one** rather than advisory: it is green, and an
advisory leg that nobody has to fix is a leg that goes red and stays red.

What the leg does not prove: it runs no external binary, so it gates the Python half only.

**Left for Wave 1, unchanged:** none of this touched case sensitivity. Every test builds its
own fixture with the casing the handler expects, so the suite cannot see the defect at all —
it needs a fixture whose casing deliberately disagrees, which is Wave 1's job.

### Wave 1a — Names that differ only in case are not silently merged. **DONE** v0.7.37

This jumped the queue, and the reason is worth keeping: it is not a portability improvement,
it is a **data-loss defect on the platform the tool primarily runs on, affecting runs today.**

A Linux acquisition can legitimately hold `etc/Config` and `etc/config`. On NTFS those are one
path, and the extractor wrote both to it. What came out was not "one of the two files" — it
was a single file carrying the **first member's name and the second member's content**, whose
hash matches neither of the files that were on the host. `skipped: 0`, `sanitized: 0`, and the
run reported a clean tree. Reproduced before anything was changed.

Fixed by claiming each relative path as it is written: the first member is kept whole, the
second is dropped rather than spliced over it, the pair is named in the case log, and the
acquisition is marked `partial` — which is what `incomplete_acquisitions`, the run summary and
the exit code already read. The marker records it too, because extraction is the phase a
re-run skips.

The half worth noting for the rest of this document: whether two names collide is **probed on
the destination**, not inferred from `os.name`. An exFAT stick folds case under Linux and an
NTFS directory can be flagged case-sensitive, so the platform is the wrong question — and
probing is what lets one code path be correct on both, reporting nothing where both names can
coexist because nothing was lost there.

Not covered, and said plainly in the code: the 7-Zip *binary* fallback writes members itself,
so there is no per-member hook to refuse one.

**This is the direction the original proposal did not predict.** Its §5.1 anticipated
collisions as a *Linux reading* problem. The one that destroys evidence is *Windows writing*.

### Wave 1 — Evidence resolution, all three surfaces. **DONE** v0.7.38

`core/evidence.py` resolves a declared path against the tree that is actually there, on both
platforms with no conditional. Lazy: the exact spelling is one stat and always hits on Windows,
and only a miss walks the components, caching each directory it had to list. An eager index
would walk hundreds of thousands of entries per machine to answer what the fast path already
answers.

Three things the plan above got wrong, found while building it:

**The surface was four, not three.** `requires`, `detect` clauses and `{evidence}` templates
were the three named. The fourth is the handlers themselves, and it was the biggest: 33 sites
across 18 `win_*` handlers. The worst of them is a *glob* rather than a join —
`users_dir.glob("*/NTUSER.DAT")`, which three handlers use to find the per-user registry and
which matches **nothing** on a lowercased tree. No error, no empty directory: a parser
reporting no users on a machine full of them. `win_consolehost` had already hit this and
worked around it by hand, writing `PSRead[Ll]ine` into its pattern years ago.

**The `ParserContext` change was not needed at all.** The plan said to pay the 75-parser
re-fingerprint once, deliberately. But the resolver is not *configuration* — it is a function
of a path `ParserContext` already carries, so a module with an internal cache is the honest
shape and handlers just import it. (The full re-fingerprint happens anyway this version, since
`runner.py` imports `evidence` and every handler imports `runner` — which is precisely why the
handler conversions belong in *this* version rather than a later one that would pay it twice.)

**Two defects in the resolver itself, caught by its own tests.** The fast path let `..` escape:
`exists()` collapses a parent reference, so `Windows/../../elsewhere` came back as a real path
outside the volume, never seen by the walk. And the directory cache did not work — the
ambiguity check re-scanned the directory every time a component resolved by case, which on a
consistently lowercased acquisition is every component of every lookup.

**Enforced, not just fixed.** `tests/test_portability.py` bans a bare join onto `ctx.evidence`
in any `win_*` handler. On NTFS such a join works whatever the acquisition spelled, which is
exactly why it survived in eighteen files — so the guard has to bite on the forgiving platform
too, and it does.

### Wave 2a — Preflight: what this installation can run. **DONE** v0.7.39

`aeng preflight`, and the same report printed once during a run after machine detection and
before phase 3, scoped to the parsers that case selected. It lands in `run-summary.json` under
`tools` and in `report.txt`. Verified on Linux, where nothing is installed: *16 external tools
absent, 39 of 113 parsers cannot run*, exit 3.

Two things the plan above had wrong:

**There is no required/optional split, and inventing one would be a mistake.** The plan said
"absent and required → abort with exit code 3". But nothing in this engine is a mandatory tool:
every parser self-gates, and a triage of the artifacts that *are* reachable is worth having. A
`required: true` field would add a failure mode the engine does not otherwise have, to serve a
case that does not exist. So `aeng preflight` exits 3 — a deployment check wants a yes or no —
and `aeng run` reports and carries on.

**The value is not "fail fast", it is "say it once".** A missing binary already errors today,
per parser and per volume; it is not silent, it is *repeated*. On a host missing a toolchain
that is dozens of identical lines, each true, drowning the errors that are about the evidence.
Grouping by binary is most of the fix: EvtxECmd is one download and seventeen parsers.

And one boundary held deliberately: resolution is the runner's rule verbatim, with no `PATH`
fallback yet. A preflight that looked somewhere `_run_command` does not would call a tool
present and then watch the parser fail on it. The fallback lands in 2b, where the runner
changes anyway — and a test pins the two expressions together so they cannot drift apart
quietly.

### Wave 2b — Per-platform tools. **DONE** v0.7.40

`core/toolchain.py`, called by both `_run_command` and the preflight. A `linux:` block on a
manifest's `tool:` names a different file; everything written before it keeps working.

The measurements changed the shape of this work more than once:

**chainsaw needed no new download at all.** Its asset is literally named
`chainsaw_all_platforms+rules+examples.zip`, and `chainsaw_x86_64-unknown-linux-gnu` was
already sitting in the tools directory next to the Windows build. Four lines of manifest, and
`chainsaw 2.16.2` runs — executed on Linux, not inferred.

**The EZ tools were the opposite of what "per-platform asset" suggests.** They are not Windows
binaries with a Linux twin somewhere; they are framework-dependent .NET, and the `.exe` is a
340 KB apphost wrapping a 2.4 MB `.dll` that is already portable. So nothing is declared for
them: off Windows the resolver finds the `.dll` beside the apphost and starts `dotnet X.dll`.
What that does NOT establish is that they *work* there, and the code says so — a portable
assembly can still call a Windows API. The mechanism exists; the result will speak for itself.

**sidr has no Linux build**, confirmed against the release API rather than assumed. That is the
same kind of fact as `esentutl`: a row in the coverage table.

**And the `PATH` fallback the plan asked for was reverted after it worked.** `shutil.which`
found a separate copy of the EZ tools on the development machine and ran those — which breaks
the claim `tools.lock.json` exists to make, that the recorded sha256 is the build that produced
the results. `dotnet` stays the one thing taken from `PATH`, because it is a runtime and the
assembly it executes is still the pinned one.

**DeepBlueCLI turned out not to be an interpreter problem** — v0.7.41. The handler hardcoded
`powershell`, and the obvious fix was to fall back to `pwsh`, which does run on Linux. It would
have been the wrong fix: every event the script examines arrives through `Get-WinEvent`, and
PowerShell 7's reference for that cmdlet opens with *"This cmdlet is only available on the
Windows platform"*. Installing `pwsh` on a Linux host buys a script that starts and then fails
at its first data access, once per log and once per volume.

So the interpreter moved to `core/toolchain.powershell()` — `powershell` first (5.1 is what the
script was written against and what every run so far used), `pwsh` where that is absent — and off
Windows it refuses with the reason, which `aeng preflight` now prints before the evidence is
touched. `toolchain.resolve` grew the `.ps1` case for the same reason: a script has no `.exe`
suffix, so the "is it a file, and is it not a Windows apphost" test called DeepBlueCLI *runnable*
on Linux and the preflight reported it ready.

**And the parser was throwing its exit code away.** Measured against the samples that ship with
the tool and 200 KB of random bytes named `.evtx`: the script catches its own `Get-WinEvent`
failure, prints it with `Write-Host` (stdout, not stderr) and calls a bare `exit` — code 0. The
pipeline behind it still runs, so `Export-Csv` writes a three-byte file. Exit 0, empty stderr, and
a header-only CSV identical to the one a quiet log produces: a corrupt Security.evtx passed as a
log with nothing in it. That is this project's cardinal sin in its purest form, and it was on
Windows too, not a portability defect at all.

### Wave 3 — The remaining portability edges

- **A 7-Zip binary belongs in the preflight.** **DONE** v0.7.46. Found by running on Linux:
  without one, four of eleven acquisitions extracted to nothing. It is the only tool whose
  absence can cost a whole acquisition and the only one no manifest declares, so
  `preflight.check` — built from the manifests — cannot see it. `aeng preflight` now checks it
  first and exits 3 on it like any other absence, the run summary records `archiver_present`,
  and the message names the package (`p7zip-full`) rather than saying `aeng setup`, which cannot
  fetch a system package. `find_7z`'s `C:\Program Files` candidates are now built only on
  Windows — off it they were two guaranteed misses dressed up as a search, which also closes the
  second hardcoded path of Wave 3.
- **Long paths on Windows**: **DONE** v0.7.50, by *behaviour* — `extractor.long_path_warning`
  makes a 300-character path and writes into it. Reading `LongPathsEnabled` answers a different
  question: that key is one of TWO conditions, the running executable also has to declare
  `longPathAware` in its manifest, so a host where the key is 1 can still fail and the registry
  would have said yes. It is asked of the CASE ROOT in a run, because the limit belongs to the
  volume — a case on a mapped drive or a UNC share can answer differently from `C:`.
  It **warns rather than aborts**, which is a deliberate change from the line this replaced: the
  failure is already loud (extraction reports a failed or partial acquisition), so what was
  missing was saying it *first*, not stopping the run. Same shape as the archiver check in
  v0.7.46, and it counts towards `aeng preflight`'s exit 3 the same way.
- **Unconditional name sanitisation.** **DONE** v0.7.43. The proposal's reason is SMB; the
  stronger one is that it is what makes the two platforms extract the *same tree*, which is the
  precondition for comparing their outputs at all. It is a behaviour change on Linux — a name
  legal there is now rewritten — so every changed name is recorded in `.aeng_renamed.txt` beside
  the extraction, sampled into the case log, counted in the summary, and kept in the marker so a
  re-run that adopts the destination still reports it. Measured against a real 20,469-file UAC
  acquisition: **zero renames**, so nothing changes for the acquisitions this engine actually
  sees. Two gaps stated rather than left to be discovered: the 7-Zip binary fallback and the
  `py7zr` path both write members under the names they were given.
- **`mp_context="spawn"`** in the scheduler. **DONE** v0.7.41 — and CPython's own
  `DeprecationWarning` on 3.12 is the evidence, not a theory about fork. Enforced by a
  meta-test that bans any process pool built without a pinned start method.
- Drop the two hardcoded paths, or demote them explicitly to last-resort Windows fallbacks.
  **DONE**: `win_sum`'s `%SystemRoot%\System32\esentutl.exe` is returned only on Windows and only
  if it exists (v0.7.44), so off Windows the parser reports *why* instead of a FileNotFoundError
  on a path that cannot exist; `extractor.find_7z`'s two `C:\Program Files` candidates are
  built only on Windows (v0.7.46).

### Found by running it — a clean Linux host, 11 acquisitions

`aeng setup` on a box with no .NET, no PowerShell and an empty tools directory:
**18 s, 310 MB, the right assets** — hayabusa's `lin-x64-gnu` build, chainsaw's Linux binary out
of the archive that was being downloaded anyway, the EZ tools as `.exe` + `.dll` +
`runtimeconfig.json`. The per-platform work of v0.7.40 does what it says.

It also reported **"2 failed"** and named neither. Both were the casing defect above, and both
are fixed in v0.7.45 — including the count, which is now a line per tool.

**The one that is not fixed: no 7-Zip binary.** Four of the eleven acquisitions extracted to
nothing, each reported as `(no 7-Zip)` — an unsupported compression method twice, a corrupt
deflate stream once, a truncated archive once. The engine says so rather than inventing a clean
tree, which is the right failure, but it says so *during* extraction, after the analyst has
committed to the run. It is the only tool that can cost a whole acquisition and the only one no
manifest declares, so it belongs in the preflight — see Wave 3.

**And v0.7.43 earns its keep immediately**: six of the seven Linux acquisitions carried members
whose names Windows cannot hold — 336 of them in total, 17 to 80 per acquisition. Before v0.7.43
each of those extracted under one name on Linux and another on Windows.

### Wave 4 — Configuration discovery

**DONE** v0.7.52. The layering is now install dir → per-user config dir → cwd, with
`ARTIFACT_ENGINE_CONFIG` and `-c` each naming one file exclusively, and `aeng config` printing
the whole chain with the effective values.

Two departures from the plan as written. The per-user directory is computed rather than taken
from `platformdirs`: one dependency for two `os.environ` lookups is not a trade worth making,
and both conventions are stable. And the command is `aeng config`, not `aeng config show` —
there is one thing to show.

It stopped being theoretical during the Linux run: a 24-core host was observed at
`max_workers: 32` with the spreadsheet output off, both inherited from a different machine in a
folder copy, neither chosen for it, and nothing anywhere saying so. `aeng config` now flags
exactly that — a worker count that does not match this host's CPUs — and the other thing the
same run exposed, a `tools_dir` inside the install, where `aeng setup` puts 310 MB of binaries.

Note what does *not* move: there is no cases root to configure. The case is `-p <path>`.

### Wave 5 — `run-summary.json` as a contract

**DONE** v0.7.53. It carries `schema_version`, an `engine` block (version, Python, OS — no
hostname; the analyst's machine name is not something this file needs), `started_at` and
`finished_at` as ISO-8601 UTC with a `Z`, `duration_seconds`, and a top-level `status` of
`complete` or `incomplete`. Every key that was there is kept, including the parsers-not-run list
under `tools`.

"Agrees with the exit code" turned out to be the wrong shape: agreement is something two
independent computations can lose. `status` is now the only place the verdict is decided and
`cmd_run` DERIVES the exit code from it — a meta-test fails if that test reappears beside it.

The version is bumped when a key changes meaning or disappears, not when one is added: a reader
that ignores unknown keys is unaffected by growth. Which it needed — the keys grew twice in the
week before this existed and nothing downstream could tell.

### Wave 6 — The log that survives an unattended failure

Already always-on and per case. Two gaps: nothing rotates, and a failure *before* a case root
is known (bad path, preflight abort) leaves only stdout — which the Windows Task Scheduler
discards. Add a rotated global log in the platform log directory. Keep the per-case log where
it is; it is the one that belongs with the evidence.

### Wave 7 — Notification (separate track)

Not a portability change, and it should not gate one. When it is built, the design in the
proposal is sound: a `Notifier` protocol, backends selected by config, `stdout` as the default
so the repo is usable without secrets, fail-soft so a notifier outage never changes a case's
exit code, and the event built **from `run-summary.json`** rather than from engine state, so
what is announced is what is on disk.

The content rule is this project's existing one and is not negotiable: metadata only. Case
label, status, duration, detection counts by severity, failed phases. Never a hostname, path,
username, IOC value or artifact fragment — see the "Case data never becomes text" rule in
`CLAUDE.md`. A third-party chat service is outside the case directory in every sense that
matters. And the token is in the URL, so `raise_for_status()` will put it in a traceback
unless it is redacted on the way out.

### Wave 8 — CI that proves parity

Once Waves 1-3 land: run a versioned synthetic **Linux/UAC** case end to end on both legs and
diff the two `run-summary.json` files, ignoring duration, platform and timestamps. Counts and
status must match.

Linux/UAC and not Windows/KAPE on purpose: CI has no tool binaries (`aeng setup` fetches them
and they are gitignored), and every Linux parser is pure Python. That makes this the only
end-to-end comparison CI can actually run, and it is also the evidence class where parity is
a real promise rather than an aspiration. A Windows-evidence job can compare the
handler-only subset later.

Add a portability lint: literal backslash path separators, drive letters, and hardcoded FHS
paths outside tests.

---

## 6. Acceptance criteria

Rewritten from the proposal's, with the ones that cannot be met removed and the ones that
were missing added.

**Installation**

1. A clean Linux and a clean Windows both reach a working `artifact-engine --version` from the
   documented install path (the git checkout + editable install — *not* pipx; see §3).
2. `aeng config` names the origin of every effective value on both.
3. The portability lint passes on both legs.

**Behaviour**

4. The same **Linux/UAC** case produces equivalent `run-summary.json` on both, net of duration,
   platform and timestamps.
5. A **Windows/KAPE** case on Linux produces a *reduced* run whose summary states, per parser,
   what did not run and why. Parity is not claimed here and must not be asserted anywhere in
   the docs.
6. The mixed-casing fixture resolves on both; a real casing collision appears in the case log
   and the summary.
7. A >260-character output path processes on Windows with long paths enabled, and both
   `aeng preflight` and `aeng run` say so first when they are not — WARNING, not aborting. The
   failure is already loud (extraction reports a failed or partial acquisition), so what was
   missing was saying it before phase 1 rather than during it; the criterion said "aborts" only
   because it was written before the archiver check established the better shape.
8. A missing tool → `aeng preflight` names it and exits 3; `aeng run` reports the same list once,
   before phase 3, and finishes. The parsers it gated are counted apart from `skipped`, because
   that number is about the machine and this one is about the installation. No tool is
   mandatory, and none of this changes the run's own exit code.
9. The README states where the engine *runs*, separately from what it *parses*, and the
   asymmetry table of §0 is in it.

**Operation**

10. An unattended failure leaves a trace in a log file on both systems, without depending on
    stdout.
11. `Get-ScheduledTaskInfo` returns the documented exit code after a scheduled run.
12. If a notifier is configured: its outage does not change the case's exit code, and no token
    appears in any log after a forced failure.

---

## 7. Out of scope

- **Replacing the work model.** Queue, workers, concurrency and scheduling stay. No Celery, no
  RQ, no asyncio rewrite.
- **Case structure.** The engine already creates and governs it.
- **Parsers and detection logic.** Not rewritten, not reordered, not "modernised".
- **Deployment of the unattended pipeline** — service units, shares, resource limits, Defender
  exclusions. That is environment documentation, not repository code. Worth repeating one
  warning from the proposal, because it is correct: a machine whose evidence folder is excluded
  from its antivirus is a sample-handling environment and has to be treated as one.
- **Image mounting**, which is an external tool on both systems and never the engine's job.

If something on this list looks necessary to satisfy something above it, that is a question,
not a decision.
