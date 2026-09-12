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

| Toolchain | On Windows | On Linux |
|---|---|---|
| Eric Zimmerman tools (12 of them) | native, bundled | `net9` builds under `dotnet` — plausible, unverified |
| chainsaw / hayabusa / sidr | native | official Linux builds exist; the manifests pin the `-pc-windows-msvc.exe` asset |
| DeepBlueCLI | `powershell` | needs `pwsh`, and the handler hardcodes `powershell` |
| `esentutl` (SRUM/SUM repair) | in the OS | **no equivalent exists.** `win_sum` is simply lost |

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
| §5.2 long-path preflight | nothing; `downloader.py:30` prefixes `\\?\` in one place only | build |
| §5.3 no hardcoded system paths | two left: `extractor.py:180-181` (7-Zip, already a *fallback* after `shutil.which`), `win_sum.py:26` (`%SystemRoot%`, a Windows-only artifact anyway) | small, real |
| §5.4 `shutil.which` + preflight, `.exe` in one place | `.exe` is in **38 parser manifests** and in the download asset names — see §4 | build, bigger than stated |
| §5.5 no `shell=True`, timeouts, capture stderr | `procs.run` takes argv lists, never a shell, `timeout=parser.timeout`, output to temp files, stderr into the error detail | **already done** |
| §5.6 explicit utf-8 | already explicit; the apparent exceptions are registry `.open()` calls and an xlsx helper | **already done** |
| §5.7 safe extraction | `_safe_relpath` rejects `..` and absolute members lexically; non-regular tar members (symlinks, devices, fifos) are skipped outright | **already done, and stronger than the proposal** (`filter="data"` does not exist on 3.10 anyway) |
| §5.8 remove `chmod` on output | there is none | nothing to do |
| §5.9 sanitise names on both platforms | `_sanitize_component` returns early off Windows (`extractor.py:134`) | **real finding** — see Wave 3 |
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

### Wave 1 — Evidence resolution, all three surfaces

`core/evidence.py`: resolve a cased relative path against the tree that is actually there.
Used on **both** platforms, with no conditional — on Windows it is redundant and harmless, and
one code path is what stops the two systems diverging quietly.

- **Lazy, not an eager full index.** Try the literal path first, which is one `exists()` call
  and always hits on Windows and on a correctly-cased tree; only walk and cache the directories
  a lookup actually consults. An eager index over a KAPE tree costs a full walk per machine and
  has to be pickled to every pool worker, to answer questions almost all of which the fast path
  already answered. (Wave 1a's probe means the fast path can be skipped entirely where the
  filesystem folds case anyway.)
- Ambiguity is **recorded, not ignored**: where a case-insensitive lookup finds more than one
  candidate, the choice is a guess and the case log has to say so.
- Wire it into `detector.parsers_for`, the profile `detect` clauses, `_build_argv`, and
  `ParserContext` — **one** context change, since it re-fingerprints 75 parsers.

**Done when:** a fixture tree with deliberately mixed casing detects its machine, selects its
parsers and resolves its command templates identically on both systems.

### Wave 2 — Tool resolution and preflight

- Per-platform `source`/`binary` in the manifest `tool` section; one resolver, `shutil.which`
  plus configuration overrides, the platform decided in that one place.
- A **preflight** that runs before any evidence is touched: every tool a selected parser needs,
  present or absent, with version where it is cheap. Absent and optional → the parser is
  skipped with a reason. Absent and required → abort with exit code 3.
- Surface it as a command (`aeng preflight`) so it can be answered without starting a case.

The argument is not tidiness. Today a missing binary is reported by the parser that needed it,
mid-run, 37 times. What cannot happen is a two-hour case dying on a binary that was missing in
the first second — and what equally cannot happen is a Linux run quietly producing a Windows
case with a third of its parsers skipped and nothing saying that is why.

**Done when:** a Windows acquisition triaged on Linux ends with an explicit, counted list of
what could not run, in the console, in `run-summary.json` and in `report.txt`.

### Wave 3 — The remaining portability edges

- **Long paths on Windows**: check by *behaviour* — try to create a >260-character path in the
  scratch directory and act on the result. Reading the registry gives false positives when the
  interpreter manifest does not agree with it. Failure aborts with a message naming exactly
  what to enable.
- **Unconditional name sanitisation** (`extractor.py:134`). The proposal's reason is SMB; the
  stronger one is that it is what makes the two platforms extract the *same tree*, which is the
  precondition for comparing their outputs at all. It is a behaviour change on Linux — a name
  legal there is now rewritten — so the original name must be recorded, not just replaced.
- **`mp_context="spawn"`** in the scheduler.
- Drop the two hardcoded paths, or demote them explicitly to last-resort Windows fallbacks.

### Wave 4 — Configuration discovery

Add, above the current layering: `--config` (exists) → `ARTIFACT_ENGINE_CONFIG` →
per-user config dir via `platformdirs` → install dir → cwd. And `aeng config show`, printing
the effective value **and where each one came from**. That command is the first diagnostic
when two machines behave differently, and `Config.sources` already tracks most of what it needs.

Note what does *not* move: there is no cases root to configure. The case is `-p <path>`.

### Wave 5 — `run-summary.json` as a contract

It exists. Make it dependable: `schema_version`, `platform`, `started_at`/`finished_at` in UTC
with a `Z` suffix, `duration_seconds`, a top-level `status` that agrees with the exit code, and
the parsers-not-run list from Wave 2. Keep the keys that are there. Document it as the file
anything downstream reads — nothing should parse the log.

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
2. `aeng config show` names the origin of every effective value on both.
3. The portability lint passes on both legs.

**Behaviour**

4. The same **Linux/UAC** case produces equivalent `run-summary.json` on both, net of duration,
   platform and timestamps.
5. A **Windows/KAPE** case on Linux produces a *reduced* run whose summary states, per parser,
   what did not run and why. Parity is not claimed here and must not be asserted anywhere in
   the docs.
6. The mixed-casing fixture resolves on both; a real casing collision appears in the case log
   and the summary.
7. A >260-character output path processes on Windows with long paths enabled, and the preflight
   aborts with an actionable message when they are not.
8. A missing optional tool → the run finishes, the parser is listed as not run with its reason,
   exit code 2. A missing required tool → exit code 3, before evidence is touched.
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
