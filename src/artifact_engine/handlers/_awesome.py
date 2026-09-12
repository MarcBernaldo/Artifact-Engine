"""Community threat lists (mthcht/awesome-lists), as patterns a handler can match.

The engine already carries curated lists for what LIVES ON DISK -- LOLBAS
binaries, RMM tools, vulnerable drivers -- and one analyst-editable list of named
tooling for what was TYPED into a shell. What it has never had is data for the
tables it builds and then does not judge: service names, scheduled-task names,
ransom notes. This reads the lists that cover those.

WHY THE METADATA MATTERS MORE THAN THE PATTERNS. Every row carries
`metadata_tool_type` -- `offensive_tool` or `greyware_tool` -- and a severity, and
that distinction is the whole reason these lists are usable here. A managed estate
runs PDQ and three RMM agents; flagging those turns the table into a rule and
`findings.py` will rank it last, correctly. So a handler flags what the list calls
offensive and REPORTS what it calls greyware, with the tool name and the
reference, and leaves the verdict where it belongs.

THE FORMAT. CSV with a first column of patterns in a shell-glob dialect: `*foo*`
is a substring, `Live_*` a prefix, a bare name an exact match. That is translated
to an anchored regex here rather than at every call site, because the translation
has one trap -- a pattern with no `*` must not become a substring search, or
`\\Defender` matches every Defender task on the machine.

WHAT ABSENCE MEANS. The lists arrive with `aeng update`, so on a fresh install
they are simply not there. Every consumer treats them as ENRICHMENT: the
structural detectors (a service whose image is a command shell, a random-looking
name) stand on their own, and a missing list costs the tool name and the
reference, never the finding.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path

from artifact_engine.logging_setup import get_logger

log = get_logger()

# Where `aeng update` puts them, under the assets dir.
DIR = "awesome"

# Rows read from one list. A hostile or corrupt CSV must not become a memory
# problem in a parser worker; the real lists are a few hundred rows.
_MAX_ROWS = 20_000


@dataclass(frozen=True)
class Entry:
    """One list row: what to match, and what the list says it is."""

    pattern: re.Pattern
    raw: str                 # the pattern as written, for the report
    tool: str = ""
    category: str = ""
    kind: str = ""           # offensive_tool | greyware_tool | ...
    severity: str = ""
    reference: str = ""
    extra: str = ""          # a second pattern column (a path, a command line)

    @property
    def offensive(self) -> bool:
        """Whether the list calls this an attacker's tool rather than software an
        attacker borrows. Only the first is worth a flag."""
        return "offensive" in self.kind.lower()


def to_regex(glob: str) -> re.Pattern | None:
    r"""A list pattern as an anchored, case-insensitive regex.

    `*foo*` -> contains foo, `foo*` -> starts with foo, `foo` -> exactly foo.
    Anchoring is the point: without it `\Defender` (a real entry, the name of a
    backdoor's task) would match `\Microsoft\Windows\Defender\Scheduled Scan` on
    every healthy machine in the case.
    """
    text = (glob or "").strip()
    if not text or text == "*":
        return None
    body = "".join(".*" if part == "*" else re.escape(part)
                   for part in re.split(r"(\*)", text) if part)
    try:
        return re.compile(rf"\A{body}\Z", re.IGNORECASE)
    except re.error as e:
        log.debug(f"awesome-lists: unusable pattern {text!r} ({e})")
        return None


def _first(row: dict, *names: str) -> str:
    for n in names:
        v = row.get(n)
        if v:
            return str(v).strip()
    return ""


class Patterns(list):
    r"""One list's entries, indexed so that a value matching nothing costs almost
    nothing to reject.

    A plain list, so everything that reads one keeps working. What is added is a
    three-part index over the SAME patterns, used only to answer "could any of
    these match at all".

    WHY. MEASURED on a real case: the 8,831,237 filesystem rows of seven Linux
    acquisitions. The ransomware lists carry 232 note names and 738 extensions;
    `match` scans every entry and deliberately does not stop at the first hit,
    because it is looking for an `offensive` one further down. `_ransom.classify`
    calls it three times per filename, so one name cost up to 1,708 regex
    searches -- 162 microseconds each, and 1,146 seconds of a 757-second run to
    produce 45 rows. It was the slowest thing the engine did, by a factor of
    seven over building the entire 8.8-million-row bodyfile it was reading.

    The patterns turned out to have shape. Of the 232 note names, 224 carry no
    `*` at all and are exact names; of the 738 extensions, 732 are `*X`, which is
    "ends with X" and nothing more. So:

      literals   a set          ->  one hash lookup
      suffixes   a tuple        ->  one `str.endswith`, a C-level loop
      others     an alternation ->  one regex search over the handful that are left

    Nearly every value falls out at the first two. When the index says no, the
    scan would have said no too, hundreds of searches later; when it says yes the
    scan still runs, because WHICH entry matched depends on list order and on
    `offensive`, and the index cannot answer that.

    The classification is exact rather than heuristic, and that matters, because
    the dangerous error is the index saying "no" where the scan would say "yes" --
    a detection silently lost. `to_regex` builds `\A{escaped}\Z` from a glob in
    which `*` becomes `.*` and everything else is `re.escape`d, so a pattern with
    no `*` matches exactly itself, and `*X` matches exactly the values ending in
    X. Anything whose shape is not one of those two goes to `others` untouched.
    Case folding is safe for the same reason: every pattern is IGNORECASE.

    Built once by `load`; the list is not mutated afterwards. Mutating one makes
    the index stale in the direction that loses detections, so build a new
    `Patterns` instead.
    """

    __slots__ = ("literals", "others", "suffixes")

    def __init__(self, entries=()) -> None:
        super().__init__(entries)
        literals: set[str] = set()
        suffixes: list[str] = []
        rest: list[Entry] = []
        for e in self:
            raw = (e.raw or "").strip()
            if not raw:
                rest.append(e)
            elif "*" not in raw:
                literals.add(raw.lower())
            elif raw.startswith("*") and "*" not in raw[1:]:
                suffixes.append(raw[1:].lower())
            else:
                rest.append(e)
        self.literals = frozenset(literals)
        self.suffixes = tuple(suffixes)
        self.others = _combined(rest)

    def could_match(self, text: str) -> bool:
        """Whether any entry COULD match `text`. Never False where one would."""
        low = text.lower()
        if low in self.literals:
            return True
        if self.suffixes and low.endswith(self.suffixes):
            return True
        return self.others is not None and self.others.search(text) is not None


def _combined(entries: list[Entry]) -> re.Pattern | None:
    r"""The alternation of the patterns that are neither exact nor a plain suffix.

    Safe to combine: `to_regex` emits nothing but `re.escape`d text and `.*`
    between `\A` and `\Z` -- no groups, no backreferences, no inline flags,
    nothing whose meaning changes inside an alternation. A failure here costs
    speed and never correctness, because `could_match` then says "maybe" and the
    scan decides, exactly as it always did.
    """
    if not entries:
        return None
    try:
        return re.compile("|".join(f"(?:{e.pattern.pattern})" for e in entries),
                          re.IGNORECASE)
    except (re.error, RecursionError, OverflowError) as e:
        log.debug(f"awesome-lists: no prefilter for {len(entries)} entries ({e})")
        return _ALWAYS


# Stands in for "this list could match anything": used only when the alternation
# above cannot be built, so the scan keeps deciding on its own.
_ALWAYS = re.compile("")


def load(assets: Path, name: str, key: str, extra_key: str = "") -> Patterns:
    """One list as Entries, or an empty one when it has not been downloaded.

    `key` is the column holding the pattern; `extra_key` an optional second one
    (a service's image path, a task's command) kept verbatim on the Entry.
    """
    path = Path(assets) / DIR / name
    if not path.is_file():
        return Patterns()
    out: list[Entry] = []
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            for i, row in enumerate(csv.DictReader(fh)):
                if i >= _MAX_ROWS:
                    log.warning(f"[!] {name}: stopped at {_MAX_ROWS} rows")
                    break
                raw = (row.get(key) or "").strip()
                pattern = to_regex(raw)
                if pattern is None:
                    continue
                out.append(Entry(
                    pattern=pattern, raw=raw,
                    tool=_first(row, "metadata_tool", "metadata_tool_name"),
                    category=_first(row, "metadata_tool_category"),
                    kind=_first(row, "metadata_tool_type"),
                    severity=_first(row, "metadata_severity"),
                    reference=_first(row, "metadata_link", "metadata_reference"),
                    extra=(row.get(extra_key) or "").strip() if extra_key else "",
                ))
    except (OSError, csv.Error) as e:
        log.warning(f"[!] could not read {name}: {e}")
        return Patterns()
    return Patterns(out)


def match(entries: list[Entry], value: str) -> Entry | None:
    """The first entry whose pattern covers `value`, offensive ones first.

    Order matters where a name is on the list twice -- a greyware RMM service and
    an offensive tool sharing a prefix -- because the caller reports whichever
    comes back, and the more serious reading is the one worth surfacing. Which is
    also why the scan below cannot stop at the first hit, and why it was worth
    1,146 seconds of a 757-second run before `Patterns.could_match` existed.
    """
    text = (value or "").strip()
    if not text:
        return None
    # One index lookup that can only say "no". It is wrong about nothing: the
    # same patterns, asked as a set membership, a suffix test and one alternation
    # instead of one regex search per entry.
    could = getattr(entries, "could_match", None)
    if could is not None and not could(text):
        return None
    hit = None
    for e in entries:
        if e.pattern.search(text):
            if e.offensive:
                return e
            hit = hit or e
    return hit
