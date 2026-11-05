"""Pydantic models for the YAML manifests (parsers and profiles).

The goal is that adding a tool or a collector is just editing a YAML, and that a
badly written manifest fails with a clear error (not halfway through a run).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

OSType = Literal["windows", "linux"]
ParserOSType = Literal["windows", "linux", "any"]
# What a parser's main table IS, for `docs/atlas.html`; the table's prefix says
# the same (`tests/test_atlas.py` holds the two together):
#   alert     every row is a finding -- a rule or catalogue hit, or a check that
#             lists only what it caught
#   artifact  the facts one source holds; a `suspicious` column may mark the rows
#             that matter, and those reach the Findings section and findings.csv
Kind = Literal["alert", "artifact"]


class StrictModel(BaseModel):
    # Reject unknown keys: catches typos in the YAML
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- #
# External tools (binaries)
# --------------------------------------------------------------------------- #
class ToolSource(StrictModel):
    """Where `aeng setup` gets the binary from."""

    repo: str | None = None      # owner/name in GitHub releases
    asset: str | None = None     # asset name inside the release
    url: str | None = None       # alternative direct URL
    sha256: str | None = None    # expected hash (integrity check)
    unpack: bool = False         # whether the asset is a zip to extract
    unpack_dir: str | None = None  # extract into this subfolder of tools_dir (isolates DLLs)
    rename_to: str | None = None # rename after download (e.g. *_windows.exe -> tool.exe)


class Tool(StrictModel):
    binary: str                  # executable name inside tools_dir
    source: ToolSource | None = None


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
class OutputSpec(StrictModel):
    path: str                    # template, e.g. "{out}/art_mft.csv"
    format: Literal["csv", "json", "txt"] = "csv"
    delimiter: str = ","


class Retry(StrictModel):
    when: str                    # text the failed run printed
    add: list[str]               # arguments appended for the second run


class ParserManifest(StrictModel):
    id: str
    name: str = ""
    description: str = ""
    os: ParserOSType = "any"
    category: str = ""
    # DOCUMENTARY ONLY, and deliberately outside `parser_fingerprint`
    # (`core/runner.py` hashes id/command/handler/short/subtypes/requires/
    # tool.binary and `retry` when set), so
    # writing either of these re-parses NOTHING. They are what `core/atlas.py`
    # renders: `source` is where the data comes from in the analyst's words, and
    # `kind` is what the resulting table is. Every BUNDLED manifest carries both
    # (`tests/test_atlas.py` fails otherwise); a manifest an analyst adds of their
    # own gets an empty source and the kind its id's prefix says.
    source: str = ""
    kind: Kind = "artifact"
    # Prefix of the tables a multi-output tool writes (`art_srum`), each named
    # `<short>_<subtype>`: the tool's subtype in snake_case, or the name `subtypes`
    # gives it (`ProgramEntries: programs`) to keep within Excel's 31 characters.
    short: str = ""
    subtypes: dict[str, str] = Field(default_factory=dict)
    # Paths (relative to the machine root) that must exist to trigger
    requires: list[str] = Field(default_factory=list)
    # DOCUMENTARY ONLY: a label for what this parser emits. Nothing reads it --
    # execution order comes from `depends_on` alone, so declaring `provides: [x]`
    # here and expecting another parser to wait for it does nothing.
    provides: list[str] = Field(default_factory=list)
    # Ids of other parsers that must finish first: THE ordering mechanism
    # (scheduler._topo_order / _levels; unknown ids are warned about and ignored).
    depends_on: list[str] = Field(default_factory=list)
    tool: Tool | None = None
    # A command that fails saying `when` (in its stdout or stderr, any case) runs
    # once more with `add` appended -- e.g. a dirty hive with no transaction logs
    # beside it, which AppCompatCacheParser refuses unless told to ignore the logs
    # it would otherwise replay. The run log and the run's detail say it happened.
    # Part of `parser_fingerprint`: a marker written by a retried run must not
    # outlive a change to what the retry does.
    retry: Retry | None = None
    # Declarative command: PREFERRED as a list of arguments (robust with spaces);
    # a string is also accepted (split with shlex). Placeholders: {binary} {evidence}
    # {out} {tools} {assets} {machine}.
    command: str | list[str] | None = None
    handler: str | None = None   # "module:function" (Python escape hatch)
    # Mostly documentary. Read in one place: before a parser has a record of what it
    # wrote (`core/outputs.py`, v0.7.106), the names declared directly in `{out}` say
    # which tables a re-run that no longer writes them should remove.
    outputs: list[OutputSpec] = Field(default_factory=list)
    # Parsers this one supersedes -- renamed, or folded into it -- each with the
    # names it wrote directly in `{out}`. That parser no longer exists, so no run
    # of its own will ever clean up after it; after an `ok` run of this one, those
    # names are removed (`outputs.retire`), so the consolidation does not load a
    # table nothing produces any more beside the one that replaced it.
    replaces: dict[str, list[str]] = Field(default_factory=dict)
    timeout: int = 600
    # False = skip this parser on VSS snapshot machines: for heavyweights whose
    # output barely differs from the live volume's (a snapshot's $MFT is ~the
    # same disk). The live machine still runs it.
    on_vss: bool = True
    # "heavy" = one of the long poles of a parse (art_mft and hayabusa:
    # ~200 s each on average on a measured 29-machine case, far above the rest). Dispatched ahead of every
    # other ready task, on every machine, so it never starts late and sets the
    # tail; everything else goes machine by machine (v0.7.133). Scheduling only:
    # outside `parser_fingerprint`, so setting it re-parses nothing.
    weight: Literal["normal", "heavy"] = "normal"

    @model_validator(mode="before")
    @classmethod
    def _kind_of_an_older_manifest(cls, data):
        """A manifest with no `kind:` takes the one its id's prefix says. One
        written before v0.7.187 says `alert: detect|flag|context` instead: that
        key is documentary, so it is dropped rather than failing the parser."""
        if isinstance(data, dict) and "kind" not in data:
            data = {k: v for k, v in data.items() if k != "alert"}
            data["kind"] = ("alert" if str(data.get("id", "")).startswith("alert_")
                            else "artifact")
        return data

    @model_validator(mode="after")
    def _exactly_one_executor(self) -> ParserManifest:
        if bool(self.command) == bool(self.handler):
            raise ValueError(
                f"parser '{self.id}': must define exactly one of 'command' or 'handler'"
            )
        if self.command and not self.tool:
            raise ValueError(f"parser '{self.id}': 'command' requires a 'tool' section")
        return self

    @property
    def display_name(self) -> str:
        return self.name or self.id


# --------------------------------------------------------------------------- #
# Profiles (OS / collector detection)
# --------------------------------------------------------------------------- #
class DetectClause(StrictModel):
    exists: str | None = None    # relative path that must exist
    glob: str | None = None      # glob pattern that must match
    dir_name: str | None = None  # regex the candidate FOLDER NAME must match
                                 # (convention-based drops, e.g. "weblogs[-label]")

    @model_validator(mode="after")
    def _one_condition(self) -> DetectClause:
        if sum(map(bool, (self.exists, self.glob, self.dir_name))) != 1:
            raise ValueError(
                "each detect clause must have exactly one of 'exists', 'glob' or 'dir_name'"
            )
        return self


class Detect(StrictModel):
    any_of: list[DetectClause] = Field(default_factory=list)
    all_of: list[DetectClause] = Field(default_factory=list)

    @model_validator(mode="after")
    def _non_empty(self) -> Detect:
        if not self.any_of and not self.all_of:
            raise ValueError("detect must have 'any_of' or 'all_of'")
        return self


class MachineName(StrictModel):
    # acquisition = the acquisition folder (first level under the root), useful for KAPE
    strategy: Literal["parent_dir", "dir_name", "file", "acquisition"] = "parent_dir"
    file: str | None = None      # for strategy=file (relative path)
    regex: str | None = None     # for strategy=acquisition: captures group 1 of the name
    suffix: str = ""             # e.g. "_uac"
    fallback: Literal["parent_dir", "dir_name"] = "dir_name"


class ProfileManifest(StrictModel):
    id: str
    description: str = ""
    os: OSType
    collector: str
    detect: Detect
    machine_name: MachineName = Field(default_factory=MachineName)
