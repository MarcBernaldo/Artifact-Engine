"""The host's time zone from the SYSTEM hive: a disk-only acquisition has no live
response to say it, and every `_local` column is unreadable without it."""

from __future__ import annotations

import json
from pathlib import Path

from artifact_engine.core import report
from artifact_engine.core.detector import Machine, Volume
from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import win_systeminfo


class _Val:
    def __init__(self, name, value):
        self._n, self._v = name, value

    def name(self):
        return self._n

    def value(self):
        return self._v


class _Key:
    def __init__(self, values: dict):
        self._vals = [_Val(k, v) for k, v in values.items()]

    def values(self):
        return self._vals


class _Hive:
    """Just enough of python-registry's Registry: open(path) -> key or KeyError."""

    def __init__(self, keys: dict[str, dict]):
        self._keys = keys

    def open(self, path):
        if path not in self._keys:
            raise KeyError(path)
        return _Key(self._keys[path])


def _start(month: int) -> bytes:
    """A SYSTEMTIME: wYear, wMonth, wDayOfWeek, wDay, wHour, ..."""
    return (0).to_bytes(2, "little") + month.to_bytes(2, "little") + bytes(12)


_ROMANCE = {"TimeZoneKeyName": "Romance Standard Time", "StandardName": "@tzres.dll,-322",
            "Bias": 0xFFFFFFC4, "DaylightBias": 0xFFFFFFC4, "DaylightStart": _start(3),
            "DynamicDaylightTimeDisabled": 0}


def test_the_zone_its_offset_and_dst_come_from_the_current_control_set():
    hive = _Hive({
        "Select": {"Current": 2},
        r"ControlSet001\Control\TimeZoneInformation": {"TimeZoneKeyName": "UTC", "Bias": 0},
        r"ControlSet002\Control\TimeZoneInformation": _ROMANCE,
    })
    assert win_systeminfo._timezone(hive) == {
        "timezone_source": "SYSTEM hive", "timezone": "Romance Standard Time",
        "timezone_utc_offset": "+01:00", "timezone_dst": True}


def test_a_zone_west_of_utc_and_one_without_dst():
    hive = _Hive({r"ControlSet001\Control\TimeZoneInformation": {
        "TimeZoneKeyName": "Eastern Standard Time\x00junk after the name", "Bias": 300,
        "DaylightStart": _start(3), "DynamicDaylightTimeDisabled": 1}})
    tz = win_systeminfo._timezone(hive)
    assert tz["timezone"] == "Eastern Standard Time"
    assert tz["timezone_utc_offset"] == "-05:00"
    assert tz["timezone_dst"] is False, "automatic DST adjustment is switched off"

    half = _Hive({r"ControlSet001\Control\TimeZoneInformation": {
        "TimeZoneKeyName": "India Standard Time", "Bias": 0xFFFFFEB6, "DaylightStart": _start(0)}})
    tz = win_systeminfo._timezone(half)
    assert (tz["timezone_utc_offset"], tz["timezone_dst"]) == ("+05:30", False)


def test_standard_name_stands_in_only_when_it_is_text():
    old = _Hive({r"ControlSet001\Control\TimeZoneInformation": {
        "StandardName": "GMT Standard Time", "Bias": 0}})
    assert win_systeminfo._timezone(old)["timezone"] == "GMT Standard Time"

    resource = _Hive({r"ControlSet001\Control\TimeZoneInformation": {
        "StandardName": "@tzres.dll,-322", "Bias": 0xFFFFFFC4}})
    tz = win_systeminfo._timezone(resource)
    assert "timezone" not in tz, "a resource reference is not a zone name"
    assert tz["timezone_utc_offset"] == "+01:00"

    assert win_systeminfo._timezone(_Hive({})) == {}


def _run(tmp_path, monkeypatch, volume="C") -> dict:
    hive = _Hive({"Select": {"Current": 1},
                  r"ControlSet001\Control\TimeZoneInformation": _ROMANCE})
    cfg = tmp_path / "C" / "Windows" / "System32" / "config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(b"x")
    monkeypatch.setattr(win_systeminfo, "_open",
                        lambda path: hive if path.name == "SYSTEM" else None)
    monkeypatch.setattr(win_systeminfo, "_computer_name", lambda h: "HOST-01")
    monkeypatch.setattr(win_systeminfo, "_ips", lambda h: [])
    monkeypatch.setattr(win_systeminfo, "_domain", lambda h: {})
    out = tmp_path / "out"
    win_systeminfo.run(ParserContext(evidence=tmp_path / "C", out=out, tools=tmp_path,
                                     assets=tmp_path, machine_name="HOST-01", volume=volume,
                                     log=None))
    return json.loads((out / "art_machine_info.json").read_text(encoding="utf-8"))


def test_a_disk_only_acquisition_now_says_its_zone(tmp_path, monkeypatch):
    info = _run(tmp_path, monkeypatch)
    assert info["timezone"] == "Romance Standard Time"
    assert info["timezone_utc_offset"] == "+01:00" and info["timezone_source"] == "SYSTEM hive"


def test_the_live_abbreviation_is_kept_beside_the_hives_zone(tmp_path, monkeypatch):
    monkeypatch.setattr(win_systeminfo, "_live",
                        lambda rows: {"timezone": "CEST", "timezone_offset_s": 7200})
    info = _run(tmp_path, monkeypatch)
    assert info["timezone"] == "Romance Standard Time"
    assert info["timezone_at_collection"] == "CEST"
    assert info["timezone_offset_s"] == 7200


def test_a_snapshot_says_the_zone_its_own_hive_holds(tmp_path, monkeypatch):
    """Unlike the live response, the hive is the snapshot's own evidence."""
    assert _run(tmp_path, monkeypatch, volume="VSS1")["timezone"] == "Romance Standard Time"


def test_the_report_shows_the_zone_with_its_offset(tmp_path):
    csvs = tmp_path / "CSVs"
    csvs.mkdir()
    (csvs / "art_machine_info.json").write_text(json.dumps(
        {"timezone": "Romance Standard Time", "timezone_utc_offset": "+01:00",
         "timezone_dst": True}), encoding="utf-8")
    m = Machine("HOST-01", "windows", "kape", "windows_kape", tmp_path, "acq",
                [Volume("C", Path(tmp_path), True)])
    report.build(m, [])

    txt = (tmp_path / "report.txt").read_text(encoding="utf-8")
    assert "Timezone : Romance Standard Time (UTC+01:00, DST)" in txt
