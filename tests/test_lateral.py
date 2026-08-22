import csv as _csv
import json
import re
from pathlib import Path


def test_the_category_names_the_mechanism_never_the_outcome():
    """`failed` used to be returned first and won over everything, so a failed
    Kerberos request and a failed network logon collapsed to one class: the graph
    could say something failed but not what. Status is a separate axis."""
    from artifact_engine.core.lateral import _Edge, _edge_category

    def cat(eid, ltype, status):
        return _edge_category(_Edge("A", "B", "u", ltype, eid, status, True, True))

    assert cat("4769", None, "failed") == "kerberos", "a failed Kerberos lost its mechanism"
    assert cat("4625", 3, "failed") == "network", "a failed network logon lost its mechanism"
    assert cat("4625", 10, "failed") == "rdp"
    assert cat("4624", 3, "ok") == "network"
    # the Linux failure records name their own mechanism and carry no logon type,
    # so without explicit handling they fall through to "other"
    for eid in ("ssh_fail", "ssh_invalid", "btmp"):
        assert cat(eid, None, "failed") == "ssh", f"{eid} fell through to other"


def test_no_edge_is_ever_categorised_as_failed():
    """The whole point: `failed` is not a mechanism. If it reappears as a category
    the two axes have been collapsed again."""
    from artifact_engine.core import lateral

    for eid in ("4624", "4625", "4648", "4768", "4769", "1024", "TSC-MRU",
                "TypedPath", "ssh", "ssh_fail", "btmp", "known_host", "LSM-21"):
        for ltype in (None, 3, 9, 10):
            for status in ("ok", "failed"):
                c = lateral._edge_category(
                    lateral._Edge("A", "B", "u", ltype, eid, status, True, True))
                assert c != "failed", f"{eid}/{ltype}/{status} categorised as failed"


def test_every_graph_category_is_explained():
    """A class that reaches the legend without a description is a chip the analyst
    cannot act on. Pinned at the source so a new category cannot ship silent."""
    import inspect as _inspect
    import re as _re

    from artifact_engine.core import lateral, lateral_report

    # the function's own source rather than a slice of the file: the descriptions
    # moved to lateral_report, so the old "split at CAT_DESC" marker is gone and
    # that slice would now run past the end of _edge_category into whatever follows
    body = _inspect.getsource(lateral._edge_category)
    returned = set(_re.findall(r'return "([a-z_]+)"', body))
    assert returned, "could not read the categories back out of _edge_category"
    missing = sorted(returned - set(lateral_report.CAT_DESC))
    assert not missing, f"categories with no description: {missing}"


def test_every_reason_the_engine_emits_is_explained():
    """Same for the reason vocabulary, which is just as opaque to a reader."""
    import re as _re
    from pathlib import Path as _Path

    from artifact_engine.core import lateral, lateral_report

    # no split needed any more: the descriptions live in lateral_report, so scanning
    # the whole of lateral.py cannot match their own prose back at us
    src = _Path(lateral.__file__).read_text(encoding="utf-8")
    emitted = set(_re.findall(r'reasons\.add\("([a-z_]+)"\)', src))
    emitted |= set(_re.findall(r'reasons = \{"([a-z_]+)"', src))
    missing = sorted(emitted - set(lateral_report.REASON_DESC))
    assert not missing, f"reasons with no description: {missing}"


def test_an_offset_bearing_auth_timestamp_is_converted_not_relabelled():
    """auth.csv writes what the log wrote -- RFC3339 WITH an offset -- and it lands
    in a column named `_utc`. The offset used to be discarded rather than applied
    (only the leading 19 chars were matched, then rebuilt as UTC), so an edge from
    a host in UTC+2 read two hours late."""
    from artifact_engine.core.lateral import _as_utc

    assert _as_utc("2026-05-19T10:15:03+02:00") == "2026-05-19 08:15:03"
    assert _as_utc("2026-05-19 10:15:03-03:00") == "2026-05-19 13:15:03"
    assert _as_utc("2026-05-19 10:15:03") == "2026-05-19 10:15:03"


def test_a_yearless_syslog_timestamp_is_dropped_not_compared_as_text():
    """`May 19 10:15:03` has no year, and _add_edge keeps the window with max() on
    the raw string: "May ..." sorts after "Aug ...", so an edge spanning a month
    boundary reported first and last activity the wrong way round. An empty window
    is honest; an inverted one is not."""
    from artifact_engine.core.lateral import _as_utc

    assert _as_utc("May 19 10:15:03") == ""
    assert _as_utc("") == ""
    # the ordering bug this prevents, stated directly: max() over the raw strings
    # picks May over August, so first/last came out the wrong way round
    may, august = "May 19 10:15:03", "Aug 01 09:00:00"
    assert max(may, august) == may

from artifact_engine.core import lateral
from artifact_engine.core.detector import Machine, Volume

_HDR = ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider",
        "Channel", "ProcessId", "ThreadId", "Computer", "ChunkNumber", "UserId",
        "MapDescription", "UserName", "RemoteHost", "PayloadData1", "PayloadData2",
        "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6", "ExecutableInfo",
        "HiddenRecord", "SourceFile", "Keywords", "ExtraDataOffset", "Payload"]


def _win_machine(path, name, ips):
    (path / "CSVs" / "SystemInfo").mkdir(parents=True)
    (path / "CSVs" / "EventLogs").mkdir(parents=True)
    (path / "CSVs" / "SystemInfo" / "machine_info.json").write_text(
        json.dumps({"machine_name": name, "fqdn": f"{name}.corp", "IPs": ips}), encoding="utf-8")
    return Machine(name, "windows", "kape", "windows_kape", path, "src", [Volume("C", path, True)])


def _write_security(machine, rows):
    p = machine.path / "CSVs" / "EventLogs" / "evtx_security.csv"
    with p.open("w", encoding="utf-8", newline="") as fh:
        w = _csv.DictWriter(fh, fieldnames=_HDR)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def test_extract_src_formats():
    assert lateral._extract_src("- (192.168.1.5)") == "192.168.1.5"
    assert lateral._extract_src("WKSTN (-)") == "WKSTN"
    assert lateral._extract_src("- (::1)") is None
    assert lateral._extract_src("-:-") is None
    assert lateral._extract_src("::ffff:10.0.0.9:52000") == "10.0.0.9"


def test_norm_and_payload_helpers():
    assert lateral._norm_ip("::ffff:10.1.2.3:445") == "10.1.2.3"
    assert lateral._logon_type("x | LogonType 10 | y") == 10
    assert lateral._logon_type("no type here") is None
    assert lateral._first(lateral._RE_TARGET, "Target: CORP\\admin") == "CORP\\admin"
    assert lateral._first(lateral._RE_TARGET_SERVER, "TargetServerName: srv01") == "srv01"


def test_clean_user_canonicalises_identity():
    # same principal, many spellings -> one canonical form (edges merge)
    for v in ("CORP\\administrator", "CORP\\Administrator",
              "corp\\administrator", "CORP\\ADMINISTRATOR",
              "CORP.LOCAL\\Administrator", "\\CORP\\administrator\\"):
        assert lateral._clean_user(v) == "CORP\\administrator"
    # genuinely different domains stay distinct
    assert lateral._clean_user("OTHERDOM\\administrator") == "OTHERDOM\\administrator"
    assert lateral._clean_user("workgroup\\administrator") == "WORKGROUP\\administrator"
    # bare / empty / null tokens
    assert lateral._clean_user("administrator") == "administrator"
    assert lateral._clean_user("-") == "" and lateral._clean_user("") == ""


def test_clean_user_unknown_domain_and_case_do_not_split_a_principal():
    """`-` is EvtxECmd's "no domain recorded" placeholder, not a domain -- the RDP
    operational channels emit it constantly. Treating it as one split a single
    principal roughly in half on a real case (`-\\svc` 16.7k events vs `CORP\\svc`
    16.0k), so half of an actor's activity hid behind a search for either form.
    Bare names fold case for the same reason, and to agree with `_short_user`
    (which chain / brute_success matching already lower-cases)."""
    assert lateral._clean_user("-\\jdoe") == "jdoe"
    assert lateral._clean_user("-\\JDoe") == "jdoe"
    assert lateral._clean_user("Administrador") == lateral._clean_user("administrador")
    # a name with no account left is not an account
    assert lateral._clean_user("CORP\\-") == "" and lateral._clean_user("CORP\\") == ""
    # but a REAL domain still separates principals: a machine's LOCAL administrator
    # is not the domain administrator, and merging them invents lateral movement
    assert lateral._clean_user("SRV01\\administrator") != lateral._clean_user("CORP\\administrator")
    assert lateral._clean_user("SRV01\\administrator") != lateral._clean_user("administrator")


def test_resolve_by_ip_name_and_external(tmp_path):
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    index = lateral._load_host_index([a])
    assert lateral._resolve("10.0.0.10", index) == ("PCA", True)
    assert lateral._resolve("pca.corp", index) == ("PCA", True)
    assert lateral._resolve("203.0.113.9", index) == ("203.0.113.9", False)


def test_build_lateral_graph(tmp_path):
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_security(b, [
        # RDP (type 10) from PCA's IP -> lateral PCA->PCB, flagged rdp
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "4624", "Computer": "PCB.corp",
         "UserName": "CORP\\attacker", "RemoteHost": "- (10.0.0.10)",
         "PayloadData1": "Target: CORP\\attacker", "PayloadData2": "LogonType 10"},
        # local service logon (type 5) -> ignored
        {"TimeCreated": "2026-06-18 10:01:00", "EventId": "4624", "Computer": "PCB.corp",
         "UserName": "PCB$", "RemoteHost": "- (-)",
         "PayloadData1": "Target: SYSTEM", "PayloadData2": "LogonType 5"},
        # failed logon (4625) from an EXTERNAL ip -> external_source + failed_logon
        {"TimeCreated": "2026-06-18 10:02:00", "EventId": "4625", "Computer": "PCB.corp",
         "UserName": "-", "RemoteHost": "- (203.0.113.9)",
         "PayloadData1": "Target: \\", "PayloadData2": "LogonType 3"},
    ])

    summary = lateral.build([a, b], tmp_path)

    assert (tmp_path / "lateral_movement.csv").is_file()
    assert (tmp_path / "lateral_movement.html").is_file()
    assert summary["edges"] == 2                       # type-5 local logon dropped
    with (tmp_path / "lateral_movement.csv").open(encoding="utf-8") as fh:
        out = list(_csv.DictReader(fh))
    rdp = [r for r in out if r["event_id"] == "4624"]
    assert len(rdp) == 1
    assert rdp[0]["src"] == "PCA" and rdp[0]["dst"] == "PCB"
    # between two ACQUIRED hosts -> case_to_case is what makes it notable; a plain
    # successful RDP no longer carries a reason of its own (see _rdp_in_reasons)
    assert rdp[0]["src_in_case"] == "yes" and "case_to_case" in rdp[0]["reasons"]
    ext = [r for r in out if r["event_id"] == "4625"][0]
    assert ext["src"] == "203.0.113.9" and ext["src_in_case"] == "no"
    assert "failed_logon" in ext["reasons"] and "external_source" not in ext["reasons"]
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    assert "PCA" in page and "PCB" in page and "203.0.113.9" in page
    # each edge carries the username, category and timestamps for labels/filtering
    assert '"user":' in page and "attacker" in page
    assert '"cat":' in page and '"first":' in page and '"count":' in page
    # interactive controls: user/host search, logon-category chips, time-range
    # sliders, and the chronological timeline sidebar
    assert 'id="q"' in page and 'id="cats"' in page
    assert 'id="ta"' in page and 'id="tb"' in page
    assert "function applyFilters(" in page and "Timeline" in page


def test_anonymous_logon_flagged_and_server_role(tmp_path):
    """A network null-session logon is surfaced (reason anonymous_logon), and an
    off-case node reached BY NAME is a `server` while a bare source IP is
    `external` -- so the graph separates targets from source IPs."""
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    _write_security(a, [
        # anonymous network logon from an external IP -> flagged
        {"TimeCreated": "2026-06-18 03:00:00", "EventId": "4624", "Computer": "PCA.corp",
         "UserName": "NT AUTHORITY\\ANONYMOUS LOGON", "RemoteHost": "- (203.0.113.9)",
         "PayloadData1": "Target: NT AUTHORITY\\ANONYMOUS LOGON", "PayloadData2": "LogonType 3"},
        # explicit creds out to a named server (not in the case) -> server node
        {"TimeCreated": "2026-06-18 03:05:00", "EventId": "4648", "Computer": "PCA.corp",
         "UserName": "CORP\\admin", "RemoteHost": "-:-",
         "PayloadData1": "Target: CORP\\admin", "PayloadData2": "TargetServerName: fileserver01"},
    ])
    lateral.build([a], tmp_path)
    with (tmp_path / "lateral_movement.csv").open(encoding="utf-8") as fh:
        rows = list(_csv.DictReader(fh))
    anon = [r for r in rows if "anonymous_logon" in r["reasons"]]
    assert len(anon) == 1 and anon[0]["src"] == "203.0.113.9"

    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    import json as _json
    nodes = _json.loads(re.search(r"const NODES=(\[.*?\]), LINKS=", page, re.DOTALL).group(1))
    role = {n["id"]: n["role"] for n in nodes}
    assert role["fileserver01"] == "server"     # reached by name -> internal server
    assert role["203.0.113.9"] == "external"     # bare source IP -> attacker origin
    assert role["PCA"] == "case"


def test_build_4648_outbound_and_kerberos(tmp_path):
    dc = _win_machine(tmp_path / "DC", "DC01", ["10.0.0.1"])
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    # PCA used explicit creds to reach SRV5 (4648 outbound), and hit the DC (4768)
    _write_security(a, [
        {"TimeCreated": "2026-06-18 11:00:00", "EventId": "4648", "Computer": "PCA.corp",
         "UserName": "CORP\\svc", "RemoteHost": "-:-",
         "PayloadData1": "Target: CORP\\svc", "PayloadData2": "TargetServerName: SRV5"},
    ])
    _write_security(dc, [
        {"TimeCreated": "2026-06-18 11:05:00", "EventId": "4768", "Computer": "DC01.corp",
         "UserName": "", "RemoteHost": "::ffff:10.0.0.10:5000",
         "PayloadData1": "Target: CORP\\svc", "PayloadData2": "ServiceName: krbtgt"},
    ])
    summary = lateral.build([dc, a], tmp_path)
    with (tmp_path / "lateral_movement.csv").open(encoding="utf-8") as fh:
        out = list(_csv.DictReader(fh))
    e48 = [r for r in out if r["event_id"] == "4648"][0]
    # unresolved external host name is canonicalised to short lower-case ("SRV5"->"srv5")
    assert e48["src"] == "PCA" and e48["dst"] == "srv5" and "explicit_creds" in e48["reasons"]
    e68 = [r for r in out if r["event_id"] == "4768"][0]
    assert e68["src"] == "PCA" and e68["dst"] == "DC01"     # 10.0.0.10 resolved to PCA
    assert summary["hosts"] >= 3


def test_4648_to_own_machine_account_is_skipped(tmp_path):
    """A 4648 whose TargetServerName is the host's own machine account (PCA$) is a
    local runas, not lateral movement -> dropped (the trailing $ resolves to self)."""
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    _write_security(a, [
        {"TimeCreated": "2026-06-18 12:00:00", "EventId": "4648", "Computer": "PCA.corp",
         "UserName": "CORP\\u", "RemoteHost": "-:-",
         "PayloadData1": "Target: CORP\\u", "PayloadData2": "TargetServerName: PCA$"},
    ])
    summary = lateral.build([a], tmp_path)
    assert summary["edges"] == 0


def test_build_skips_vss_and_empty_linux(tmp_path):
    """VSS snapshots are excluded (duplicate the live host's logs); a Linux machine
    with no parsed logon CSVs simply contributes nothing -> no output at all."""
    vss = Machine("PCA_VSS1", "windows", "kape", "windows_kape",
                  tmp_path / "V", "src", [Volume("VSS1", tmp_path / "V", True)])
    lin = Machine("h", "linux", "uac", "linux_uac", tmp_path / "L", "src",
                  [Volume("live", tmp_path / "L", True)])
    summary = lateral.build([vss, lin], tmp_path)
    assert summary == {"hosts": 0, "edges": 0, "suspicious": 0}
    assert not (tmp_path / "lateral_movement.csv").exists()


# --------------------------------------------------------------------------- #
# Linux/UAC lateral movement (SSH), unified into the same graph
# --------------------------------------------------------------------------- #
def _lin_machine(path, name, ips):
    """A Linux/UAC machine whose m.name carries the `_uac` suffix (as the detector
    assigns) while machine_info reports the bare hostname -- so the tests also
    exercise canonicalisation onto a single node label."""
    (path / "CSVs" / "SystemInfo").mkdir(parents=True)
    (path / "CSVs" / "SystemInfo" / "machine_info.json").write_text(
        json.dumps({"machine_name": name, "IPs": ips}), encoding="utf-8")
    return Machine(name + "_uac", "linux", "uac", "linux_uac", path, "src",
                   [Volume("live", path, True)])


def test_linux_ssh_inbound_gating_and_brute_success(tmp_path):
    lnx1 = _lin_machine(tmp_path / "L1", "lnx1", ["10.0.0.30"])
    lnx2 = _lin_machine(tmp_path / "L2", "lnx2", ["10.0.0.40"])
    # wtmp: case->case login (graphed), a routine external login (csv-only), a
    # local console login (dropped), and a success from a brute-forcing IP.
    _write_rows(lnx1, "EventLogs", "wtmp.csv", ["time_utc", "user", "type", "line", "host"], [
        ["2026-06-18 10:00:00", "alice", "USER_PROCESS", "pts/0", "10.0.0.40"],   # <- lnx2 (case)
        ["2026-06-18 09:00:00", "carol", "USER_PROCESS", "pts/2", "10.0.0.99"],   # routine ext
        ["2026-06-18 08:00:00", "root", "USER_PROCESS", "tty1", ""],              # local -> drop
        ["2026-06-18 11:00:00", "mallory", "USER_PROCESS", "pts/1", "203.0.113.5"],  # brute win
    ])
    # btmp: 6 failures from the same IP -> brute_success on the wtmp login above.
    _write_rows(lnx1, "EventLogs", "btmp.csv", ["time_utc", "user", "type", "line", "host"],
                [[f"2026-06-18 10:5{i}:00", "mallory", "LOGIN_PROCESS", "ssh:notty", "203.0.113.5"]
                 for i in range(6)])
    # auth: accepted (method, ISO ts parses) + invalid user (legacy ts, no year).
    _write_rows(lnx1, "EventLogs", "auth.csv",
                ["timestamp", "host", "event", "user", "source", "detail"], [
        ["2026-06-18 10:00:01", "lnx1", "ssh_accepted", "alice", "10.0.0.40", "publickey port 22"],
        ["Jun 18 10:55:00", "lnx1", "ssh_invalid_user", "admin", "198.51.100.7", ""],
        ["Jun 18 10:56:00", "lnx1", "su", "root", "", ""],                        # not ssh -> ignore
    ])
    # known_hosts: one case target (graphed), one external IP + one bracketed host
    # (csv-only), one hashed summary (dropped).
    _write_rows(lnx1, "Network", "known_hosts.csv",
                ["account", "target", "key_types", "note", "suspicious"], [
        ["alice", "10.0.0.40", "ssh-rsa", "", ""],                 # -> lnx2 (case)
        ["alice", "198.51.100.20", "ssh-rsa", "", ""],             # external -> csv only
        ["bob", "[gitserver.example]:2222", "ssh-rsa", "", ""],    # bracketed host -> csv only
        ["dbw", "(hashed)", "ssh-rsa", "13 entries", ""],          # summary -> dropped
    ])

    summary = lateral.build([lnx1, lnx2], tmp_path)
    assert summary["chains"] == 0 and summary["edges"] >= 6
    out = list(_csv.DictReader((tmp_path / "lateral_movement.csv").open(encoding="utf-8")))

    def by(eid):
        return [r for r in out if r["event_id"] == eid]

    # inbound case->case wtmp login, canonicalised to bare hostnames on one node each
    w_alice = [r for r in by("wtmp") if r["user"] == "alice"][0]
    assert w_alice["src"] == "lnx2" and w_alice["dst"] == "lnx1"
    assert "case_to_case" in w_alice["reasons"]
    # routine external login: in the csv, but NOT flagged (stays out of the graph)
    w_carol = [r for r in by("wtmp") if r["user"] == "carol"][0]
    assert w_carol["src"] == "10.0.0.99" and w_carol["reasons"] == ""
    # local console login dropped entirely
    assert not [r for r in by("wtmp") if r["user"] == "root"]
    # brute force that worked: 6 btmp fails + the success from the same IP
    b = by("btmp")[0]
    assert b["src"] == "203.0.113.5" and b["count"] == "6" and "failed_logon" in b["reasons"]
    w_mal = [r for r in by("wtmp") if r["user"] == "mallory"][0]
    assert "brute_success" in w_mal["reasons"]
    # auth: accepted carries the method edge (ISO ts parsed), invalid user is failed
    a_ok = by("ssh")[0]
    assert a_ok["user"] == "alice" and a_ok["first_seen_utc"] == "2026-06-18 10:00:01"
    inv = by("ssh_invalid")[0]
    assert inv["src"] == "198.51.100.7" and "invalid_user" in inv["reasons"]
    # legacy syslog line keeps its raw string but has no year -> not a real time,
    # so it never lands on the timeline / a chain (wtmp/btmp carry those)
    # CHANGED with the _as_utc fix, deliberately: this used to assert that a
    # yearless syslog stamp lands verbatim in a column named `_utc`. It is not
    # UTC, it has no year, and _add_edge keeps the window with max() on the raw
    # string -- so "May ..." sorts after "Aug ..." and an edge spanning a month
    # boundary reported first/last inverted. Dropping it leaves an empty window,
    # which is honest; keeping it produced a wrong one that looked right.
    assert inv["first_seen_utc"] == ""
    assert lateral._parse_ts(inv["first_seen_utc"]) is None
    # known_hosts: case target graphed, external + bracketed targets csv-only
    kh = by("known_host")
    kh_case = [r for r in kh if r["dst"] == "lnx2"][0]
    assert kh_case["src"] == "lnx1" and "case_to_case" in kh_case["reasons"]
    assert any(r["dst"] == "gitserver" for r in kh)   # bracket/port stripped, short-form canon
    assert not [r for r in kh if "198.51.100.20" in r["dst"] and r["reasons"]]

    # graph: linux role on acquired hosts, ssh categories, and routine/csv-only
    # peers kept out of the graph
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    nodes = json.loads(re.search(r"const NODES=(\[.*?\]), LINKS=", page, re.DOTALL).group(1))
    role = {n["id"]: n["role"] for n in nodes}
    assert role["lnx1"] == "linux" and role["lnx2"] == "linux"
    assert role["203.0.113.5"] == "external"
    assert "10.0.0.99" not in role                    # routine login: csv-only
    assert "198.51.100.20" not in role                # reference known_host: csv-only
    assert '"ssh"' in page and "ssh_known_host" in page
    assert "brute_success" in page


def test_linux_pivot_chain_cross_host(tmp_path):
    """X ->(u) B (ssh) then B ->(u) Y (ssh) within the window = Linux pivot chain,
    reusing the same chain machinery as Windows."""
    x = _lin_machine(tmp_path / "X", "lnx1", ["10.0.0.30"])
    b = _lin_machine(tmp_path / "B", "lnx2", ["10.0.0.40"])
    y = _lin_machine(tmp_path / "Y", "lnx3", ["10.0.0.50"])
    # eve lands on B from X ...
    _write_rows(b, "EventLogs", "wtmp.csv", ["time_utc", "user", "type", "line", "host"],
                [["2026-06-18 10:00:00", "eve", "USER_PROCESS", "pts/0", "10.0.0.30"]])
    # ... then reaches Y from B, 30 min later, same account
    _write_rows(y, "EventLogs", "wtmp.csv", ["time_utc", "user", "type", "line", "host"],
                [["2026-06-18 10:30:00", "eve", "USER_PROCESS", "pts/0", "10.0.0.40"]])
    summary = lateral.build([x, b, y], tmp_path)
    assert summary["chains"] == 1
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    assert '"path": ["lnx1", "lnx2", "lnx3"]' in page
    out = list(_csv.DictReader((tmp_path / "lateral_movement.csv").open(encoding="utf-8")))
    assert all("chain" in r["reasons"] for r in out if r["event_id"] == "wtmp")


def _write_evtx(machine, fname, rows):
    d = machine.path / "CSVs" / "EventLogs"
    d.mkdir(parents=True, exist_ok=True)
    with (d / fname).open("w", encoding="utf-8", newline="") as fh:
        w = _csv.DictWriter(fh, fieldnames=_HDR)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def test_rdp_inbound_from_lsm_and_rcm(tmp_path):
    """Destination-side inbound RDP from the operational logs: LocalSessionManager
    25 (reconnect) / 21 (logon) and RemoteConnectionManager 1149. Source is in
    RemoteHost, account in UserName; LOCAL console + IPv6 link-local are dropped."""
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_evtx(b, "evtx_rdpSessions.csv", [
        # reconnect from PCA -> inbound RDP, case_to_case
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "25", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "10.0.0.10", "PayloadData1": "Session ID: 1"},
        # console logon (LOCAL) -> not lateral, dropped
        {"TimeCreated": "2026-06-18 10:01:00", "EventId": "21", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "LOCAL", "PayloadData1": "Session ID: 1"},
        # reconnect from IPv6 link-local -> dropped
        {"TimeCreated": "2026-06-18 10:02:00", "EventId": "25", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "0:0:fe80::e69e:e7fa%2953534224",
         "PayloadData1": "Session ID: 2"},
        # logon from an external IP -> inbound RDP, no case_to_case
        {"TimeCreated": "2026-06-18 10:03:00", "EventId": "21", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "203.0.113.9", "PayloadData1": "Session ID: 3"},
        # disconnect (24) -> not a login, ignored
        {"TimeCreated": "2026-06-18 10:04:00", "EventId": "24", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "10.0.0.10", "PayloadData1": "Session ID: 1"},
    ])
    _write_evtx(b, "evtx_rdpAuth.csv", [
        {"TimeCreated": "2026-06-18 09:59:00", "EventId": "1149", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "10.0.0.10"},
    ])
    lateral.build([a, b], tmp_path)
    out = list(_csv.DictReader((tmp_path / "lateral_movement.csv").open(encoding="utf-8")))

    lsm25 = [r for r in out if r["event_id"] == "LSM-25"]
    assert len(lsm25) == 1                                  # link-local dropped
    assert lsm25[0]["src"] == "PCA" and lsm25[0]["dst"] == "PCB"
    assert lsm25[0]["logon_type"] == "rdp"
    assert "case_to_case" in lsm25[0]["reasons"]      # acquired -> acquired
    assert "rdp" not in lsm25[0]["reasons"]           # routine RDP is not a reason
    lsm21 = [r for r in out if r["event_id"] == "LSM-21"]
    assert len(lsm21) == 1 and lsm21[0]["src"] == "203.0.113.9"   # LOCAL dropped, external kept
    rcm = [r for r in out if r["event_id"] == "RCM-1149"]
    assert len(rcm) == 1 and rcm[0]["src"] == "PCA" and "case_to_case" in rcm[0]["reasons"]
    # no LOCAL / link-local ever became a node
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    assert "LOCAL" not in page and "fe80" not in page
    assert '"cat": "rdp"' in page


def test_routine_internal_rdp_is_csv_only_like_routine_ssh(tmp_path):
    """RDP is the normal administration transport on a Windows estate, so flagging
    every inbound session is the same mistake as flagging every successful SSH: on a
    real case it put 83% of all edges under `suspicious=yes`, 500 of them a private
    host RDP-ing to another private host and nothing else. Those stay in the CSV and
    out of the graph -- while a FAILED attempt from the very same source is kept, so
    an attack-shaped session never depends on this gate."""
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_evtx(b, "evtx_rdpSessions.csv", [
        # routine: unacquired private peer, successful, nothing else about it
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "21", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "192.168.50.50", "PayloadData1": "Session ID: 1"},
    ])
    _write_security(b, [
        # same peer, but failing -> still flagged, on its own reason
        {"TimeCreated": "2026-06-18 10:02:00", "EventId": "4625", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "- (192.168.50.50)",
         "PayloadData1": "Target: CORP\\admin", "PayloadData2": "LogonType 10"},
    ])
    lateral.build([b], tmp_path)
    out = list(_csv.DictReader((tmp_path / "lateral_movement.csv").open(encoding="utf-8")))
    by_eid = {r["event_id"]: r for r in out}

    # CHANGED with the yes-or-empty fix, deliberately: this pinned the literal
    # "no" that ARCHITECTURE.md §5 forbids. An analyst filtering `suspicious` is
    # not blank -- the estate-wide habit -- got every unflagged edge back, on the
    # one file where curation is the whole point.
    assert by_eid["LSM-21"]["suspicious"] == ""        # recorded, not flagged
    assert by_eid["LSM-21"]["reasons"] == ""
    assert by_eid["4625"]["suspicious"] == "yes"       # the failure still stands out
    assert "failed_logon" in by_eid["4625"]["reasons"]


def test_chainsaw_informational_verdicts_are_not_findings(tmp_path):
    """Chainsaw's RDP/logon rulesets label every ORDINARY session event as well as
    real detections. "RDS - Session logoff succeeded" is a description of something
    that happened, not a finding; treating it as one made an edge `suspicious` for
    the crime of being an RDP session -- which `event_id`/`logon_type` already say."""
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_security(b, [
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "4624", "Computer": "PCB.corp",
         "UserName": "CORP\\bob", "RemoteHost": "- (198.51.100.7)",
         "PayloadData1": "Target: CORP\\bob", "PayloadData2": "LogonType 10"},
    ])
    base = b.path / "CSVs" / "EventLogs"
    with (base / "chainsaw_rdp_events.csv").open("w", encoding="utf-8", newline="") as fh:
        w = _csv.DictWriter(fh, fieldnames=["detections", "Computer", "User", "Event ID"])
        w.writeheader()
        w.writerow({"detections": "RDS - Session logoff succeeded",
                    "Computer": "PCB.corp", "User": "CORP\\bob", "Event ID": "4624"})

    lateral.build([a, b], tmp_path)
    row = [r for r in _csv.DictReader((tmp_path / "lateral_movement.csv").open(encoding="utf-8"))
           if r["event_id"] == "4624"][0]
    assert row["chainsaw"] == ""                  # the label is dropped entirely
    assert "chainsaw" not in row["reasons"]


def test_brute_force_campaign_collapses_and_the_page_says_so(tmp_path, monkeypatch):
    """An internet-wide password spray is ONE fact, not one finding per source.
    Keeping every failed-only source unconditionally turned a real case into a
    443-node graph of which 368 were public IPs that had only ever failed -- the
    volume cap ended up deciding 4 nodes and the real lateral movement was buried.
    Past _MAX_BRUTE only the loudest are drawn, the rest are COUNTED in the header
    (never silently dropped), and a source that also succeeded is always kept."""
    monkeypatch.setattr(lateral, "_MAX_BRUTE", 2)
    monkeypatch.setattr(lateral, "_MAX_EXTERNAL", 0)   # nothing survives on volume alone
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    rows = []
    for i in range(6):                       # 6 spray sources, decreasing volume
        for _ in range(6 - i):
            rows.append(
                {"TimeCreated": f"2026-06-18 10:0{i}:00", "EventId": "4625",
                 "Computer": "PCB.corp", "UserName": "CORP\\admin",
                 "RemoteHost": f"- (203.0.113.{10 + i})",
                 "PayloadData1": "Target: CORP\\admin", "PayloadData2": "LogonType 10"})
    # a 7th source that ALSO got in: an anonymous logon -- must never be collapsed
    rows.append({"TimeCreated": "2026-06-18 11:00:00", "EventId": "4624",
                 "Computer": "PCB.corp", "UserName": "ANONYMOUS LOGON",
                 "RemoteHost": "- (203.0.113.99)",
                 "PayloadData1": "Target: ANONYMOUS LOGON", "PayloadData2": "LogonType 3"})
    _write_security(b, rows)
    # chainsaw calls the quiet tail "Account Brute Force" -- a REAL verdict, but it
    # describes the same campaign. Collapsing keys on the OUTCOME (this source never
    # authenticated) rather than the rule name, so the verdict does not rescue it.
    with (b.path / "CSVs" / "EventLogs" / "chainsaw_login_attacks.csv").open(
            "w", encoding="utf-8", newline="") as fh:
        w = _csv.DictWriter(fh, fieldnames=["detections", "Computer", "User", "Event ID"])
        w.writeheader()
        w.writerow({"detections": "Account Brute Force", "Computer": "PCB.corp",
                    "User": "CORP\\admin", "Event ID": "4625"})

    summary = lateral.build([b], tmp_path)
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    ids = {n["id"] for n in json.loads(re.search(r"const NODES=(\[.*?\]), LINKS=", page, re.DOTALL).group(1))}

    assert "203.0.113.10" in ids and "203.0.113.11" in ids   # the two loudest kept
    assert "203.0.113.14" not in ids                          # the quiet tail collapsed
    assert "203.0.113.99" in ids            # anonymous_logon is never collapsed
    assert summary["graph_brute"] == 4 and summary["graph_hidden"] == 4
    # and the page SAYS what it left out -- a silently trimmed graph is how three
    # internet-facing RDP sources once went unnoticed
    assert "4 peer(s) hidden (4 brute-force sources)" in page
    assert "full list in lateral_movement.csv" in page
    # the CSV still carries every one of them
    out = list(_csv.DictReader((tmp_path / "lateral_movement.csv").open(encoding="utf-8")))
    assert len({r["src"] for r in out}) == 7


def test_public_ip_rdp_never_culled_by_volume_cap(tmp_path, monkeypatch):
    """A successful inbound RDP from a PUBLIC internet IP must survive the external
    volume cap even at count 1 (internet-facing RDP straight onto an internal host
    is a top finding), while a low-volume INTERNAL RFC1918 RDP source may be culled.
    RFC 5737 doc ranges are classified non-global by Python's ipaddress, so a plain
    routable placeholder (1.2.3.4) is needed to exercise the public path."""
    monkeypatch.setattr(lateral, "_MAX_EXTERNAL", 0)   # nothing survives on volume alone
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_evtx(b, "evtx_rdpSessions.csv", [
        # public internet IP, count 1, rdp-only -> must survive the cap
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "25", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "1.2.3.4", "PayloadData1": "Session ID: 1"},
        # internal RFC1918 IP, count 1, rdp-only -> culled when nothing is kept on volume
        {"TimeCreated": "2026-06-18 10:05:00", "EventId": "21", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "192.168.50.50", "PayloadData1": "Session ID: 2"},
    ])
    lateral.build([b], tmp_path)
    out = list(_csv.DictReader((tmp_path / "lateral_movement.csv").open(encoding="utf-8")))
    # the CSV keeps everything -- both inbound RDP edges are recorded...
    assert {r["src"] for r in out} == {"1.2.3.4", "192.168.50.50"}
    # ...but only the internet-facing one is FLAGGED: routine internal RDP is
    # context, and marking it suspicious is what drowned the column at 83%
    flagged = {r["src"]: r["reasons"] for r in out if r["suspicious"] == "yes"}
    assert flagged == {"1.2.3.4": "rdp_public"}
    # ...but the curated HTML keeps only the public source when volume can't save it
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    nodes = json.loads(re.search(r"const NODES=(\[.*?\]), LINKS=", page, re.DOTALL).group(1))
    ids = {n["id"] for n in nodes}
    assert "1.2.3.4" in ids                # public RDP source survives the cap
    assert "192.168.50.50" not in ids      # internal low-volume RDP source culled


def test_evtx_drop_joins_graph_as_its_real_host(tmp_path):
    """A loose EVTX drop is detected as `evtx-<label>` (a folder name, not a host).
    Phase 5 renames it to the host its events name (`Computer`), so its logons land
    on that host's node and correlate with the rest of the case instead of hanging
    off a folder-shaped stranger."""
    pca = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    drop = tmp_path / "evtx-drop"
    (drop / "CSVs" / "EventLogs").mkdir(parents=True)
    ev = Machine("evtx-drop", "windows", "evtx", "evtx", drop, "src",
                 [Volume("C", drop, True)])
    _write_security(ev, [
        # inbound RDP onto the host the dropped logs came from, sourced at PCA
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "4624", "Computer": "PCB.corp",
         "UserName": "CORP\\attacker", "RemoteHost": "- (10.0.0.10)",
         "PayloadData1": "Target: CORP\\attacker", "PayloadData2": "LogonType 10"},
    ])

    lateral.build([pca, ev], tmp_path)
    assert ev.name == "PCB"                 # renamed from the folder to the real host
    out = list(_csv.DictReader((tmp_path / "lateral_movement.csv").open(encoding="utf-8")))
    e = [r for r in out if r["event_id"] == "4624"][0]
    assert (e["src"], e["dst"]) == ("PCA", "PCB")      # NOT "evtx-drop"
    assert e["src_in_case"] == "yes" and "case_to_case" in e["reasons"]
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    assert "evtx-drop" not in page


def test_public_ip_own_role_and_graph_filter(tmp_path):
    """A globally-routable source IP is its own `public` node role (coloured apart so
    internet sources jump out) and the HTML carries a public-IP-only filter; a private
    RFC1918 source stays `external`. (1.2.3.4 is used because RFC 5737 doc ranges are
    classified non-global by Python's ipaddress.)"""
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_evtx(b, "evtx_rdpSessions.csv", [
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "25", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "1.2.3.4", "PayloadData1": "Session ID: 1"},
    ])
    # the private peer needs a reason of its own to be graphed at all now that a
    # routine internal RDP is CSV-only -- a failed logon is the everyday one
    _write_security(b, [
        {"TimeCreated": "2026-06-18 10:05:00", "EventId": "4625", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "- (192.168.50.50)",
         "PayloadData1": "Target: CORP\\admin", "PayloadData2": "LogonType 10"},
    ])
    lateral.build([b], tmp_path)
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    nodes = json.loads(re.search(r"const NODES=(\[.*?\]), LINKS=", page, re.DOTALL).group(1))
    role = {n["id"]: n["role"] for n in nodes}
    assert role["1.2.3.4"] == "public"           # internet-routable -> its own role
    assert role["192.168.50.50"] == "external"   # RFC1918 -> stays internal/external
    # the public-IP-only filter control + wiring is present in the page
    assert 'id="pub"' in page and "public IP only" in page
    assert "pubOnly" in page and "public:'#ff2e88'" in page


def test_timestamps_declared_utc_in_csv_and_html(tmp_path):
    """Both outputs state their timezone. The CSV columns carry `_utc` (same
    contract as every other engine CSV), and the HTML both says so and ANCHORS the
    values: "2026-06-18 10:00:00" has no zone, so a bare Date.parse would read it
    in the viewer's local zone -- the same report would then show different hours
    on a UTC+2 analyst's laptop than the case clock. Hence the 'Z' anchor plus
    getUTC* formatting, which this test pins."""
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_evtx(b, "evtx_rdpSessions.csv", [
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "21", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "1.2.3.4", "PayloadData1": "Session ID: 1"},
    ])
    lateral.build([b], tmp_path)

    header = (tmp_path / "lateral_movement.csv").read_text(
        encoding="utf-8").splitlines()[0].split(",")
    assert "first_seen_utc" in header and "last_seen_utc" in header
    assert "first_seen" not in header and "last_seen" not in header   # no unlabelled leftovers

    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    assert "all times UTC" in page                    # stated in the header bar
    assert "Timeline (chronological, UTC)" in page    # and on the sidebar
    assert "t+='Z'" in page                           # parse anchored to UTC...
    assert "getUTCFullYear" in page and "getUTCHours" in page   # ...and formatted in UTC
    assert "d.getHours()" not in page                 # never the viewer's local zone


def test_locked_output_warns_instead_of_killing_the_run(tmp_path, monkeypatch):
    """Phase 5 is the LAST thing `aeng run` does. An analyst who left
    lateral_movement.csv open in Excel used to lose the entire run to an unhandled
    PermissionError after every parser had already finished. It must warn and carry
    on -- and still produce the output that IS writable."""
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_evtx(b, "evtx_rdpSessions.csv", [
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "21", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "1.2.3.4", "PayloadData1": "Session ID: 1"},
    ])
    real_open = Path.open

    def locked(self, *a, **kw):
        if self.name == "lateral_movement.csv":
            raise PermissionError(13, "Permission denied")
        return real_open(self, *a, **kw)

    monkeypatch.setattr(Path, "open", locked)
    summary = lateral.build([b], tmp_path)          # must NOT raise

    assert summary["edges"] >= 1                     # the analysis still ran
    assert not (tmp_path / "lateral_movement.csv").exists()
    assert (tmp_path / "lateral_movement.html").is_file()   # the graph still lands


def test_graph_has_reason_filter_export_and_node_detail(tmp_path):
    """Three things the web report had and the graph did not. Reasons are what make
    an edge worth looking at, so they must be pickable (positive OR selection, unlike
    the category chips); the current view must be exportable, since whatever you
    narrowed down to is the next thing that goes in a ticket or a blocklist; and a
    selected node needs a panel that STAYS, because the hover tooltip vanishes the
    moment you move the mouse."""
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_evtx(b, "evtx_rdpSessions.csv", [
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "21", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "1.2.3.4", "PayloadData1": "Session ID: 1"},
    ])
    lateral.build([b], tmp_path)
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    links = json.loads(re.search(r"LINKS=(\[.*?\]), CHAINS=", page, re.DOTALL).group(1))

    # every link carries the canonical reason tokens for filtering, separately from
    # the display list (which mixes in chainsaw RULE NAMES -> one chip per rule)
    assert links[0]["rs"] == ["rdp_public"]
    assert 'id="reasons"' in page and "none picked = no filter" in page
    assert "!pickedR.size||(l.rs||[]).some(r=>pickedR.has(r))" in page
    # export of the CURRENT view, not the whole case
    assert 'id="cpy"' in page and 'id="csv"' in page
    assert "lateral_movement_filtered.csv" in page
    assert "first_seen_utc,last_seen_utc,reasons" in page
    # node detail panel, and its arrows are entities OUTSIDE esc() (a peer name is
    # attacker-controlled, so escaping it must not turn "&rarr;" into literal text)
    assert 'id="detail"' in page and "function showDetail" in page
    assert "k[0]==='>'?'&rarr;':'&larr;'" in page


def test_timeline_sidebar_scopes_to_the_selected_node(tmp_path):
    """Clicking a host narrows the timeline to that host's events. On a real case
    the full sidebar is hundreds of rows; once you pick a host the question is
    always "what happened on THIS host". The scope survives clicking one of its
    rows (that focuses an edge, it does not undo what you were reading) and is
    dropped by a chain click, which spans three hosts."""
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_evtx(b, "evtx_rdpSessions.csv", [
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "21", "Computer": "PCB.corp",
         "UserName": "CORP\\admin", "RemoteHost": "1.2.3.4", "PayloadData1": "Session ID: 1"},
    ])
    lateral.build([b], tmp_path)
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")

    # the sidebar filters on the selected node and says whose events it is showing
    assert "selNode?VLINKS.filter(l=>l.source===selNode||l.target===selNode):VLINKS" in page
    assert "`Timeline — ${selNode}" in page
    # selecting/clearing a node must rebuild it: that path never calls applyFilters
    assert "clearSel();buildTimeline();render();" in page
    # a chain spans 3 hosts -> it drops the single-host scope
    assert "buildTimeline();          // a chain spans 3 hosts" in page


def test_rdp_inbound_lsm_feeds_pivot_chain(tmp_path):
    """An LSM reconnect landing on B, then B reaching out (4648) by the same
    account within the window, forms a pivot chain -- LSM counts as inbound."""
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_evtx(b, "evtx_rdpSessions.csv", [
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "25", "Computer": "PCB.corp",
         "UserName": "CORP\\attacker", "RemoteHost": "10.0.0.10", "PayloadData1": "Session ID: 1"},
    ])
    _write_security(b, [
        {"TimeCreated": "2026-06-18 10:30:00", "EventId": "4648", "Computer": "PCB.corp",
         "UserName": "CORP\\attacker", "RemoteHost": "-:-",
         "PayloadData1": "Target: CORP\\attacker", "PayloadData2": "TargetServerName: SRV9"}])
    assert lateral.build([a, b], tmp_path)["chains"] == 1


def test_cross_os_pivot_windows_to_linux(tmp_path):
    """An account lands on a Windows host by RDP, then that host SSHes out to a
    Linux box (known_hosts) -- the unified graph is the whole point of not
    splitting Windows/Linux into separate pages."""
    win = _win_machine(tmp_path / "W", "PCW", ["10.0.0.10"])
    lnx = _lin_machine(tmp_path / "L", "lnx1", ["10.0.0.30"])
    # inbound RDP onto the Windows host, then a login on the Linux box FROM it
    _write_security(win, [
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "4624", "Computer": "PCW.corp",
         "UserName": "CORP\\eve", "RemoteHost": "- (203.0.113.9)",
         "PayloadData1": "Target: CORP\\eve", "PayloadData2": "LogonType 10"},
    ])
    _write_rows(lnx, "EventLogs", "wtmp.csv", ["time_utc", "user", "type", "line", "host"],
                [["2026-06-18 10:20:00", "eve", "USER_PROCESS", "pts/0", "10.0.0.10"]])  # <- PCW
    lateral.build([win, lnx], tmp_path)
    out = list(_csv.DictReader((tmp_path / "lateral_movement.csv").open(encoding="utf-8")))
    ssh_in = [r for r in out if r["event_id"] == "wtmp"][0]
    assert ssh_in["src"] == "PCW" and ssh_in["dst"] == "lnx1"     # PCW resolved by IP
    assert "case_to_case" in ssh_in["reasons"]
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    nodes = json.loads(re.search(r"const NODES=(\[.*?\]), LINKS=", page, re.DOTALL).group(1))
    role = {n["id"]: n["role"] for n in nodes}
    assert role["PCW"] == "case" and role["lnx1"] == "linux"


def _write_chainsaw(machine, fname, cols, rows):
    p = machine.path / "CSVs" / "EventLogs" / fname
    with p.open("w", encoding="utf-8-sig", newline="") as fh:
        w = _csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def test_chainsaw_verdict_enriches_edge_generic_dropped(tmp_path):
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_security(b, [
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "4625", "Computer": "PCB.corp",
         "UserName": "CORP\\attacker", "RemoteHost": "- (10.0.0.10)",
         "PayloadData1": "Target: CORP\\attacker", "PayloadData2": "LogonType 3"},
    ])
    # chainsaw's curated verdict for that failed logon, plus a generic Network Logon
    _write_chainsaw(b, "chainsaw_login_attacks.csv", ["detections", "Event ID", "User"],
                    [{"detections": "Account Brute Force", "Event ID": "4625", "User": "attacker"}])
    _write_chainsaw(b, "chainsaw_lateral_movement.csv",
                    ["detections", "Event ID", "Computer", "User", "IP Address"],
                    [{"detections": "Network Logon", "Event ID": "4625", "Computer": "PCB.corp",
                      "User": "attacker", "IP Address": "10.0.0.10"}])
    lateral.build([a, b], tmp_path)
    out = list(_csv.DictReader((tmp_path / "lateral_movement.csv").open(encoding="utf-8")))
    row = [r for r in out if r["event_id"] == "4625"][0]
    assert row["chainsaw"] == "Account Brute Force"       # matched, domain-stripped user
    assert "Network Logon" not in row["chainsaw"]         # generic dropped
    assert "chainsaw" in row["reasons"]
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    assert "Account Brute Force" in page                  # verdict shown, not "chainsaw" token


def test_4769_service_ticket_maps_to_target_host(tmp_path):
    dc = _win_machine(tmp_path / "DC", "DC01", ["10.0.0.1"])
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_security(dc, [
        # PCA requested a service ticket for PCB$ -> real target is PCB, not the DC
        {"TimeCreated": "2026-06-18 11:00:00", "EventId": "4769", "Computer": "DC01.corp",
         "UserName": "", "RemoteHost": "::ffff:10.0.0.10:5000",
         "PayloadData1": "Target: CORP\\jdoe", "PayloadData2": "ServiceName: PCB$"},
        # a krbtgt ticket has no host SPN -> stays source -> DC (informational)
        {"TimeCreated": "2026-06-18 11:01:00", "EventId": "4769", "Computer": "DC01.corp",
         "UserName": "", "RemoteHost": "::ffff:10.0.0.10:5001",
         "PayloadData1": "Target: CORP\\jdoe", "PayloadData2": "ServiceName: krbtgt"},
    ])
    lateral.build([dc, a, b], tmp_path)
    out = list(_csv.DictReader((tmp_path / "lateral_movement.csv").open(encoding="utf-8")))
    svc = [r for r in out if r["event_id"] == "4769" and r["dst"] == "PCB"]
    assert len(svc) == 1 and svc[0]["src"] == "PCA" and svc[0]["user"] == "CORP\\jdoe"
    assert "kerberos_service" in svc[0]["reasons"] and "case_to_case" in svc[0]["reasons"]
    dc_edge = [r for r in out if r["event_id"] == "4769" and r["dst"] == "DC01"]
    assert len(dc_edge) == 1 and dc_edge[0]["src"] == "PCA"   # krbtgt -> DC, not a host


def _write_rows(machine, subdir, name, header, rows):
    d = machine.path / "CSVs" / subdir
    d.mkdir(parents=True, exist_ok=True)
    with (d / name).open("w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def _write_rdpout(machine, rows):
    d = machine.path / "CSVs" / "EventLogs"
    d.mkdir(parents=True, exist_ok=True)
    with (d / "evtx_rdpOut.csv").open("w", encoding="utf-8", newline="") as fh:
        w = _csv.DictWriter(fh, fieldnames=_HDR)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def test_source_side_rdp_mru_typed_unc_and_rdpout(tmp_path):
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_rdpout(a, [
        {"TimeCreated": "2026-06-18 09:00:00", "EventId": "1024", "Computer": "PCA.corp",
         "UserId": "S-1-5-21-1111111111-2222222222-3333333333-1001",  # resolves via ProfileList
         "PayloadData1": "Dest: 10.0.0.20"},                 # -> PCB (case host)
        {"TimeCreated": "2026-06-18 09:05:00", "EventId": "1102", "Computer": "PCA.corp",
         "UserId": "S-1-5-21-9999999999-8888888888-7777777777-1500",  # unknown SID -> no user
         "PayloadData1": "Address: 203.0.113.50"},           # -> external
        {"TimeCreated": "2026-06-18 09:06:00", "EventId": "1024", "Computer": "PCA.corp",
         "PayloadData1": "Dest: 3"},                          # junk (<3 chars) -> dropped
    ])
    _write_rows(a, "Registry", "reg_profList.csv",
                ["ValueData", "ValueData2", "ValueData3"],
                [["KeyName: S-1-5-21-1111111111-2222222222-3333333333-1001",
                  "Timestamp: 2026-01-01 00:00:00", "ProfileImagePath: C:\\Users\\jdoe"],
                 ["KeyName: S-1-5-18", "",                    # service SID -> filtered out
                  "ProfileImagePath: %systemroot%\\system32\\config\\systemprofile"]])
    _write_rows(a, "Registry", "rdp_outbound.csv",
                ["user", "target", "mru", "username_hint", "cert_accepted", "key_last_write_utc"],
                [["jdoe", "SRVDB", "0", "CORP\\admin", "yes", "2026-06-18 08:00:00"],
                 ["jdoe", "PCA", "1", "CORP\\jdoe", "", ""]])       # self -> dropped
    _write_rows(a, "Registry", "explorer_input.csv",
                ["user", "kind", "order", "value", "key_last_write_utc"],
                [["jdoe", "typed_path", "0", "\\\\PCB\\share", "2026-06-18 07:00:00"],
                 ["jdoe", "typed_path", "1", "C:\\Users\\x", ""],       # not UNC -> dropped
                 ["jdoe", "search", "0", "password", ""]])              # not a typed_path

    lateral.build([a, b], tmp_path)
    out = list(_csv.DictReader((tmp_path / "lateral_movement.csv").open(encoding="utf-8")))

    ro = {(r["dst"], r["event_id"]): r for r in out if r["event_id"] in ("1024", "1102")}
    assert ro[("PCB", "1024")]["src"] == "PCA"
    assert ro[("PCB", "1024")]["first_seen_utc"] == "2026-06-18 09:00:00"     # real per-conn time
    assert "case_to_case" in ro[("PCB", "1024")]["reasons"]
    assert ro[("PCB", "1024")]["user"] == "jdoe"              # UserId SID -> ProfileList name
    assert ("203.0.113.50", "1102") in ro                                 # external kept
    assert ro[("203.0.113.50", "1102")]["user"] == ""         # unknown SID stays account-less
    assert all(k[0] != "3" for k in ro)                                   # "Dest: 3" dropped

    mru = [r for r in out if r["event_id"] == "TSC-MRU"]
    assert len(mru) == 1                                                  # self entry dropped
    assert mru[0]["dst"] == "srvdb" and mru[0]["user"] == "CORP\\admin"
    assert "rdp_outbound" in mru[0]["reasons"] and "untrusted_cert" in mru[0]["reasons"]

    tp = [r for r in out if r["event_id"] == "TypedPath"]
    assert len(tp) == 1 and tp[0]["dst"] == "PCB" and "typed_unc" in tp[0]["reasons"]

    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    assert "rdp_mru" in page and "typed_unc" in page                      # graph legend chips


def test_parse_ts_formats():
    assert lateral._parse_ts("2026-03-20 10:48:25.5110661") is not None
    assert lateral._parse_ts("2022-07-04 11:09:50") is not None
    assert lateral._parse_ts("2026-03-20T10:48:25") is not None
    assert lateral._parse_ts("") is None and lateral._parse_ts("garbage") is None
    # ordering survives the parse (fraction dropped, second resolution)
    assert lateral._parse_ts("2026-03-20 10:00:00") < lateral._parse_ts("2026-03-20 10:00:01")


def test_pivot_chain_detected_and_marked(tmp_path):
    """X ->(u) B (4624 rdp) then B ->(u) Y (4648) within the window = pivot chain:
    both edges get reason `chain`, the HTML lists the path, summary counts it."""
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_security(b, [
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "4624", "Computer": "PCB.corp",
         "UserName": "CORP\\attacker", "RemoteHost": "- (10.0.0.10)",
         "PayloadData1": "Target: CORP\\attacker", "PayloadData2": "LogonType 10"},
        # 40 min later the SAME account reaches out from PCB with explicit creds
        {"TimeCreated": "2026-06-18 10:40:00", "EventId": "4648", "Computer": "PCB.corp",
         "UserName": "CORP\\attacker", "RemoteHost": "-:-",
         "PayloadData1": "Target: CORP\\attacker", "PayloadData2": "TargetServerName: SRV9"},
    ])
    summary = lateral.build([a, b], tmp_path)
    assert summary["chains"] == 1
    out = list(_csv.DictReader((tmp_path / "lateral_movement.csv").open(encoding="utf-8")))
    inbound = [r for r in out if r["event_id"] == "4624"][0]
    outbound = [r for r in out if r["event_id"] == "4648"][0]
    assert "chain" in inbound["reasons"] and "chain" in outbound["reasons"]
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    assert '"path": ["PCA", "PCB", "srv9"]' in page       # CHAINS island
    assert "Attack paths" in page and "pivot chain" in page
    # direction arrows + curved edges shipped with the same template
    assert "marker-end" in page and "egeom(" in page


def test_pivot_chain_respects_user_window_and_machine_accounts(tmp_path):
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_security(b, [
        # inbound by user1
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "4624", "Computer": "PCB.corp",
         "UserName": "CORP\\user1", "RemoteHost": "- (10.0.0.10)",
         "PayloadData1": "Target: CORP\\user1", "PayloadData2": "LogonType 10"},
        # outbound by a DIFFERENT user -> no chain
        {"TimeCreated": "2026-06-18 10:10:00", "EventId": "4648", "Computer": "PCB.corp",
         "UserName": "CORP\\user2", "RemoteHost": "-:-",
         "PayloadData1": "Target: CORP\\user2", "PayloadData2": "TargetServerName: SRV1"},
        # outbound by user1 but 3 DAYS later -> outside the window, no chain
        {"TimeCreated": "2026-06-21 10:00:00", "EventId": "4648", "Computer": "PCB.corp",
         "UserName": "CORP\\user1", "RemoteHost": "-:-",
         "PayloadData1": "Target: CORP\\user1", "PayloadData2": "TargetServerName: SRV2"},
        # machine-account round trip -> excluded (mutual auth chains everything)
        {"TimeCreated": "2026-06-18 10:01:00", "EventId": "4624", "Computer": "PCB.corp",
         "UserName": "CORP\\PCA$", "RemoteHost": "- (10.0.0.10)",
         "PayloadData1": "Target: CORP\\PCA$", "PayloadData2": "LogonType 3"},
        {"TimeCreated": "2026-06-18 10:02:00", "EventId": "4648", "Computer": "PCB.corp",
         "UserName": "CORP\\PCA$", "RemoteHost": "-:-",
         "PayloadData1": "Target: CORP\\PCA$", "PayloadData2": "TargetServerName: SRV3"},
    ])
    summary = lateral.build([a, b], tmp_path)
    assert summary["chains"] == 0
    out = (tmp_path / "lateral_movement.csv").read_text(encoding="utf-8")
    assert "chain" not in out.replace("chainsaw", "")     # no chain reason anywhere


def test_pivot_chain_no_boomerang(tmp_path):
    """X -> B -> X (back to the source) is the same session's artifacts, not a chain."""
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    b = _win_machine(tmp_path / "B", "PCB", ["10.0.0.20"])
    _write_security(b, [
        {"TimeCreated": "2026-06-18 10:00:00", "EventId": "4624", "Computer": "PCB.corp",
         "UserName": "CORP\\u", "RemoteHost": "- (10.0.0.10)",
         "PayloadData1": "Target: CORP\\u", "PayloadData2": "LogonType 10"},
        {"TimeCreated": "2026-06-18 10:05:00", "EventId": "4648", "Computer": "PCB.corp",
         "UserName": "CORP\\u", "RemoteHost": "-:-",
         "PayloadData1": "Target: CORP\\u", "PayloadData2": "TargetServerName: PCA"},
    ])
    assert lateral.build([a, b], tmp_path)["chains"] == 0


def test_multi_dc_both_marked_as_dc(tmp_path):
    dc1 = _win_machine(tmp_path / "D1", "DC01", ["10.0.0.1"])
    dc2 = _win_machine(tmp_path / "D2", "DC02", ["10.0.0.2"])
    a = _win_machine(tmp_path / "A", "PCA", ["10.0.0.10"])
    for dc in (dc1, dc2):
        _write_security(dc, [
            {"TimeCreated": "2026-06-18 11:00:00", "EventId": "4768", "Computer": f"{dc.name}.corp",
             "UserName": "", "RemoteHost": "::ffff:10.0.0.10:5000",
             "PayloadData1": "Target: CORP\\svc", "PayloadData2": "ServiceName: krbtgt"}])
    lateral.build([dc1, dc2, a], tmp_path)
    page = (tmp_path / "lateral_movement.html").read_text(encoding="utf-8")
    # both DCs (not just the busiest) get role "dc"
    assert '{"id": "DC01", "role": "dc"}' in page
    assert '{"id": "DC02", "role": "dc"}' in page


def test_detection_settles_an_evtx_drop_name_before_the_graph_sees_it(tmp_path):
    """Detection can only name a loose EVTX drop after its folder. `lateral.build`
    has always fixed that itself, first thing, so the graph carried the host either
    way -- this is not a bug being closed. What phase 2 doing it too buys is a
    different guarantee: the machines are correct when they LEAVE detection, so
    nothing downstream repairs its own input, and a caller that stops before the
    graph still sees the real host.

    (An earlier version of this test spied on `lateral.build` by replacing it, which
    meant it read the names BEFORE the rename that build performs, and reported a
    defect that was an artefact of the instrument.)"""
    from artifact_engine.config import load_config
    from artifact_engine.core import pipeline
    from artifact_engine.registry import load_profiles

    drop = tmp_path / "evtx-caso"
    logs = drop / "CSVs" / "EventLogs"
    logs.mkdir(parents=True)
    (drop / "Security.evtx").write_bytes(b"ElfFile" + bytes(1))   # makes the folder a machine
    with (logs / "evtx_security.csv").open("w", encoding="utf-8", newline="") as fh:
        w = _csv.DictWriter(fh, fieldnames=["TimeCreated", "EventId", "Computer"])
        w.writeheader()
        for _ in range(3):
            w.writerow({"TimeCreated": "2026-06-18 10:00:00", "EventId": "4624",
                        "Computer": "PCB.corp"})          # FQDN -> short form wins

    cfg = load_config(None)
    machines = pipeline.detect(tmp_path, cfg, load_profiles(cfg.all_profile_dirs),
                               stage_drops=False)

    assert [m.name for m in machines] == ["PCB"], "detection handed on the folder name"
    assert [m.display for m in machines] == ["PCB"], "the console label did not follow"


def test_both_commands_describe_a_graph_in_the_same_words():
    """The summary line was built twice from the same f-string with a different
    prefix, which is a drift waiting to happen: the numbers a case reports would
    depend on whether the graph came from `aeng run` or `aeng lateral`. One
    formatter now, and it says nothing at all when there is nothing to say."""
    from artifact_engine.core.pipeline import describe_graph

    assert describe_graph({"edges": 0}) == "", "an empty graph should stay quiet"

    lat = {"edges": 7, "hosts": 3, "suspicious": 1, "chains": 2, "graph_hosts": 3}
    plain = describe_graph(lat)
    assert "7 edge(s), 3 host(s), 1 suspicious, 2 pivot chain(s)" in plain
    assert plain.endswith("-> lateral_movement.html")
    assert "hidden" not in plain, "nothing was hidden, so nothing should say so"

    # `chains` and `graph_hosts` are read with .get: an older graph dict lacking
    # them must still produce a line rather than raise mid-run
    assert "0 pivot chain(s)" in describe_graph({"edges": 1, "hosts": 1, "suspicious": 0})

    withheld = describe_graph({**lat, "graph_hidden": 4})
    assert "graph 3 host(s) (4 peer(s) hidden) -> lateral_movement.html" in withheld


def test_a_renamed_chainsaw_ruleset_is_reported_not_absorbed(tmp_path, caplog):
    """The four CSVs the graph reads are named by CHAINSAW, after the rules that
    fired -- the parser runs with `short: chainsaw` and the engine only prefixes
    them. So an upstream rename removes an evidence source without removing
    anything the engine can see: edges arrive unenriched, which is indistinguishable
    from a case where chainsaw found nothing."""
    import logging

    from artifact_engine.core import lateral
    from artifact_engine.core.detector import Machine, Volume

    base = tmp_path / "CSVs" / "EventLogs"
    base.mkdir(parents=True)
    m = Machine("HOST-01", "windows", "kape", "windows_kape", tmp_path, "src",
                [Volume("C", tmp_path, True)])

    # chainsaw ran, but every rule CSV is named something the graph does not read
    (base / "chainsaw_renamed_logon_rule.csv").write_text(
        "detections,Computer,User,Event ID\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="aeng"):
        lateral._load_chainsaw_verdicts([m], {})
    assert any("chainsaw ran but none of the rule CSVs" in r.message
               for r in caplog.records), "the graph lost a source and said nothing"

    # and it stays quiet when chainsaw simply did not run on this machine
    caplog.clear()
    (base / "chainsaw_renamed_logon_rule.csv").unlink()
    with caplog.at_level(logging.WARNING, logger="aeng"):
        lateral._load_chainsaw_verdicts([m], {})
    assert not caplog.records, "no chainsaw output at all is not a warning"
