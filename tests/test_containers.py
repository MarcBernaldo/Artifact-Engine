"""The system inside the system, which no host-level parser can see.

Every other Linux parser here reads the host. A compromised container's processes
are in the host `ps` as bare PIDs, its filesystem is not in the bodyfile in any
readable form, and what it wrote since it started exists only in `docker diff` --
which UAC collects and nothing read. Every value below is invented.
"""
from __future__ import annotations

import csv
import json
import logging
from pathlib import Path

from artifact_engine.core.runner import ParserContext
from artifact_engine.handlers import lin_containers as C
from artifact_engine.handlers import lin_vms as V


def _ctx(evidence: Path, out: Path) -> ParserContext:
    return ParserContext(
        evidence=evidence, out=out, tools=evidence, assets=evidence,
        machine_name="HOST-01", volume="live", log=logging.getLogger("aeng.test"),
    )


def _containers_dir(tmp_path: Path) -> Path:
    d = tmp_path / "evidence" / "live_response" / "containers"
    d.mkdir(parents=True)
    return d


def _inspect(cdir: Path, ident: str, runtime: str = "docker", **over) -> None:
    doc = {
        "Id": ident + "0" * (64 - len(ident)),
        "Created": "2026-03-04T10:11:12.0Z",
        "Name": "/" + over.pop("name", "app"),
        "State": {"Status": over.pop("status", "running")},
        "Config": {"Image": over.pop("image", "nginx:1.25"),
                   "Cmd": over.pop("cmd", ["nginx", "-g", "daemon off;"])},
        "HostConfig": {"Privileged": False, "NetworkMode": "bridge"},
        "Mounts": [],
        "NetworkSettings": {"Ports": {}},
    }
    doc["HostConfig"].update(over.pop("host", {}))
    doc.update(over)
    (cdir / f"{runtime}_inspect_{ident}.txt").write_text(
        json.dumps([doc], indent=1), encoding="utf-8")


def _rows(out: Path, name: str) -> list[dict]:
    path = out / name
    if not path.is_file():
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _run(tmp_path: Path):
    out = tmp_path / "out"
    C.run(_ctx(tmp_path / "evidence", out))
    return out


# --------------------------------------------------------------------------- #
# The inventory
# --------------------------------------------------------------------------- #
def test_the_inventory_is_read_from_the_json_not_from_the_human_table(tmp_path):
    """`container ls` is a table whose columns hold spaces -- an image tag, a
    command, a port list -- and splitting it by column is how a parser silently
    attributes one container's command to another. `inspect` is the same facts in
    a form that cannot be misread."""
    cdir = _containers_dir(tmp_path)
    _inspect(cdir, "a1b2c3d4e5f6", name="web", image="registry.example.local/app:2.1",
             cmd=["/bin/sh", "-c", "exec nginx -g 'daemon off;'"])
    # the table says something else entirely, and is not what is read
    (cdir / "docker_container_ls_--all_--size.txt").write_text(
        "CONTAINER ID   IMAGE   COMMAND   STATUS\nffffffffffff  other  'nope'  Exited\n",
        encoding="utf-8")

    [row] = _rows(_run(tmp_path), "containers.csv")

    assert row["container_id"] == "a1b2c3d4e5f6"
    assert row["name"] == "web"
    assert row["image"] == "registry.example.local/app:2.1"
    assert row["command"] == "/bin/sh -c exec nginx -g 'daemon off;'"
    assert row["status"] == "running"
    assert row["suspicious"] == ""


def test_a_privileged_container_is_flagged(tmp_path):
    """Escape is not an exploit from here; it is a feature."""
    cdir = _containers_dir(tmp_path)
    _inspect(cdir, "aaaa1111", name="builder", host={"Privileged": True})

    [row] = _rows(_run(tmp_path), "containers.csv")

    assert row["suspicious"] == "yes" and "privileged" in row["detail"]


def test_a_container_sharing_the_hosts_namespaces_is_flagged(tmp_path):
    cdir = _containers_dir(tmp_path)
    _inspect(cdir, "bbbb2222", name="agent",
             host={"NetworkMode": "host", "PidMode": "host", "IpcMode": "host"})

    [row] = _rows(_run(tmp_path), "containers.csv")

    for flag in ("host_network", "host_pid", "host_ipc"):
        assert flag in row["detail"]


def test_a_bind_mount_of_the_host_or_its_control_plane_is_flagged(tmp_path):
    """`/var/run/docker.sock` is root on the host by a shorter route than any
    exploit: whoever holds it can start a privileged container."""
    cdir = _containers_dir(tmp_path)
    _inspect(cdir, "cccc3333", name="ci", Mounts=[
        {"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock",
         "RW": True},
        {"Source": "/srv/data", "Destination": "/data", "RW": False},
    ])

    [row] = _rows(_run(tmp_path), "containers.csv")

    assert "bind_/var/run/docker.sock" in row["detail"]
    assert "/srv/data:/data:ro" in row["mounts"], "a read-only mount is still recorded"


def test_a_root_bind_and_a_hot_capability_are_each_their_own_flag(tmp_path):
    cdir = _containers_dir(tmp_path)
    _inspect(cdir, "dddd4444", name="rescue",
             host={"CapAdd": ["CAP_SYS_ADMIN", "NET_BIND_SERVICE"],
                   "SecurityOpt": ["apparmor=unconfined"]},
             Mounts=[{"Source": "/", "Destination": "/host", "RW": True}])

    [row] = _rows(_run(tmp_path), "containers.csv")

    assert "bind_root" in row["detail"]
    assert "cap_sys_admin" in row["detail"]
    assert "net_bind_service" not in row["detail"], "an ordinary capability is noise"
    assert "apparmor=unconfined" in row["detail"]


def test_only_the_published_ports_are_named(tmp_path):
    """An exposed-but-unpublished port is not reachable from anywhere, and listing
    it as if it were makes the column useless for deciding what was exposed."""
    cdir = _containers_dir(tmp_path)
    _inspect(cdir, "eeee5555", NetworkSettings={"Ports": {
        "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
        "9000/tcp": None,
    }})

    [row] = _rows(_run(tmp_path), "containers.csv")

    assert row["ports"] == "0.0.0.0:8080->80/tcp"


def test_a_container_the_collector_could_not_describe_is_still_a_row(tmp_path):
    """The command ran and wrote its error: the id was gone by the time the
    collector reached it, or the daemon refused. A container that was seen and
    could not be described is itself a fact, and dropping the file would leave
    the inventory quietly short."""
    cdir = _containers_dir(tmp_path)
    (cdir / "docker_inspect_f00dcafe.txt").write_text(
        "Error: No such object: f00dcafe\n", encoding="utf-8")

    [row] = _rows(_run(tmp_path), "containers.csv")

    assert row["container_id"] == "f00dcafe" and row["status"] == "unreadable"


def test_a_network_or_volume_inspect_is_not_read_as_a_container(tmp_path):
    """They sit in the same directory under names a loose glob matches, and they
    describe different objects entirely."""
    cdir = _containers_dir(tmp_path)
    _inspect(cdir, "1111aaaa", name="real")
    (cdir / "docker_network_inspect_br0.txt").write_text(
        json.dumps([{"Name": "br0", "Driver": "bridge"}]), encoding="utf-8")
    (cdir / "docker_volume_inspect_data.txt").write_text(
        json.dumps([{"Name": "data", "Mountpoint": "/var/lib/docker/volumes/data"}]),
        encoding="utf-8")

    rows = _rows(_run(tmp_path), "containers.csv")

    assert [r["name"] for r in rows] == ["real"]


def test_podman_is_read_the_same_way_and_keeps_its_runtime(tmp_path):
    cdir = _containers_dir(tmp_path)
    _inspect(cdir, "9999", runtime="podman", name="rootless")

    [row] = _rows(_run(tmp_path), "containers.csv")

    assert row["runtime"] == "podman" and row["name"] == "rootless"


# --------------------------------------------------------------------------- #
# What the container wrote
# --------------------------------------------------------------------------- #
def test_the_filesystem_delta_is_the_closest_thing_to_an_mft(tmp_path):
    """`docker diff` is the only record of what a container wrote since the image
    it started from, and it is handed over for free."""
    cdir = _containers_dir(tmp_path)
    (cdir / "docker_diff_a1b2c3d4e5f6.txt").write_text(
        "C /etc\n"
        "A /tmp/.x\n"
        "A /var/www/html/up.php\n"
        "C /usr/share/nginx/html/index.html\n"
        "A /etc/cron.d/refresh\n"
        "D /var/log/nginx/access.log\n"
        "A /opt/app/cache/page-1\n",
        encoding="utf-8")

    rows = {r["path"]: r for r in _rows(_run(tmp_path), "container_changes.csv")}

    assert rows["/tmp/.x"]["detail"] == "staging_dir"
    assert "server_side_script" in rows["/var/www/html/up.php"]["detail"]
    assert rows["/usr/share/nginx/html/index.html"]["detail"] == "web_root", \
        "an html file in a web root is a web_root write, not a script"
    assert "persistence_path" in rows["/etc/cron.d/refresh"]["detail"]
    assert "deleted_system_path" in rows["/var/log/nginx/access.log"]["detail"]
    assert rows["/opt/app/cache/page-1"]["suspicious"] == "", \
        "an application writing to its own cache is not a finding"


def test_the_change_table_knows_its_three_kinds_and_nothing_else(tmp_path):
    """Anything that is not `A`, `C` or `D` is the command's own error text, and
    it has no business in a table of filesystem changes."""
    cdir = _containers_dir(tmp_path)
    (cdir / "docker_diff_dead.txt").write_text(
        "Error response from daemon: No such container: dead\n"
        "A /tmp/real\n",
        encoding="utf-8")

    rows = _rows(_run(tmp_path), "container_changes.csv")

    assert [r["path"] for r in rows] == ["/tmp/real"]


def test_the_processes_give_the_host_pids_their_context_back(tmp_path):
    """In the host's own `ps` these are PIDs with no container around them."""
    cdir = _containers_dir(tmp_path)
    (cdir / "docker_top_a1b2c3d4e5f6.txt").write_text(
        "UID                 PID                 PPID                C"
        "                   STIME               TTY                 TIME"
        "                CMD\n"
        "root                2411                2390                0"
        "                   10:11               ?                   00:00:00"
        "            nginx: master process nginx -g daemon off;\n",
        encoding="utf-8")

    [row] = _rows(_run(tmp_path), "container_procs.csv")

    assert row["container"] == "a1b2c3d4e5f6"
    assert (row["uid"], row["pid"], row["ppid"]) == ("root", "2411", "2390")
    assert row["command"] == "nginx: master process nginx -g daemon off;", \
        "the command holds spaces and must not be split by column"


# --------------------------------------------------------------------------- #
# LXC, which answers in a different shape
# --------------------------------------------------------------------------- #
def test_an_lxc_container_is_inventoried_and_its_privilege_read_from_its_config(tmp_path):
    """LXD has no JSON equivalent of `inspect` collected here, and it is the
    runtime the exfil work hit as a blind spot on a real engagement."""
    cdir = _containers_dir(tmp_path)
    (cdir / "lxc_list.txt").write_text(
        "NAME  STATE    IPV4              TYPE       SNAPSHOTS\n"
        "web1  RUNNING  10.0.0.5 (eth0)   CONTAINER  0\n"
        "db1   STOPPED                    CONTAINER  2\n",
        encoding="utf-8")
    (cdir / "lxc_config_show_web1.txt").write_text(
        "architecture: x86_64\nconfig:\n  security.privileged: \"true\"\n"
        "  security.nesting: \"false\"\ndevices:\n  hostroot:\n    path: /\n"
        "    source: /\n    type: disk\n",
        encoding="utf-8")

    rows = {r["name"]: r for r in _rows(_run(tmp_path), "containers.csv")}

    assert rows["web1"]["runtime"] == "lxc" and rows["web1"]["status"] == "running"
    assert "privileged" in rows["web1"]["detail"] and "bind_/" in rows["web1"]["detail"]
    assert "nesting" not in rows["web1"]["detail"], "nesting is false here"
    assert rows["db1"]["suspicious"] == "" and rows["db1"]["status"] == "stopped"


def test_an_lxc_listing_with_a_project_column_is_still_read(tmp_path):
    """`lxc list --all-projects` puts PROJECT first, which moves every column."""
    cdir = _containers_dir(tmp_path)
    (cdir / "lxc_list.txt").write_text(
        "PROJECT  NAME  STATE    TYPE\n"
        "default  web1  RUNNING  CONTAINER\n",
        encoding="utf-8")

    [row] = _rows(_run(tmp_path), "containers.csv")

    assert row["name"] == "web1" and row["status"] == "running"


# --------------------------------------------------------------------------- #
# The run as a whole
# --------------------------------------------------------------------------- #
def test_a_host_with_no_containers_writes_nothing(tmp_path):
    (tmp_path / "evidence" / "live_response").mkdir(parents=True)

    out = _run(tmp_path)

    assert not (out / "containers.csv").exists()
    assert not (out / "container_changes.csv").exists()
    assert not (out / "container_procs.csv").exists()


def test_the_flagged_rows_come_first(tmp_path):
    """The table is read top-down and the one that matters is at the top."""
    cdir = _containers_dir(tmp_path)
    _inspect(cdir, "aaaa0001", name="aaa-ordinary")
    _inspect(cdir, "zzzz0002", name="zzz-privileged", host={"Privileged": True})

    rows = _rows(_run(tmp_path), "containers.csv")

    assert [r["name"] for r in rows] == ["zzz-privileged", "aaa-ordinary"]


def test_the_web_roots_are_the_ones_the_webshell_scanner_already_knows(tmp_path):
    """Imported rather than copied, so adding a web root in one place teaches
    both. A second list would have drifted from the first."""
    assert C._WEBROOTS is not None
    from artifact_engine.handlers import lin_webshells

    assert C._WEBROOTS is lin_webshells._WEBROOTS
    assert C._SCRIPT_EXTS is lin_webshells._EXTS


# --------------------------------------------------------------------------- #
# Virtual machines: context, not activity
# --------------------------------------------------------------------------- #
def _vms_dir(tmp_path: Path) -> Path:
    d = tmp_path / "evidence" / "live_response" / "vms"
    d.mkdir(parents=True)
    return d


def _run_vms(tmp_path: Path) -> list[dict]:
    out = tmp_path / "out"
    V.run(_ctx(tmp_path / "evidence", out))
    return _rows(out, "vms.csv")


def test_libvirt_guests_are_listed_with_a_state_that_holds_a_space(tmp_path):
    """"shut off" is two tokens, so the state is everything after the name."""
    vdir = _vms_dir(tmp_path)
    (vdir / "virsh_list_--all.txt").write_text(
        " Id   Name    State\n"
        "---------------------\n"
        " 1    web01   running\n"
        " -    db01    shut off\n",
        encoding="utf-8")

    rows = {r["vm"]: r for r in _run_vms(tmp_path)}

    assert rows["web01"]["state"] == "running" and rows["web01"]["id"] == "1"
    assert rows["db01"]["state"] == "shut off" and rows["db01"]["id"] == ""


def test_a_proxmox_guest_carries_the_disks_an_analyst_would_ask_for_next(tmp_path):
    vdir = _vms_dir(tmp_path)
    (vdir / "qm_list.txt").write_text(
        "      VMID NAME    STATUS   MEM(MB)  BOOTDISK(GB)  PID\n"
        "       100 web01   running  2048     32.00         1234\n",
        encoding="utf-8")
    (vdir / "qm_config_100_--current.txt").write_text(
        "boot: order=scsi0\nscsi0: local-lvm:vm-100-disk-0,size=32G\n"
        "net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0\n"
        "scsi1: nas:vm-100-disk-1,size=500G\n",
        encoding="utf-8")

    [row] = _run_vms(tmp_path)

    assert row["hypervisor"] == "proxmox" and row["id"] == "100"
    assert row["disks"] == "local-lvm:vm-100-disk-0; nas:vm-100-disk-1"
    assert "net0" not in row["disks"], "a NIC is not a disk"


def test_virtualbox_state_comes_from_which_list_the_uuid_is_in(tmp_path):
    vdir = _vms_dir(tmp_path)
    (vdir / "VBoxManage_list_vms.txt").write_text(
        '"win10-lab" {11111111-1111-1111-1111-111111111111}\n'
        '"kali" {22222222-2222-2222-2222-222222222222}\n', encoding="utf-8")
    (vdir / "VBoxManage_list_runningvms.txt").write_text(
        '"kali" {22222222-2222-2222-2222-222222222222}\n', encoding="utf-8")

    rows = {r["vm"]: r for r in _run_vms(tmp_path)}

    assert rows["kali"]["state"] == "running"
    assert rows["win10-lab"]["state"] == "stopped"


def test_an_esxi_guest_is_one_machine_even_though_two_commands_describe_it(tmp_path):
    """`vim-cmd` lists every guest and `esxcli` lists the running ones, so a
    running guest appears twice. Two rows for one machine would overstate the
    estate -- and the row kept is the one that names the config file."""
    vdir = _vms_dir(tmp_path)
    (vdir / "vim-cmd_vmsvc_getallvms.txt").write_text(
        "Vmid   Name     File                              Guest OS       Version\n"
        "1      app srv  [datastore1] app/app.vmx          ubuntu64Guest  vmx-14\n",
        encoding="utf-8")
    (vdir / "vim-cmd_vmsvc_get.summary_1.txt").write_text(
        '(vim.vm.Summary) {\n   runtime = (vim.vm.RuntimeInfo) {\n'
        '      powerState = "poweredOn",\n   },\n}\n', encoding="utf-8")
    (vdir / "esxcli_vm_process_list.txt").write_text(
        "app srv\n   World ID: 2098\n   Display Name: app srv\n"
        "   Config File: /vmfs/volumes/datastore1/app/app.vmx\n", encoding="utf-8")

    rows = _run_vms(tmp_path)

    assert len(rows) == 1, "the same guest was counted twice"
    assert rows[0]["vm"] == "app srv", "a name with a space survives"
    assert rows[0]["disks"] == "/vmfs/volumes/datastore1/app/app.vmx"


def test_nothing_about_a_virtual_machine_is_flagged(tmp_path):
    """An inventory is context. There is no claim to make about a guest from the
    fact that it exists, and a flag that fires on every host stops being read."""
    vdir = _vms_dir(tmp_path)
    (vdir / "virsh_list_--all.txt").write_text(
        " Id   Name    State\n---------\n 1    web01   running\n", encoding="utf-8")

    [row] = _run_vms(tmp_path)

    assert "suspicious" not in row
    assert V.HEADER == ["hypervisor", "vm", "state", "id", "disks", "detail"]


def test_a_host_with_no_hypervisor_writes_nothing(tmp_path):
    (tmp_path / "evidence" / "live_response").mkdir(parents=True)
    out = tmp_path / "out"

    V.run(_ctx(tmp_path / "evidence", out))

    assert not (out / "vms.csv").exists()


# --------------------------------------------------------------------------- #
# What the correctness review found: five ways to read the same files wrong
# --------------------------------------------------------------------------- #
def test_a_named_volume_is_not_a_bind_mount_of_the_host(tmp_path):
    """A named volume's source is a path the runtime owns, under
    /var/lib/docker/volumes -- which is inside the sensitive list. Judging a
    mount by its path alone flags the ordinary way containers persist data, and
    a column that fires on every container separates nothing."""
    cdir = _containers_dir(tmp_path)
    _inspect(cdir, "1234beef", name="db", Mounts=[
        {"Type": "volume", "Name": "appdata",
         "Source": "/var/lib/docker/volumes/appdata/_data",
         "Destination": "/var/lib/postgresql/data", "RW": True},
    ])

    [row] = _rows(_run(tmp_path), "containers.csv")

    assert row["suspicious"] == "" and row["detail"] == ""
    assert "appdata" in row["mounts"], "it is still recorded, just not judged"


def test_a_real_bind_of_the_runtime_directory_is_still_flagged(tmp_path):
    """The other half: handing the daemon's own storage to a container IS the
    finding the list exists for."""
    cdir = _containers_dir(tmp_path)
    _inspect(cdir, "5678beef", name="snoop", Mounts=[
        {"Type": "bind", "Source": "/var/lib/docker", "Destination": "/host-docker",
         "RW": True},
    ])

    [row] = _rows(_run(tmp_path), "containers.csv")

    assert "bind_/var/lib/docker" in row["detail"]


def test_a_mount_with_no_type_is_read_as_a_bind(tmp_path):
    """Older daemons omit `Type` and everything they report is a bind; dropping
    those would lose the flag on exactly the hosts most likely to be old."""
    cdir = _containers_dir(tmp_path)
    _inspect(cdir, "9999beef", Mounts=[{"Source": "/etc", "Destination": "/host-etc",
                                        "RW": False}])

    [row] = _rows(_run(tmp_path), "containers.csv")

    assert "bind_/etc" in row["detail"]


def test_podmans_elapsed_is_not_written_into_the_started_column(tmp_path):
    """docker's `top` reports STIME, a clock time; podman's reports ELAPSED, a
    duration. Same column count, so reading by position puts a duration where a
    reader expects a time and the table looks complete while being wrong."""
    cdir = _containers_dir(tmp_path)
    (cdir / "docker_top_aaaa.txt").write_text(
        "UID    PID   PPID  C  STIME  TTY  TIME      CMD\n"
        "root   2411  2390  0  10:11  ?    00:00:00  nginx -g daemon off;\n",
        encoding="utf-8")
    (cdir / "podman_top_bbbb.txt").write_text(
        "USER   PID  PPID  %CPU  ELAPSED      TTY  TIME      COMMAND\n"
        "nobody 1    0     0.000 5h13m22.9s   ?    00:00:00  /usr/bin/app --serve\n",
        encoding="utf-8")

    rows = {r["container"]: r for r in _rows(_run(tmp_path), "container_procs.csv")}

    assert rows["aaaa"]["started"] == "10:11" and rows["aaaa"]["elapsed"] == ""
    assert rows["bbbb"]["elapsed"] == "5h13m22.9s" and rows["bbbb"]["started"] == ""
    assert rows["bbbb"]["uid"] == "nobody" and rows["bbbb"]["pid"] == "1"
    assert rows["bbbb"]["command"] == "/usr/bin/app --serve"


def test_an_lxc_device_is_judged_on_the_host_path_not_the_container_path(tmp_path):
    """`path:` is the mountpoint INSIDE the container and `source:` is the host
    path handed over. Reading `path:` gets it backwards twice: the host's /etc
    mounted at /mnt/hostetc says nothing, and the ordinary root device every
    container has (`path: /`, a storage pool, no source) says everything."""
    cdir = _containers_dir(tmp_path)
    (cdir / "lxc_list.txt").write_text(
        "NAME      STATE    TYPE\n"
        "exposed   RUNNING  CONTAINER\n"
        "ordinary  RUNNING  CONTAINER\n",
        encoding="utf-8")
    (cdir / "lxc_config_show_exposed.txt").write_text(
        "devices:\n  hostetc:\n    path: /mnt/hostetc\n    source: /etc\n"
        "    type: disk\n", encoding="utf-8")
    (cdir / "lxc_config_show_ordinary.txt").write_text(
        "devices:\n  root:\n    path: /\n    pool: default\n    type: disk\n",
        encoding="utf-8")

    rows = {r["name"]: r for r in _rows(_run(tmp_path), "containers.csv")}

    assert "bind_/etc" in rows["exposed"]["detail"]
    assert rows["ordinary"]["suspicious"] == "", \
        "a container's own root device is not a bind of the host"


def test_an_esxi_datastore_path_with_a_space_keeps_its_guest(tmp_path):
    """An ESXi folder is named after the guest, so a guest whose name holds a
    space has a path that holds one. An anchor that stops at the space dropped
    the whole row -- silently, from the one table whose purpose is naming the
    machines nobody acquired."""
    vdir = _vms_dir(tmp_path)
    (vdir / "vim-cmd_vmsvc_getallvms.txt").write_text(
        "Vmid   Name     File                                 Guest OS\n"
        "1      app srv  [datastore1] app srv/app srv.vmx      ubuntu64Guest\n"
        "2      db01     [datastore1] db01/db01.vmx            ubuntu64Guest\n",
        encoding="utf-8")

    rows = {r["vm"]: r for r in _run_vms(tmp_path)}

    assert set(rows) == {"app srv", "db01"}
    assert rows["app srv"]["disks"] == "[datastore1] app srv/app srv.vmx"


def test_the_created_column_does_not_claim_a_basis_it_cannot_promise(tmp_path):
    """docker writes RFC 3339 with a `Z`, podman with the host's offset. A column
    named `created_utc` would be wrong for one of them on every host that is not
    on UTC, so the name states nothing and the value states its own basis
    (docs/ARCHITECTURE.md §5)."""
    cdir = _containers_dir(tmp_path)
    _inspect(cdir, "cccc", runtime="podman", Created="2026-03-04T10:11:12.0+02:00")

    [row] = _rows(_run(tmp_path), "containers.csv")

    assert "created" in C.CONTAINER_HEADER and "created_utc" not in C.CONTAINER_HEADER
    assert row["created"] == "2026-03-04T10:11:12.0+02:00"
