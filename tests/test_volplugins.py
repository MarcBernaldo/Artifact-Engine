"""v0.7.163: the engine's lsof / sockstat read each file table once, not once per
thread, and decode sockets with one handler per network namespace."""
from __future__ import annotations

from types import SimpleNamespace as NS

import pytest

pytest.importorskip("volatility3")

from volatility3.framework import exceptions
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist, sockstat

from artifact_engine.volplugins import aeng_linux


def _task(pid, tgid, files, netns=1):
    return NS(pid=pid, tgid=tgid, files=files, vol=NS(type_name="kernel!task_struct"),
              nsproxy=NS(net_ns=NS(get_inode=lambda: netns)))


# a leader, a thread sharing its table, a thread with a table of its own
# (unshare(CLONE_FILES)), a second process and its thread
TASKS = [_task(10, 10, 0xA), _task(11, 10, 0xA), _task(12, 10, 0xB),
         _task(20, 20, 0xC, netns=2), _task(21, 20, 0xC, netns=2)]


@pytest.fixture
def walked(monkeypatch):
    monkeypatch.setattr(pslist.PsList, "list_tasks",
                        classmethod(lambda cls, ctx, name, f, include_threads: iter(TASKS)))
    monkeypatch.setattr(linux.LinuxUtilities, "files_descriptors_for_process",
                        classmethod(lambda cls, ctx, table, task, files_only:
                                    iter([(3, task.pid, f"/fd/{task.pid}")])))


def test_a_thread_sharing_its_leaders_file_table_is_not_read_again(walked):
    got = [fd.task.pid for fd in aeng_linux.file_tables(None, "kernel")]
    assert got == [10, 12, 20]
    assert [fd.task.pid for fd in aeng_linux.Lsof.list_fds(None, "kernel")] == got


class _Op(int):
    def is_readable(self):
        return True


class _Ptr:
    def __init__(self, obj):
        self._obj = obj

    def is_readable(self):
        return True

    def dereference(self):
        return self._obj


def _sockets(monkeypatch):
    """Two sockets and a regular file in each table; returns the rows and the
    namespaces a handler was built for."""
    sfop = 0x1000
    vmlinux = NS(name="kernel",
                 object_from_symbol=lambda name: NS(vol=NS(offset=sfop if name == "socket_file_ops"
                                                           else 0x2000)))
    context = NS(modules={"kernel": vmlinux})
    made = []

    class Handlers:
        def __init__(self, ctx, name, task):
            made.append(task.nsproxy.net_ns.get_inode())

        def process_sock(self, sock):
            return (NS(get_protocol=lambda: "TCP"), ("10.0.0.5", 22), {})

    monkeypatch.setattr(sockstat, "SockHandlers", Handlers)
    monkeypatch.setattr(linux.LinuxUtilities, "files_descriptors_for_process",
                        classmethod(lambda cls, ctx, table, task, files_only: iter(
                            [(3, NS(f_op=_Op(sfop), get_dentry=lambda: _Ptr(None)), "socket:[1]"),
                             (4, NS(f_op=_Op(sfop), get_dentry=lambda: _Ptr(None)), "socket:[2]"),
                             (5, NS(f_op=_Op(0x9999)), "/etc/passwd")])))
    sock = NS(get_type=lambda: "STREAM", get_family=lambda: "AF_INET")
    monkeypatch.setattr(linux.LinuxUtilities, "container_of",
                        classmethod(lambda cls, *a: NS(socket=NS(sk=_Ptr(sock)))))
    monkeypatch.setattr(_Ptr, "d_inode", _Ptr(None), raising=False)
    return list(aeng_linux.Sockstat.list_sockets(context, "kernel")), made


def test_sockets_are_decoded_with_one_handler_per_namespace(walked, monkeypatch):
    rows, made = _sockets(monkeypatch)
    # two sockets in each of the three tables read; the regular file is not one
    assert [(r[0].pid, r[2]) for r in rows] == [(10, 3), (10, 4), (12, 3), (12, 4), (20, 3), (20, 4)]
    assert [r[1] for r in rows] == [1, 1, 1, 1, 2, 2]
    assert made == [1, 2]


def test_a_task_whose_namespace_cannot_be_read_loses_its_sockets_not_the_run(walked, monkeypatch):
    """As in Volatility's own, the namespace is read under the socket's guard."""
    def unreadable():
        raise exceptions.InvalidAddressException("layer", 0xDEAD, "unmapped")
    monkeypatch.setattr(TASKS[2], "nsproxy", NS(net_ns=NS(get_inode=unreadable)))
    rows, _ = _sockets(monkeypatch)
    assert [(r[0].pid, r[2]) for r in rows] == [(10, 3), (10, 4), (20, 3), (20, 4)]
