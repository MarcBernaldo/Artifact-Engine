"""The engine's own Volatility plugins. v0.7.163: lsof / sockstat read each file
table once, not once per thread, and decode sockets with one handler per network
namespace. v0.7.164: vadyarascan survives a match Volatility cannot render."""
from __future__ import annotations

from types import SimpleNamespace as NS

import pytest

pytest.importorskip("volatility3")

from volatility3.cli import text_renderer
from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist, sockstat
from volatility3.plugins.windows import vadyarascan

from artifact_engine.volplugins import aeng_linux, aeng_windows


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


# --- aeng_windows: vadyarascan (v0.7.164) ---------------------------------------

class _Process(interfaces.layers.TranslationLayerInterface):
    """A process layer as Volatility's renderer sees it: the match's own range
    is mapped (its first two bytes), the range the renderer asks for -- the end
    passed as a length -- comes back empty."""
    dependencies = minimum_address = maximum_address = None

    def __init__(self):
        pass

    def is_valid(self, offset, length=1):
        return True

    def mapping(self, offset, length, ignore_errors=False):
        if length > 64:
            return iter(())
        return iter([(offset, 2, 0, 2, "memory")])

    def read(self, offset, length, pad=False):
        return b"MZ" + b"\0" * (length - 2)


def _match():
    ctx = NS(layers={"pid.4": _Process()})
    return renderers.LayerData(context=ctx, layer_name="pid.4", offset=0x7FF6_0000_1000, length=4)


def test_volatilitys_renderer_stops_on_such_a_match():
    with pytest.raises(StopIteration):
        text_renderer.LayerDataRenderer().render_bytes(_match())


def test_the_engines_renders_it_marking_the_bytes_the_image_lacks():
    text = aeng_windows._Dump()(_match())
    assert "4d 5a __ __" in text and "MZ.." in text


def test_a_match_volatility_can_render_is_rendered_the_same(monkeypatch):
    monkeypatch.setattr(_Process, "mapping",
                        lambda self, offset, length, ignore_errors=False:
                        iter([(offset, length, 0, length, "memory")]))
    assert aeng_windows._Dump()(_match()) == text_renderer.LayerDataRenderer()(_match())


def test_the_value_column_is_the_rendered_text(monkeypatch):
    row = (0x1000, 4, None, 1, "x.exe", 0, 1, "Rule_X", "$a", _match())
    monkeypatch.setattr(vadyarascan.VadYaraScan, "_generator", lambda self: iter([(0, row)]))
    plugin = aeng_windows.VadYaraScan.__new__(aeng_windows.VadYaraScan)
    grid = plugin.run()
    assert [(c.name, c.type) for c in grid.columns][-1] == ("Value", str)
    [(_level, out)] = list(plugin._generator())
    assert out[:-1] == row[:-1] and "4d 5a __ __" in out[-1]
