"""`linux.lsof` and `linux.sockstat` reading each file table once (v0.7.163).

Volatility's own two walk the open files of every THREAD. The threads of a
process share one file table (`task.files`), so a process of a hundred threads
has its descriptors read a hundred times, and every socket among them decoded a
hundred times -- each time with the map of the network devices rebuilt from
every namespace. On a 4 GB desktop image that was 29k socket descriptors for 1.6k
sockets, and sockstat ran past a quarter of an hour.

Here a thread is skipped when its file table is its leader's, so the output is
Volatility's own less those repeats: one row per process, descriptor and file. A
thread with a table of its own (`unshare(CLONE_FILES)`) is still read. The device
map is built once per network namespace, which is all it depends on.

The same columns as the plugins they extend, so the tables keep their shape.
Run as `aeng_linux.Lsof` / `aeng_linux.Sockstat` with this folder on `-p`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from volatility3.framework import constants, exceptions, renderers
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import lsof, pslist, sockstat


def file_tables(context, vmlinux_module_name: str,
                filter_func: Callable = lambda _: False,
                include_files_only: bool = False) -> Iterable[lsof.FDInternal]:
    """`lsof.Lsof.list_fds`, a thread sharing its leader's file table left out.
    `list_tasks` yields each leader before its threads."""
    utils = None
    leader_files = None
    for task in pslist.PsList.list_tasks(context, vmlinux_module_name, filter_func,
                                         include_threads=True):
        if utils is None:
            if constants.BANG not in task.vol.type_name:
                raise ValueError("Task is not part of a symbol table")
            utils = task.vol.type_name.split(constants.BANG)[0]
        files = int(task.files)
        if task.pid == task.tgid:
            leader_files = files
        elif files == leader_files:
            continue
        for fd_fields in linux.LinuxUtilities.files_descriptors_for_process(
                context, utils, task, files_only=include_files_only):
            yield lsof.FDInternal(task=task, fd_fields=fd_fields)


class Lsof(lsof.Lsof):
    """Open file descriptors of every process, each file table read once."""

    @classmethod
    def list_fds(cls, context, vmlinux_module_name, filter_func=lambda _: False,
                 include_files_only=False):
        return file_tables(context, vmlinux_module_name, filter_func, include_files_only)


class Sockstat(sockstat.Sockstat):
    """Every socket of every process, each file table read once."""

    @classmethod
    def list_sockets(cls, context, symbol_table, filter_func=lambda _: False):
        # sockstat.Sockstat.list_sockets over file_tables, with one SockHandlers
        # per network namespace instead of one per socket
        vmlinux = context.modules[symbol_table]
        sfop_addr = vmlinux.object_from_symbol("socket_file_ops").vol.offset
        dfop_addr = vmlinux.object_from_symbol("sockfs_dentry_operations").vol.offset
        handlers: dict = {}
        for fd_internal in file_tables(context, vmlinux.name, filter_func):
            fd_num, filp, _full_path = fd_internal.fd_fields
            task = fd_internal.task
            if not (filp.f_op and filp.f_op.is_readable()):
                continue
            if filp.f_op not in (sfop_addr, dfop_addr):
                continue
            dentry = filp.get_dentry()
            if not (dentry and dentry.is_readable()):
                continue
            d_inode = dentry.d_inode
            if not (d_inode and d_inode.is_readable()):
                continue
            socket_alloc = linux.LinuxUtilities.container_of(
                d_inode, "socket_alloc", "vfs_inode", vmlinux)
            if not socket_alloc:
                continue
            socket = socket_alloc.socket
            if not (socket.sk and socket.sk.is_readable()):
                continue
            sock = socket.sk.dereference()
            try:
                # inside the guard, as Volatility reads it (in SockHandlers): an
                # unreadable namespace skips this socket, not the whole run
                try:
                    netns_id = task.nsproxy.net_ns.get_inode()
                except AttributeError:
                    netns_id = renderers.NotAvailableValue()
                sock_type = sock.get_type()
                family = sock.get_family()
                key = netns_id if isinstance(netns_id, int) else None
                handler = handlers.get(key)
                if handler is None:
                    handler = handlers[key] = sockstat.SockHandlers(
                        context, vmlinux.name, task)
                sock_fields = handler.process_sock(sock)
            except exceptions.InvalidAddressException:
                continue
            if not sock_fields:
                continue
            protocol = sock_fields[0].get_protocol()
            yield task, netns_id, fd_num, family, sock_type, protocol, sock_fields
