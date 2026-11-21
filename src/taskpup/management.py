"""Process actions gated by Linux process identity."""

from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import errno
import os
import select
import signal

from taskpup.processes import Identity, KERNEL_THREAD, ProcStat, iter_stats, read_stat


class ProcessActionError(Exception):
    """An actionable error suitable for display in the GUI."""


def protected_reason(stat: ProcStat) -> str | None:
    pid = stat.identity.pid
    if pid <= 1:
        return "The system init process is protected."
    if pid == os.getpid():
        return "TaskPup cannot modify its own process."
    if stat.flags & KERNEL_THREAD:
        return "Kernel threads are protected."
    return None


def check_identity(identity: Identity, *, mutable: bool = False) -> ProcStat:
    try:
        stat = read_stat(identity.pid)
    except OSError as error:
        raise action_error(error) from error
    if stat.identity != identity:
        raise ProcessActionError("The original process exited and its PID was reused.")
    if mutable:
        reason = protected_reason(stat)
        if reason:
            raise ProcessActionError(reason)
        if stat.state in {"Z", "X", "x"}:
            raise ProcessActionError("The process has already exited.")
    return stat


def action_error(error: OSError) -> ProcessActionError:
    if error.errno in {errno.ENOENT, errno.ESRCH}:
        return ProcessActionError("The process is no longer available.")
    if error.errno in {errno.EACCES, errno.EPERM}:
        return ProcessActionError("Permission denied by Linux for this process.")
    if error.errno in {errno.ENOSYS, errno.EOPNOTSUPP, errno.ENODEV}:
        return ProcessActionError("This operation is unavailable on this Linux system.")
    return ProcessActionError(error.strerror or str(error))


@contextmanager
def process_handle(identity: Identity) -> Iterator[int]:
    if identity.pid <= 1:
        raise ProcessActionError("The system init process is protected.")
    if identity.pid == os.getpid():
        raise ProcessActionError("TaskPup cannot modify its own process.")
    if not hasattr(os, "pidfd_open"):
        raise ProcessActionError("This system does not provide process file descriptors.")
    try:
        fd = os.pidfd_open(identity.pid)
        try:
            # Open first so a later PID reuse cannot redirect pidfd_send_signal.
            check_identity(identity, mutable=True)
            ensure_alive(fd)
            yield fd
        finally:
            os.close(fd)
    except OSError as error:
        raise action_error(error) from error


def ensure_alive(fd: int) -> None:
    watcher = select.poll()
    watcher.register(fd, select.POLLIN)
    if watcher.poll(0):
        raise ProcessActionError("The process has already exited.")


def send_signal(identity: Identity, sig: signal.Signals) -> None:
    if not hasattr(signal, "pidfd_send_signal"):
        raise ProcessActionError("This system does not support signaling by process file descriptor.")
    with process_handle(identity) as fd:
        signal.pidfd_send_signal(fd, sig)


def set_priority(identity: Identity, nice: int) -> None:
    if not -20 <= nice <= 19:
        raise ProcessActionError("Nice must be between −20 and 19.")
    with process_handle(identity) as fd:
        os.setpriority(os.PRIO_PROCESS, identity.pid, nice)
        ensure_alive(fd)


def get_affinity(identity: Identity) -> set[int]:
    with process_handle(identity) as fd:
        cpus = os.sched_getaffinity(identity.pid)
        ensure_alive(fd)
        return cpus


def set_affinity(identity: Identity, cpus: set[int]) -> None:
    if not cpus or min(cpus) < 0:
        raise ProcessActionError("Select at least one valid CPU.")
    with process_handle(identity) as fd:
        os.sched_setaffinity(identity.pid, cpus)
        ensure_alive(fd)
        applied = os.sched_getaffinity(identity.pid)
        ensure_alive(fd)
        if applied != cpus:
            shown = ", ".join(str(cpu) for cpu in sorted(applied))
            raise ProcessActionError(f"Linux restricted the applied affinity to CPUs {shown}.")


@dataclass(frozen=True, slots=True)
class TreePlan:
    root: Identity
    targets: tuple[ProcStat, ...]


def preview_tree(root: Identity) -> TreePlan:
    root_stat = check_identity(root, mutable=True)
    children: dict[int, list[ProcStat]] = defaultdict(list)
    for stat in iter_stats():
        if stat.identity != root:
            children[stat.ppid].append(stat)
    # If the root disappeared during enumeration, do not preview another tree.
    check_identity(root, mutable=True)
    visited = {root}
    pending = [root_stat]
    targets: list[ProcStat] = []
    while pending:
        parent = pending.pop()
        reason = protected_reason(parent)
        if reason:
            raise ProcessActionError(
                f"The tree contains {parent.name} (PID {parent.identity.pid}). {reason}"
            )
        targets.append(parent)
        descendants = [
            child for child in children.get(parent.identity.pid, ())
            if child.identity not in visited and child.identity.start_ticks >= parent.identity.start_ticks
        ]
        if descendants and parent.identity != root:
            # A reused intermediate PID can make another process's children
            # appear beneath the parent captured earlier in the scan.
            check_identity(parent.identity, mutable=True)
        for child in descendants:
            visited.add(child.identity)
            pending.append(child)
    return TreePlan(root, tuple(reversed(targets)))


def signal_tree(plan: TreePlan, sig: signal.Signals) -> list[str]:
    failures: list[str] = []
    for stat in plan.targets:
        try:
            send_signal(stat.identity, sig)
        except ProcessActionError as error:
            failures.append(f"{stat.name} (PID {stat.identity.pid}): {error}")
    return failures
