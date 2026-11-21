"""Linux process snapshots and interval-based resource sampling."""

from collections.abc import Iterator
from dataclasses import dataclass
import os
from pathlib import Path
import pwd
import shlex
from threading import Event
import time

import psutil


PROC = Path("/proc")
CLOCK_TICKS = os.sysconf("SC_CLK_TCK")
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
KERNEL_THREAD = 0x00200000

STATUSES = {
    "R": "Running",
    "S": "Sleeping",
    "D": "Disk sleep",
    "T": "Stopped",
    "t": "Tracing stop",
    "Z": "Zombie",
    "X": "Dead",
    "I": "Idle",
    "P": "Parked",
}


@dataclass(frozen=True, slots=True, order=True)
class Identity:
    pid: int
    start_ticks: int


@dataclass(frozen=True, slots=True)
class ProcStat:
    identity: Identity
    name: str
    state: str
    ppid: int
    flags: int
    cpu_ticks: int
    nice: int
    threads: int
    rss: int


@dataclass(frozen=True, slots=True)
class ProcessRow:
    stat: ProcStat
    uid: int | None
    username: str
    cpu: float | None
    executable: str
    command: str

    @property
    def identity(self) -> Identity:
        return self.stat.identity


@dataclass(frozen=True, slots=True)
class Resources:
    cpu: float | None
    ram: float
    swap: float | None


@dataclass(frozen=True, slots=True)
class Snapshot:
    rows: tuple[ProcessRow, ...]
    resources: Resources


def read_stat(pid: int) -> ProcStat:
    # comm can contain spaces, parentheses and newlines. The last ')' ends it.
    raw = (PROC / str(pid) / "stat").read_text(errors="replace")
    opening, closing = raw.index("("), raw.rindex(")")
    fields = raw[closing + 1 :].split()
    return ProcStat(
        Identity(pid, int(fields[19])),
        raw[opening + 1 : closing],
        fields[0],
        int(fields[1]),
        int(fields[6]),
        int(fields[11]) + int(fields[12]),
        int(fields[16]),
        int(fields[17]),
        max(0, int(fields[21])) * PAGE_SIZE,
    )


def iter_stats(stop: Event | None = None) -> Iterator[ProcStat]:
    with os.scandir(PROC) as entries:
        for entry in entries:
            if stop is not None and stop.is_set():
                break
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            try:
                yield read_stat(int(entry.name))
            except OSError:
                # The process can vanish between scandir and stat or be hidden.
                continue


def describe(stat: ProcStat) -> tuple[int | None, str, str]:
    pid = stat.identity.pid
    proc = psutil.Process(pid)
    uid: int | None = None
    executable = ""
    command = ""
    with proc.oneshot():
        try:
            uid = proc.uids().real
        except psutil.AccessDenied:
            pass
        try:
            executable = proc.exe()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            pass
        try:
            command = shlex.join(proc.cmdline())
        except (psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return uid, executable, command


class Sampler:
    def __init__(self) -> None:
        self.previous: dict[Identity, int] = {}
        self.previous_time: float | None = None
        self.cpu_primed = False
        self.usernames: dict[int, str] = {}

    def sample(self, stop: Event) -> Snapshot:
        now = time.monotonic()
        elapsed = now - self.previous_time if self.previous_time is not None else 0
        # psutil keeps its non-blocking CPU baseline per thread.
        system_cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory()
        swap = psutil.swap_memory()
        current: dict[Identity, int] = {}
        rows: list[ProcessRow] = []
        for stat in iter_stats(stop):
            identity = stat.identity
            try:
                uid, executable, command = describe(stat)
                if read_stat(identity.pid).identity != identity:
                    continue
            except (psutil.NoSuchProcess, OSError):
                continue

            old_ticks = self.previous.get(identity)
            cpu = None
            if old_ticks is not None and elapsed > 0:
                cpu = max(0.0, 100 * (stat.cpu_ticks - old_ticks) / (CLOCK_TICKS * elapsed))
            current[identity] = stat.cpu_ticks

            username = self.username(uid) if uid is not None else ""
            rows.append(ProcessRow(stat, uid, username, cpu, executable, command))

        resources = Resources(
            system_cpu if self.cpu_primed else None,
            ram.percent,
            swap.percent if swap.total else None,
        )
        self.cpu_primed = True
        self.previous, self.previous_time = current, now
        return Snapshot(tuple(rows), resources)

    def username(self, uid: int) -> str:
        if uid not in self.usernames:
            try:
                self.usernames[uid] = pwd.getpwuid(uid).pw_name
            except (KeyError, OSError):
                self.usernames[uid] = str(uid)
        return self.usernames[uid]
