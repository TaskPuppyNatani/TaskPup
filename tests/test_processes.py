import errno
import os
from dataclasses import replace
import signal
import subprocess
import sys
from threading import Event
import select
import time

import pytest

from taskpup import management, processes
from taskpup.processes import Identity, ProcStat, Sampler, read_stat


@pytest.fixture
def sleeper():
    with subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "taskpup-test"]) as child:
        try:
            yield child
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)


def stat(pid: int, start: int, parent: int = 0, *, flags: int = 0, state: str = "S") -> ProcStat:
    return ProcStat(Identity(pid, start), f"test-{pid}", state, parent, flags, 0, 0, 1, 100)


def test_process_discovery_and_refresh(sleeper: subprocess.Popen) -> None:
    sampler = Sampler()
    first = sampler.sample(Event())
    row = next(row for row in first.rows if row.identity.pid == sleeper.pid)
    assert row.identity == read_stat(sleeper.pid).identity
    assert row.stat.ppid == os.getpid()
    assert row.uid == os.getuid() and row.username
    assert "taskpup-test" in row.command
    assert row.executable and row.stat.rss > 0 and row.stat.threads >= 1
    assert row.cpu is None and first.resources.cpu is None
    time.sleep(0.02)
    second = sampler.sample(Event())
    row = next(candidate for candidate in second.rows if candidate.identity == row.identity)
    assert row.cpu is not None and row.cpu >= 0
    assert second.resources.cpu is not None and 0 <= second.resources.cpu <= 100
    assert second.resources.ram is not None and 0 <= second.resources.ram <= 100


def test_sampling_skips_disappearance_and_replacement(monkeypatch: pytest.MonkeyPatch) -> None:
    gone, changed, stable = stat(100, 1), stat(200, 1), stat(300, 1)
    monkeypatch.setattr(processes, "iter_stats", lambda _: iter((gone, changed, stable)))

    def describe(entry: ProcStat) -> tuple[None, str, str]:
        if entry == gone:
            raise FileNotFoundError(errno.ENOENT, "process vanished")
        return None, "", ""

    monkeypatch.setattr(processes, "describe", describe)
    monkeypatch.setattr(processes, "read_stat", lambda pid: stable if pid == 300 else stat(200, 2))
    snapshot = Sampler().sample(Event())
    assert [row.identity for row in snapshot.rows] == [stable.identity]


def test_stat_with_parentheses_and_newline(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    pid = os.getpid()
    actual = read_stat(pid)
    raw = (processes.PROC / str(pid) / "stat").read_text()
    process_dir = tmp_path / str(pid)
    process_dir.mkdir()
    name = "fuzz)\n(stage"
    (process_dir / "stat").write_text(f"{pid} ({name})" + raw[raw.rindex(")") + 1:])
    monkeypatch.setattr(processes, "PROC", tmp_path)
    parsed = read_stat(pid)
    assert parsed.name == name and parsed.identity == actual.identity and parsed.ppid == actual.ppid


def test_stale_pid_does_not_signal_replacement(sleeper: subprocess.Popen) -> None:
    current = read_stat(sleeper.pid).identity
    stale = replace(current, start_ticks=current.start_ticks - 1)
    with pytest.raises(management.ProcessActionError, match="PID was reused"):
        management.send_signal(stale, signal.SIGKILL)
    assert sleeper.poll() is None


def test_permission_denied(sleeper: subprocess.Popen, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = read_stat(sleeper.pid).identity

    def deny(*args) -> None:
        raise PermissionError(errno.EPERM, "denied")

    monkeypatch.setattr(signal, "pidfd_send_signal", deny)
    with pytest.raises(management.ProcessActionError, match="Permission denied"):
        management.send_signal(identity, signal.SIGTERM)
    assert sleeper.poll() is None


def test_disappeared_process_error(sleeper: subprocess.Popen) -> None:
    identity = read_stat(sleeper.pid).identity
    sleeper.terminate()
    sleeper.wait(timeout=3)
    with pytest.raises(management.ProcessActionError, match="no longer available|PID was reused"):
        management.send_signal(identity, signal.SIGTERM)


def test_protected_and_exited_targets(sleeper: subprocess.Popen, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(management.ProcessActionError, match="init process"):
        management.send_signal(Identity(1, 0), signal.SIGKILL)
    with pytest.raises(management.ProcessActionError, match="own process"):
        management.send_signal(read_stat(os.getpid()).identity, signal.SIGSTOP)
    original = read_stat(sleeper.pid)
    monkeypatch.setattr(management, "read_stat", lambda _: replace(original, flags=processes.KERNEL_THREAD))
    with pytest.raises(management.ProcessActionError, match="Kernel threads"):
        management.send_signal(original.identity, signal.SIGKILL)
    monkeypatch.setattr(management, "read_stat", lambda _: replace(original, state="Z"))
    with pytest.raises(management.ProcessActionError, match="already exited"):
        management.send_signal(original.identity, signal.SIGTERM)
    assert sleeper.poll() is None


def test_tree_preview_preserves_exact_identity_set(monkeypatch: pytest.MonkeyPatch) -> None:
    root = stat(100, 10)
    child = stat(200, 12, 100)
    grandchild = stat(300, 13, 200)
    unrelated = stat(400, 11, 1)
    older_than_root = stat(500, 9, 100)
    rows = [root, child, grandchild, unrelated, older_than_root]
    monkeypatch.setattr(management, "read_stat", lambda pid: next(row for row in rows if row.identity.pid == pid))
    monkeypatch.setattr(management, "iter_stats", lambda: iter(rows))
    plan = management.preview_tree(root.identity)
    assert plan.targets == (grandchild, child, root)

    rows.append(stat(600, 20, 100))
    signaled: list[tuple[Identity, signal.Signals]] = []

    def record(identity: Identity, sig: signal.Signals) -> None:
        signaled.append((identity, sig))
        if identity == child.identity:
            raise management.ProcessActionError("The process is no longer available.")

    monkeypatch.setattr(management, "send_signal", record)
    errors = management.signal_tree(plan, signal.SIGTERM)
    assert signaled == [(row.identity, signal.SIGTERM) for row in (grandchild, child, root)]
    assert len(errors) == 1 and str(child.identity.pid) in errors[0]

    rows.append(stat(os.getpid(), 21, 100))
    with pytest.raises(management.ProcessActionError, match="tree contains.*own process"):
        management.preview_tree(root.identity)


def test_tree_preview_rejects_reused_intermediate_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    root = stat(100, 10)
    original = stat(200, 12, 100)
    replacement = stat(200, 13, 1)
    unrelated_child = stat(300, 14, 200)
    live = {100: root, 200: replacement, 300: unrelated_child}
    monkeypatch.setattr(management, "iter_stats", lambda: iter((root, original, unrelated_child)))
    monkeypatch.setattr(management, "read_stat", live.__getitem__)

    with pytest.raises(management.ProcessActionError, match="PID was reused"):
        management.preview_tree(root.identity)


def wait_stopped(pid: int, stopped: bool) -> None:
    deadline = time.monotonic() + 3
    while (read_stat(pid).state == "T") != stopped:
        if time.monotonic() >= deadline:
            pytest.fail(f"Process {pid} did not reach the expected stop state")
        time.sleep(0.01)


def test_stop_continue_and_terminate_isolated_child(sleeper: subprocess.Popen) -> None:
    identity = read_stat(sleeper.pid).identity
    management.send_signal(identity, signal.SIGSTOP)
    wait_stopped(sleeper.pid, True)
    management.send_signal(identity, signal.SIGCONT)
    wait_stopped(sleeper.pid, False)
    management.send_signal(identity, signal.SIGTERM)
    assert sleeper.wait(timeout=3) == -signal.SIGTERM


def test_terminate_isolated_process_tree() -> None:
    script = """
import signal
import subprocess
import sys

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])

def shutdown(*_):
    if child.poll() is None:
        child.terminate()
    child.wait(timeout=3)
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown)
print(child.pid, flush=True)
while True:
    signal.pause()
"""
    with subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True) as parent:
        try:
            assert parent.stdout is not None and select.select([parent.stdout], [], [], 3)[0]
            child_pid = int(parent.stdout.readline())
            plan = management.preview_tree(read_stat(parent.pid).identity)
            assert [target.identity.pid for target in plan.targets] == [child_pid, parent.pid]
            assert not management.signal_tree(plan, signal.SIGTERM)
            assert parent.wait(timeout=4) == 0
        finally:
            if parent.poll() is None:
                parent.terminate()
                try:
                    parent.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    parent.kill()
                    parent.wait(timeout=3)


def test_change_scheduling_and_force_kill_isolated_child(sleeper: subprocess.Popen) -> None:
    stat = read_stat(sleeper.pid)
    cpus = management.get_affinity(stat.identity)
    chosen = {min(cpus)}
    management.set_affinity(stat.identity, chosen)
    assert management.get_affinity(stat.identity) == chosen
    if stat.nice < 19:
        management.set_priority(stat.identity, stat.nice + 1)
        assert read_stat(sleeper.pid).nice == stat.nice + 1
    management.send_signal(stat.identity, signal.SIGKILL)
    assert sleeper.wait(timeout=3) == -signal.SIGKILL
