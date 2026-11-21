from types import SimpleNamespace

import pytest

from taskpup import metrics
from taskpup.metrics import SystemSampler
from taskpup.storage import StorageSample


def cpu_line(name: str, values: list[int]) -> str:
    return f"{name} " + " ".join(map(str, values))


def make_proc(tmp_path, stat: str, *, cpuinfo: str = "", uptime: str = "123.5 20.0") -> None:
    (tmp_path / "stat").write_text(stat)
    (tmp_path / "cpuinfo").write_text(cpuinfo)
    (tmp_path / "uptime").write_text(uptime)


def patch_resources(
    monkeypatch: pytest.MonkeyPatch,
    *,
    memory=None,
    swap=None,
    timestamps: list[float] | None = None,
) -> None:
    monkeypatch.setattr(
        metrics.psutil,
        "virtual_memory",
        lambda: memory or SimpleNamespace(total=1000, available=400, percent=60, cached=100, buffers=20),
    )
    monkeypatch.setattr(
        metrics.psutil,
        "swap_memory",
        lambda: swap or SimpleNamespace(total=100, used=25, free=75, percent=25, sin=0, sout=0),
    )
    monkeypatch.setattr(metrics, "discover", lambda: ())
    monkeypatch.setattr(metrics.StorageSampler, "sample", lambda _, stamp: StorageSample(stamp, {}, ()))
    monkeypatch.setattr(metrics.NetworkSampler, "sample", lambda *_: {})
    if timestamps is not None:
        values = iter(timestamps)
        monkeypatch.setattr(metrics.time, "monotonic", lambda: next(values))


def test_cpu_first_sample_and_guest_fields_are_not_double_counted(tmp_path, monkeypatch) -> None:
    before = [100, 10, 100, 780, 0, 0, 0, 10, 50, 10]
    after = [110, 10, 110, 850, 10, 0, 0, 10, 10050, 10010]
    stat_path = tmp_path / "stat"
    make_proc(tmp_path, "\n".join((cpu_line("cpu", before), cpu_line("cpu0", before[:]), "")))
    monkeypatch.setattr(metrics, "PROC", tmp_path)
    patch_resources(monkeypatch, timestamps=[10.0, 11.0])
    sampler = SystemSampler()

    first = sampler.sample(detailed=False)
    assert first.timestamp == 10.0
    assert first.cpu_percent is None and first.logical_percent == {0: None}
    assert first.frequency_mhz is None and first.temperature_c is None

    stat_path.write_text("\n".join((cpu_line("cpu", after), cpu_line("cpu0", after), "")))
    second = sampler.sample(detailed=False)
    assert second.cpu_percent == pytest.approx(20.0)
    assert second.logical_percent[0] == pytest.approx(20.0)


def test_hotplug_preserves_native_indexes_and_reprimes_aggregate(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(metrics, "PROC", tmp_path)
    patch_resources(monkeypatch, timestamps=[1.0, 2.0, 3.0])
    sampler = SystemSampler()
    stat_path = tmp_path / "stat"

    initial = [100, 0, 100, 800, 0, 0, 0, 0]
    make_proc(
        tmp_path,
        "\n".join((cpu_line("cpu", initial), cpu_line("cpu0", initial), cpu_line("cpu7", initial), "")),
    )
    assert sampler.sample(detailed=False).logical_percent == {0: None, 7: None}

    hotplugged = [110, 0, 110, 870, 10, 0, 0, 0]
    stat_path.write_text(
        "\n".join((cpu_line("cpu", hotplugged), cpu_line("cpu0", hotplugged), cpu_line("cpu2", initial), ""))
    )
    second = sampler.sample(detailed=False)
    assert second.cpu_percent is None
    assert second.logical_percent.keys() == {0, 2}
    assert second.logical_percent[0] == pytest.approx(20.0)
    assert second.logical_percent[2] is None

    steady = [120, 0, 120, 940, 20, 0, 0, 0]
    stat_path.write_text(
        "\n".join((cpu_line("cpu", steady), cpu_line("cpu0", steady), cpu_line("cpu2", hotplugged), ""))
    )
    third = sampler.sample(detailed=False)
    assert third.cpu_percent == pytest.approx(20.0)
    assert third.logical_percent == {0: pytest.approx(20.0), 2: pytest.approx(20.0)}


def test_reset_clears_cpu_and_swap_delta_baselines(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(metrics, "PROC", tmp_path)
    swap = SimpleNamespace(total=100, used=25, free=75, percent=25, sin=100, sout=200)
    patch_resources(monkeypatch, swap=swap, timestamps=[1.0, 2.0, 3.0])
    sampler = SystemSampler()
    initial = [100, 0, 100, 800, 0, 0, 0, 0]
    make_proc(tmp_path, "\n".join((cpu_line("cpu", initial), cpu_line("cpu0", initial), "")))
    sampler.sample(detailed=False)

    swap.sin += 50
    swap.sout += 75
    updated = [110, 0, 110, 880, 10, 0, 0, 0]
    (tmp_path / "stat").write_text("\n".join((cpu_line("cpu", updated), cpu_line("cpu0", updated), "")))
    sampler.reset()
    sample = sampler.sample(detailed=False)

    assert sample.cpu_percent is None and sample.logical_percent[0] is None
    assert sample.swap is not None
    assert sample.swap.in_per_second is None and sample.swap.out_per_second is None


def test_cpu_counter_reset_invalidates_interval_then_recovers(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(metrics, "PROC", tmp_path)
    patch_resources(monkeypatch, timestamps=[1.0, 2.0, 3.0])
    sampler = SystemSampler()
    initial = [100, 0, 100, 800, 0, 0, 0, 0]
    make_proc(tmp_path, "\n".join((cpu_line("cpu", initial), cpu_line("cpu0", initial), "")))
    sampler.sample(detailed=False)

    reset = [5, 0, 5, 40, 0, 0, 0, 0]
    (tmp_path / "stat").write_text("\n".join((cpu_line("cpu", reset), cpu_line("cpu0", reset), "")))
    second = sampler.sample(detailed=False)
    assert second.cpu_percent is None and second.logical_percent[0] is None

    resumed = [15, 0, 15, 120, 0, 0, 0, 0]
    (tmp_path / "stat").write_text("\n".join((cpu_line("cpu", resumed), cpu_line("cpu0", resumed), "")))
    third = sampler.sample(detailed=False)
    assert third.cpu_percent == pytest.approx(20.0)
    assert third.logical_percent[0] == pytest.approx(20.0)


def test_memory_and_swap_utilization_and_activity_rates(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(metrics, "PROC", tmp_path)
    memory = SimpleNamespace(total=1000, available=350, used=999, percent=65, cached=120, buffers=30)
    swap = SimpleNamespace(total=800, used=200, free=600, percent=25, sin=1000, sout=500)
    patch_resources(monkeypatch, memory=memory, swap=swap, timestamps=[5.0, 7.0])
    initial = [100, 0, 100, 800, 0, 0, 0, 0]
    make_proc(tmp_path, "\n".join((cpu_line("cpu", initial), cpu_line("cpu0", initial), "")))
    sampler = SystemSampler()

    first = sampler.sample(detailed=False)
    assert first.memory is not None
    assert (first.memory.total, first.memory.available, first.memory.used) == (1000, 350, 650)
    assert (first.memory.cached, first.memory.buffers, first.memory.percent) == (120, 30, 65)
    assert first.swap == metrics.SwapSample(800, 200, 600, 25, None, None)

    swap.sin = 1040
    swap.sout = 560
    second = sampler.sample(detailed=False)
    assert second.swap is not None
    assert second.swap.in_per_second == pytest.approx(20.0)
    assert second.swap.out_per_second == pytest.approx(30.0)


def test_swap_counter_reset_and_no_swap_leave_activity_unavailable(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(metrics, "PROC", tmp_path)
    swap = SimpleNamespace(total=100, used=10, free=90, percent=10, sin=100, sout=200)
    patch_resources(monkeypatch, swap=swap, timestamps=[1.0, 2.0, 3.0, 4.0])
    initial = [100, 0, 100, 800, 0, 0, 0, 0]
    make_proc(tmp_path, "\n".join((cpu_line("cpu", initial), cpu_line("cpu0", initial), "")))
    sampler = SystemSampler()
    sampler.sample(detailed=False)

    swap.sin = 5
    swap.sout = 6
    reset = sampler.sample(detailed=False).swap
    assert reset is not None and reset.in_per_second is None and reset.out_per_second is None

    swap.total = swap.used = swap.free = 0
    no_swap = sampler.sample(detailed=False).swap
    assert no_swap == metrics.SwapSample(0, 0, 0, None, None, None)

    swap.total, swap.used, swap.free = 100, 10, 90
    resumed = sampler.sample(detailed=False).swap
    assert resumed is not None and resumed.in_per_second is None and resumed.out_per_second is None


def test_missing_swap_counters_preserve_utilization(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(metrics, "PROC", tmp_path)
    swap = SimpleNamespace(total=100, used=20, free=80, percent=20, sin=0, sout=0)
    patch_resources(monkeypatch, swap=swap, timestamps=[1.0, 2.0])
    initial = [100, 0, 100, 800, 0, 0, 0, 0]
    make_proc(tmp_path, "\n".join((cpu_line("cpu", initial), cpu_line("cpu0", initial), "")))

    sampler = SystemSampler()
    first = sampler.sample(detailed=False)
    second = sampler.sample(detailed=False)
    assert first.swap == metrics.SwapSample(100, 20, 80, 20, None, None)
    assert second.swap == metrics.SwapSample(100, 20, 80, 20, None, None)


def test_zero_swap_counters_are_valid_when_vmstat_keys_exist(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(metrics, "PROC", tmp_path)
    swap = SimpleNamespace(total=100, used=0, free=100, percent=0, sin=0, sout=0)
    patch_resources(monkeypatch, swap=swap, timestamps=[1.0, 2.0])
    initial = [100, 0, 100, 800, 0, 0, 0, 0]
    make_proc(tmp_path, "\n".join((cpu_line("cpu", initial), cpu_line("cpu0", initial), "")))
    (tmp_path / "vmstat").write_text("pswpin 0\npswpout 0\npgpgin 0\n")

    sampler = SystemSampler()
    assert sampler.sample(detailed=False).swap is not None
    second = sampler.sample(detailed=False).swap
    assert second == metrics.SwapSample(100, 0, 100, 0, 0.0, 0.0)


def test_cpu_sensors_filter_non_cpu_and_detailed_false_skips_reads(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(metrics, "PROC", tmp_path)
    patch_resources(monkeypatch, timestamps=[1.0, 2.0, 2.1, 2.2])
    stat = [100, 0, 100, 800, 0, 0, 0, 0]
    cpuinfo = """processor : 0
model name : Example CPU
physical id : 0
core id : 0

processor : 1
model name : Example CPU
physical id : 0
core id : 0
"""
    make_proc(tmp_path, "\n".join((cpu_line("cpu", stat), cpu_line("cpu0", stat), cpu_line("cpu1", stat), "")), cpuinfo=cpuinfo)
    sampler = SystemSampler()
    frequency_calls = []
    sensor_calls = []
    monkeypatch.setattr(metrics.psutil, "cpu_freq", lambda: frequency_calls.append(True))
    monkeypatch.setattr(metrics.psutil, "sensors_temperatures", lambda **_: sensor_calls.append(True))
    light = sampler.sample(detailed=False)
    assert light.cpu_model is None and light.physical_cores is None
    assert light.memory is not None and light.swap is not None
    assert frequency_calls == [] and sensor_calls == []

    monkeypatch.setattr(metrics.psutil, "cpu_freq", lambda: SimpleNamespace(current=2400.0))
    monkeypatch.setattr(
        metrics.psutil,
        "sensors_temperatures",
        lambda **_: {
            "coretemp": [SimpleNamespace(label="Package id 0", current=62.5)],
            "amdgpu": [SimpleNamespace(label="edge", current=95.0)],
            "hwmon2": [SimpleNamespace(label="Core 0", current=100.0)],
        },
    )
    detailed = sampler.sample(detailed=True)
    assert detailed.cpu_model == "Example CPU"
    assert detailed.physical_cores == 1 and detailed.logical_cores == 2
    assert detailed.frequency_mhz == 2400.0
    assert detailed.temperature_c == 62.5
    assert detailed.uptime_s == 123.5


def test_numeric_processor_index_is_not_a_cpu_model(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(metrics, "PROC", tmp_path)
    patch_resources(monkeypatch, timestamps=[1.0, 1.1, 1.2])
    monkeypatch.setattr(metrics.psutil, "cpu_count", lambda logical: None)
    monkeypatch.setattr(metrics.psutil, "cpu_freq", lambda: None)
    monkeypatch.setattr(metrics.psutil, "sensors_temperatures", lambda **_: {})
    counters = [100, 0, 100, 800, 0, 0, 0, 0]
    cpuinfo = "processor : 0\n\nprocessor : 1\n"
    make_proc(tmp_path, "\n".join((cpu_line("cpu", counters), cpu_line("cpu0", counters), "")), cpuinfo=cpuinfo)

    assert SystemSampler().sample().cpu_model is None


def test_transfer_sampling_uses_one_worker_cycle_and_resets_baselines(monkeypatch: pytest.MonkeyPatch) -> None:
    patch_resources(monkeypatch, timestamps=[5.0, 6.0, 6.1, 6.2])
    calls: list[tuple[str, float]] = []
    monkeypatch.setattr(SystemSampler, "_read_frequency", lambda _: None)
    monkeypatch.setattr(SystemSampler, "_read_temperature", lambda _: None)
    sampler = SystemSampler()

    def read_disk(stamp: float) -> StorageSample:
        calls.append(("storage", stamp))
        return StorageSample(stamp, {}, ())

    def read_net(stamp: float) -> dict:
        calls.append(("network", stamp))
        return {}

    monkeypatch.setattr(sampler._storage, "sample", read_disk)
    monkeypatch.setattr(sampler._network, "sample", read_net)
    monkeypatch.setattr(sampler._storage, "reset", lambda: calls.append(("storage reset", 0)))
    monkeypatch.setattr(sampler._network, "reset", lambda: calls.append(("network reset", 0)))

    light = sampler.sample(detailed=False)
    assert light.storage is None and light.network is None and calls == []
    detailed = sampler.sample()
    assert detailed.storage is not None and detailed.storage.timestamp == 6.2
    assert detailed.network == {} and detailed.network_timestamp == 6.1
    sampler.reset()
    assert calls == [("network", 6.1), ("storage", 6.2), ("storage reset", 0), ("network reset", 0)]
