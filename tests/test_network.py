from pathlib import Path
from types import SimpleNamespace

from taskpup import network
from taskpup.network import InterfaceSample, NetworkSampler


def _counter(received: int, transmitted: int) -> SimpleNamespace:
    return SimpleNamespace(bytes_recv=received, bytes_sent=transmitted)


def _stats(*, isup: bool = True, speed: int = 1000) -> SimpleNamespace:
    return SimpleNamespace(isup=isup, speed=speed)


def _sysfs_interface(
    root: Path,
    name: str,
    *,
    kind: int = 1,
    ifindex: int = 2,
    iflink: int | None = None,
    device: bool = False,
    bridge: bool = False,
    tun: bool = False,
    speed: int | None = 1000,
) -> Path:
    path = root / name
    path.mkdir(parents=True)
    (path / "type").write_text(str(kind))
    (path / "ifindex").write_text(str(ifindex))
    (path / "iflink").write_text(str(iflink if iflink is not None else ifindex))
    (path / "operstate").write_text("up")
    (path / "carrier").write_text("1")
    if device:
        (path / "device").mkdir()
    if bridge:
        (path / "bridge").mkdir()
    if tun:
        (path / "tun_flags").write_text("0")
    if speed is not None:
        (path / "speed").write_text(str(speed))
    return path


def _sampler(monkeypatch, tmp_path: Path, name: str = "eth0", index: int = 2):
    sources = {
        "indexes": [(index, name)],
        "counters": {name: _counter(100, 50)},
        "stats": {name: _stats()},
    }
    monkeypatch.setattr(network.socket, "if_nameindex", lambda: list(sources["indexes"]))
    monkeypatch.setattr(
        network.psutil,
        "net_io_counters",
        lambda **kwargs: dict(sources["counters"]),
    )
    monkeypatch.setattr(network.psutil, "net_if_stats", lambda: dict(sources["stats"]))
    sampler = NetworkSampler(tmp_path / "sys-net")
    return sampler, sources


def test_interface_identity_is_stable_and_rates_are_per_interface(monkeypatch, tmp_path) -> None:
    root = tmp_path / "sys-net"
    _sysfs_interface(root, "eth0", device=True)
    sampler, sources = _sampler(monkeypatch, tmp_path)

    first = sampler.sample(1.0)
    sources["counters"] = {"eth0": _counter(300, 90)}
    second = sampler.sample(3.0)

    assert first is not None and second is not None
    assert len(first) == len(second) == 1
    identity = next(iter(first))
    assert identity == next(iter(second))
    reading = second[identity]
    assert reading == InterfaceSample(
        name="eth0",
        kind="Ethernet",
        auxiliary=False,
        status="Connected",
        speed_supported=True,
        speed_mbps=1000,
        receive_rate=100.0,
        transmit_rate=20.0,
        bytes_received=300,
        bytes_transmitted=90,
    )
    assert "aggregate" not in identity.lower()


def test_reset_and_temporary_speed_loss_keep_capability(monkeypatch, tmp_path) -> None:
    root = tmp_path / "sys-net"
    path = _sysfs_interface(root, "eth0", device=True)
    sampler, sources = _sampler(monkeypatch, tmp_path)
    first = sampler.sample(1.0)
    assert first is not None
    identity = next(iter(first))

    sampler.reset()
    (path / "speed").unlink()
    sources["counters"] = {"eth0": _counter(200, 80)}
    sources["stats"] = {}
    unavailable = sampler.sample(2.0)

    assert unavailable is not None
    sample = unavailable[identity]
    assert sample.receive_rate is None and sample.transmit_rate is None
    assert sample.bytes_received == 200 and sample.bytes_transmitted == 80
    assert sample.status == "Unavailable"
    assert sample.speed_supported is True
    assert sample.speed_mbps is None

    sources["stats"] = {"eth0": _stats()}
    sources["counters"] = {"eth0": _counter(300, 100)}
    resumed = sampler.sample(3.0)
    assert resumed is not None
    assert resumed[identity].receive_rate == 100.0
    assert resumed[identity].speed_supported is True
    assert resumed[identity].speed_mbps == 1000


def test_wrap_is_counted_but_reset_suppresses_spike(monkeypatch, tmp_path) -> None:
    root = tmp_path / "sys-net"
    _sysfs_interface(root, "eth0", device=True)
    sampler, sources = _sampler(monkeypatch, tmp_path)
    sources["counters"] = {"eth0": _counter((1 << 64) - 2, 100)}
    sampler.sample(1.0)

    sources["counters"] = {"eth0": _counter(3, 10)}
    wrapped = sampler.sample(2.0)
    assert wrapped is not None
    reading = next(iter(wrapped.values()))
    assert reading.receive_rate == 5.0
    assert reading.transmit_rate is None

    sources["counters"] = {"eth0": _counter(4, 15)}
    recovered = sampler.sample(3.0)
    assert recovered is not None
    reading = next(iter(recovered.values()))
    assert reading.receive_rate == 1.0
    assert reading.transmit_rate == 5.0


def test_virtual_bridge_tunnel_and_loopback_metadata(monkeypatch, tmp_path) -> None:
    root = tmp_path / "sys-net"
    _sysfs_interface(root, "lo", kind=772, ifindex=1, speed=None)
    _sysfs_interface(root, "veth0", ifindex=2, iflink=12, speed=None)
    _sysfs_interface(root, "br0", ifindex=3, bridge=True, speed=10000)
    _sysfs_interface(root, "tun0", kind=65534, ifindex=4, tun=True, speed=None)
    _sysfs_interface(root, "wg0", ifindex=5, speed=None)
    _sysfs_interface(root, "eth0", ifindex=6, device=True)
    _sysfs_interface(root, "gre0", kind=778, ifindex=7, speed=None)
    names = ["lo", "veth0", "br0", "tun0", "wg0", "eth0", "gre0"]
    sources = {
        "indexes": list(enumerate(names, start=1)),
        "counters": {name: _counter(0, 0) for name in names},
        "stats": {name: _stats(speed=10000) for name in names},
    }
    monkeypatch.setattr(network.socket, "if_nameindex", lambda: list(sources["indexes"]))
    monkeypatch.setattr(network.psutil, "net_io_counters", lambda **kwargs: dict(sources["counters"]))
    monkeypatch.setattr(network.psutil, "net_if_stats", lambda: dict(sources["stats"]))
    sampler = NetworkSampler(root)

    result = sampler.sample(1.0)

    assert result is not None and len(result) == 7
    by_name = {sample.name: sample for sample in result.values()}
    assert (by_name["lo"].kind, by_name["lo"].auxiliary) == ("Loopback", True)
    assert (by_name["veth0"].kind, by_name["veth0"].auxiliary) == ("Virtual", True)
    assert (by_name["br0"].kind, by_name["br0"].auxiliary) == ("Bridge", False)
    assert (by_name["tun0"].kind, by_name["tun0"].auxiliary) == ("Tunnel", False)
    assert (by_name["wg0"].kind, by_name["wg0"].auxiliary) == ("Virtual", False)
    assert (by_name["eth0"].kind, by_name["eth0"].auxiliary) == ("Ethernet", False)
    assert (by_name["gre0"].kind, by_name["gre0"].auxiliary) == ("Tunnel", False)
    assert by_name["br0"].speed_supported is False
    assert by_name["tun0"].speed_supported is False


def test_link_state_counter_unavailability_and_zero_rates(monkeypatch, tmp_path) -> None:
    root = tmp_path / "sys-net"
    path = _sysfs_interface(root, "eth0", device=True)
    sampler, sources = _sampler(monkeypatch, tmp_path)
    first = sampler.sample(1.0)
    assert first is not None
    identity = next(iter(first))
    assert first[identity].receive_rate is None

    (path / "carrier").write_text("0")
    sources["counters"] = {"eth0": _counter(100, 50)}
    disconnected = sampler.sample(2.0)
    assert disconnected is not None
    assert disconnected[identity].status == "Disconnected"
    assert disconnected[identity].receive_rate == 0.0
    assert disconnected[identity].speed_supported and disconnected[identity].speed_mbps is None

    (path / "carrier").write_text("1")
    sources["counters"] = {}
    sources["stats"] = {}
    missing = sampler.sample(3.0)
    assert missing is not None
    assert missing[identity].bytes_received is None
    assert missing[identity].receive_rate is None
    assert missing[identity].status == "Unavailable"

    sources["counters"] = {"eth0": _counter(200, 100)}
    sources["stats"] = {"eth0": _stats()}
    recovered = sampler.sample(4.0)
    assert recovered is not None
    assert recovered[identity].receive_rate is None
    sources["counters"] = {"eth0": _counter(300, 120)}
    next_sample = sampler.sample(5.0)
    assert next_sample is not None
    assert next_sample[identity].receive_rate == 100.0


def test_disappearance_and_ifindex_reuse_get_new_generation(monkeypatch, tmp_path) -> None:
    root = tmp_path / "sys-net"
    _sysfs_interface(root, "eth0", device=True, ifindex=2)
    sampler, sources = _sampler(monkeypatch, tmp_path, index=2)
    initial = sampler.sample(1.0)
    assert initial is not None
    initial_key = next(iter(initial))

    sources["indexes"] = []
    sources["counters"] = {}
    sources["stats"] = {}
    assert sampler.sample(2.0) == {}
    assert sampler._identities == {}
    assert sampler._metadata == {}

    sources["indexes"] = [(2, "eth0")]
    sources["counters"] = {"eth0": _counter(500, 200)}
    sources["stats"] = {"eth0": _stats()}
    returned = sampler.sample(3.0)
    assert returned is not None
    returned_key = next(iter(returned))
    assert returned_key != initial_key
    assert returned[returned_key].receive_rate is None

    sources["indexes"] = [(9, "eth0")]
    replaced = sampler.sample(4.0)
    assert replaced is not None
    assert next(iter(replaced)) != returned_key
    assert len(sampler._metadata) == 1


def test_collection_outage_is_distinct_from_successful_empty_discovery(monkeypatch, tmp_path) -> None:
    sampler, sources = _sampler(monkeypatch, tmp_path)
    monkeypatch.setattr(network.socket, "if_nameindex", lambda: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(network.psutil, "net_io_counters", lambda **kwargs: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(network.psutil, "net_if_stats", lambda: (_ for _ in ()).throw(OSError()))
    assert sampler.sample(1.0) is None

    monkeypatch.setattr(network.socket, "if_nameindex", lambda: [])
    monkeypatch.setattr(network.psutil, "net_io_counters", lambda **kwargs: {})
    monkeypatch.setattr(network.psutil, "net_if_stats", lambda: {})
    assert sampler.sample(2.0) == {}
