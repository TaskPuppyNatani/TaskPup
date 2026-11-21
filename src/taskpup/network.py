"""Read-only network interface discovery and traffic sampling."""

from dataclasses import dataclass
import math
from pathlib import Path
import socket

import psutil


SYS_NET = Path("/sys/class/net")
_COUNTER_MODULUS = 1 << 64
_COUNTER_WRAP_WINDOW = 1 << 32
_TUNNEL_LINK_TYPES = {768, 769, 776, 778, 823}
_DOWN_STATES = {"down", "lowerlayerdown", "notpresent"}


def _read_text(path: Path) -> str | None:
    try:
        value = path.read_text(errors="replace").strip()
    except OSError:
        return None
    return value or None


def _read_nonnegative_int(path: Path) -> int | None:
    value = _read_text(path)
    try:
        result = int(value) if value is not None else None
    except ValueError:
        return None
    return result if result is not None and result >= 0 else None


def _positive_int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _counter(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


@dataclass(frozen=True, slots=True)
class InterfaceSample:
    name: str
    kind: str
    auxiliary: bool
    status: str
    speed_supported: bool
    speed_mbps: int | None
    receive_rate: float | None
    transmit_rate: float | None
    bytes_received: int | None
    bytes_transmitted: int | None


@dataclass(slots=True)
class _InterfaceMetadata:
    kind: str
    auxiliary: bool
    speed_supported: bool


@dataclass(frozen=True, slots=True)
class _Identity:
    generation: int
    ifindex: int | None
    key: str


class NetworkSampler:
    """Sample per-interface counters without combining physical and virtual links."""

    def __init__(self, sysfs_root: Path = SYS_NET) -> None:
        self._sysfs_root = sysfs_root
        self._identities: dict[str, _Identity] = {}
        self._generation = 0
        self._metadata: dict[str, _InterfaceMetadata] = {}
        self._baselines: dict[tuple[str, str], tuple[float, int]] = {}

    def reset(self) -> None:
        """Clear rate baselines while retaining interface identity and capabilities."""
        self._baselines.clear()

    def sample(self, timestamp: float) -> dict[str, InterfaceSample] | None:
        """Return per-interface readings, or ``None`` if all discovery sources fail."""
        if not math.isfinite(timestamp):
            raise ValueError("timestamp must be finite")

        indexes, index_ok = self._interface_indexes()
        counters, counters_ok = self._interface_counters()
        stats, stats_ok = self._interface_stats()
        if not (index_ok or counters_ok or stats_ok):
            # Keep identities and baselines intact through a collection-wide outage.
            return None

        names = set(indexes) | set(counters) | set(stats)
        result: dict[str, InterfaceSample] = {}
        active_keys: set[str] = set()

        for name in sorted(names):
            ifindex = indexes.get(name)
            identity = self._identity_for(name, ifindex)
            active_keys.add(identity.key)

            current_stats = stats.get(name)
            metadata = self._metadata.get(identity.key)
            if metadata is None:
                metadata, speed = self._discover_metadata(name, ifindex, current_stats)
                self._metadata[identity.key] = metadata
            else:
                speed = self._current_speed(name, current_stats, metadata)

            counters_for_interface = counters.get(name)
            received = _counter(getattr(counters_for_interface, "bytes_recv", None))
            transmitted = _counter(getattr(counters_for_interface, "bytes_sent", None))
            receive_rate = self._rate(identity.key, "receive", received, timestamp)
            transmit_rate = self._rate(identity.key, "transmit", transmitted, timestamp)
            status = self._status(name, current_stats)

            result[identity.key] = InterfaceSample(
                name=name,
                kind=metadata.kind,
                auxiliary=metadata.auxiliary,
                status=status,
                speed_supported=metadata.speed_supported,
                speed_mbps=speed if status == "Connected" else None,
                receive_rate=receive_rate,
                transmit_rate=transmit_rate,
                bytes_received=received,
                bytes_transmitted=transmitted,
            )

        removed_names = set(self._identities) - names
        for removed_name in removed_names:
            removed = self._identities.pop(removed_name)
            self._metadata.pop(removed.key, None)
        # A removed interface cannot contribute a later delta. Reappearance receives
        # a new generation key, so no stale capability or counter baseline is reused.
        self._baselines = {
            baseline_key: value
            for baseline_key, value in self._baselines.items()
            if baseline_key[0] in active_keys
        }
        return result

    def _interface_indexes(self) -> tuple[dict[str, int], bool]:
        try:
            entries = socket.if_nameindex()
        except OSError:
            return {}, False
        return {
            name: index
            for index, name in entries
            if isinstance(index, int) and index > 0 and isinstance(name, str) and name
        }, True

    @staticmethod
    def _interface_counters() -> tuple[dict[str, object], bool]:
        try:
            counters = psutil.net_io_counters(pernic=True, nowrap=False)
        except (OSError, psutil.Error):
            return {}, False
        if counters is None:
            return {}, False
        return dict(counters), True

    @staticmethod
    def _interface_stats() -> tuple[dict[str, object], bool]:
        try:
            stats = psutil.net_if_stats()
        except (OSError, psutil.Error):
            return {}, False
        if stats is None:
            return {}, False
        return dict(stats), True

    def _identity_for(self, name: str, ifindex: int | None) -> _Identity:
        previous = self._identities.get(name)
        replaced = (
            previous is not None
            and ifindex is not None
            and previous.ifindex is not None
            and ifindex != previous.ifindex
        )
        if previous is None or replaced:
            self._generation += 1
            identity = _Identity(self._generation, ifindex, f"net:{name}:{self._generation}")
            if previous is not None:
                self._metadata.pop(previous.key, None)
            self._identities[name] = identity
            return identity

        if previous.ifindex is None and ifindex is not None:
            previous = _Identity(previous.generation, ifindex, previous.key)
            self._identities[name] = previous
        return previous

    def _discover_metadata(
        self, name: str, ifindex: int | None, stats: object | None,
    ) -> tuple[_InterfaceMetadata, int | None]:
        path = self._sysfs_root / name
        link_type = _read_nonnegative_int(path / "type")
        link_index = ifindex or _read_nonnegative_int(path / "ifindex")
        peer_index = _read_nonnegative_int(path / "iflink")

        if link_type == 772:
            kind, auxiliary = "Loopback", True
        elif (path / "bridge").exists():
            kind, auxiliary = "Bridge", False
        elif link_type in _TUNNEL_LINK_TYPES or link_type == 65534 or (path / "tun_flags").exists():
            kind, auxiliary = "Tunnel", False
        elif (path / "wireless").exists() or (path / "phy80211").exists():
            kind, auxiliary = "Wi-Fi", False
        elif link_type == 1 and (path / "device").exists():
            kind, auxiliary = "Ethernet", False
        elif link_type == 1:
            # A distinct peer index is characteristic of a veth-style helper link.
            # Otherwise leave unknown virtual links visible by default.
            kind = "Virtual"
            auxiliary = peer_index is not None and link_index is not None and peer_index != link_index
        else:
            kind, auxiliary = "Unknown", False

        speed = _positive_int(getattr(stats, "speed", None)) if kind in {"Ethernet", "Wi-Fi"} else None
        if speed is None and kind in {"Ethernet", "Wi-Fi"}:
            speed = _positive_int(_read_nonnegative_int(path / "speed"))
        metadata = _InterfaceMetadata(kind, auxiliary, speed is not None)
        return metadata, speed

    def _current_speed(
        self, name: str, stats: object | None, metadata: _InterfaceMetadata,
    ) -> int | None:
        stats_speed = _positive_int(getattr(stats, "speed", None))
        if stats_speed is not None and metadata.kind in {"Ethernet", "Wi-Fi"}:
            metadata.speed_supported = True
            return stats_speed
        if not metadata.speed_supported:
            return None
        return _positive_int(_read_nonnegative_int(self._sysfs_root / name / "speed"))

    def _status(self, name: str, stats: object | None) -> str:
        isup = getattr(stats, "isup", None) if stats is not None else None
        if not isinstance(isup, bool):
            return "Unavailable"
        if not isup:
            return "Disconnected"

        path = self._sysfs_root / name
        operstate = (_read_text(path / "operstate") or "").lower()
        carrier = _read_text(path / "carrier")
        if carrier == "0" or operstate in _DOWN_STATES:
            return "Disconnected"
        if operstate == "dormant":
            return "Connecting"
        return "Connected"

    def _rate(self, key: str, direction: str, current: int | None, timestamp: float) -> float | None:
        baseline_key = (key, direction)
        if current is None:
            self._baselines.pop(baseline_key, None)
            return None

        previous = self._baselines.get(baseline_key)
        self._baselines[baseline_key] = (timestamp, current)
        if previous is None:
            return None

        previous_time, previous_count = previous
        elapsed = timestamp - previous_time
        if elapsed <= 0:
            return None
        if current >= previous_count:
            delta = current - previous_count
        elif previous_count >= _COUNTER_MODULUS - _COUNTER_WRAP_WINDOW and current < _COUNTER_WRAP_WINDOW:
            delta = _COUNTER_MODULUS - previous_count + current
        else:
            # A reset is a new baseline. Suppress this interval to avoid a spike.
            return None
        return delta / elapsed
