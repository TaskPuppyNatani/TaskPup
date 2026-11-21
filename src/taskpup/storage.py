"""Read-only Linux block-device and local filesystem sampling."""

from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import stat


PROC_DISKSTATS = Path("/proc/diskstats")
PROC_MOUNTINFO = Path("/proc/self/mountinfo")
SYS_BLOCK = Path("/sys/class/block")
SYS_BTRFS = Path("/sys/fs/btrfs")
DEV_ROOT = Path("/dev")

_SECTOR_BYTES = 512
_DISCOVERY_INTERVAL = 5.0
_TEMP_INPUT = re.compile(r"temp\d+_input\Z")


@dataclass(frozen=True, slots=True)
class DiskSample:
    name: str
    label: str
    kind: str
    capacity: int | None
    temperature_supported: bool
    temperature_c: float | None
    read_rate: float | None
    write_rate: float | None
    activity: float | None
    bytes_read: int | None
    bytes_written: int | None
    activity_supported: bool = False


@dataclass(frozen=True, slots=True)
class Filesystem:
    mountpoint: str
    fstype: str
    total: int | None
    used: int | None
    available: int | None
    percent: float | None


@dataclass(frozen=True, slots=True)
class StorageSample:
    timestamp: float
    devices: dict[str, DiskSample]
    filesystems: tuple[Filesystem, ...]
    filesystems_available: bool = True


@dataclass(frozen=True, slots=True)
class _DiskCounters:
    name: str
    read_sectors: int
    write_sectors: int
    io_ms: int


@dataclass(frozen=True, slots=True)
class _Mount:
    major: int
    minor: int
    root: str
    mountpoint: str
    fstype: str
    source: str

    @property
    def devnum(self) -> tuple[int, int]:
        return self.major, self.minor


@dataclass(frozen=True, slots=True)
class _DeviceInfo:
    identity: str
    key: tuple[int, int, str]
    major: int
    minor: int
    name: str
    label: str
    kind: str
    sys_path: Path
    capacity: int | None
    temperature_path: Path | None
    temperature_supported: bool
    activity_supported: bool
    dependencies: frozenset[tuple[int, int]]

    @property
    def devnum(self) -> tuple[int, int]:
        return self.major, self.minor


@dataclass(frozen=True, slots=True)
class _CounterState:
    read_sectors: int | None
    write_sectors: int | None
    io_ms: int | None
    timestamp: float


@dataclass(frozen=True, slots=True)
class _FilesystemCache:
    timestamp: float
    filesystem: Filesystem


def _read_text(path: Path) -> str | None:
    try:
        value = path.read_text(errors="replace").strip()
    except OSError:
        return None
    return value or None


def _nonnegative_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _signed_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _parse_devnum(value: str | None) -> tuple[int, int] | None:
    if value is None:
        return None
    parts = value.split(":", 1)
    if len(parts) != 2:
        return None
    major, minor = _nonnegative_int(parts[0]), _nonnegative_int(parts[1])
    return (major, minor) if major is not None and minor is not None else None


def _read_diskstats() -> tuple[dict[tuple[int, int], _DiskCounters] | None, tuple[tuple[int, int, str], ...] | None]:
    try:
        lines = PROC_DISKSTATS.read_text(errors="replace").splitlines()
    except OSError:
        return None, None

    counters: dict[tuple[int, int], _DiskCounters] = {}
    topology: list[tuple[int, int, str]] = []
    for line in lines:
        fields = line.split()
        if len(fields) < 14:
            continue
        major, minor = _nonnegative_int(fields[0]), _nonnegative_int(fields[1])
        name = fields[2]
        try:
            values = [int(value) for value in fields[3:14]]
        except ValueError:
            continue
        if major is None or minor is None or any(value < 0 for value in values):
            continue
        devnum = (major, minor)
        counters[devnum] = _DiskCounters(name, values[2], values[6], values[9])
        topology.append((major, minor, name))
    return counters, tuple(sorted(topology))


def _decode_mount_field(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _read_mountinfo() -> tuple[list[_Mount] | None, tuple[tuple[int, int, str, str, str, str], ...] | None]:
    try:
        lines = PROC_MOUNTINFO.read_text(errors="replace").splitlines()
    except OSError:
        return None, None

    mounts: list[_Mount] = []
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if separator < 6 or separator + 2 >= len(fields):
            continue
        devnum = _parse_devnum(fields[2])
        if devnum is None:
            continue
        mounts.append(
            _Mount(
                devnum[0], devnum[1], _decode_mount_field(fields[3]), _decode_mount_field(fields[4]),
                fields[separator + 1], _decode_mount_field(fields[separator + 2]),
            )
        )
    if not mounts:
        return None, None
    signature = tuple(
        sorted((mount.major, mount.minor, mount.root, mount.mountpoint, mount.fstype, mount.source) for mount in mounts)
    )
    return mounts, signature


def _block_names() -> tuple[str, ...] | None:
    try:
        entries = tuple(SYS_BLOCK.iterdir())
    except OSError:
        return None
    signature: list[str] = []
    for entry in entries:
        try:
            path = entry.resolve(strict=True)
        except OSError:
            signature.append(f"{entry.name}:missing")
            continue
        signature.append(f"{entry.name}:{_read_text(path / 'diskseq') or ''}")
    return tuple(sorted(signature))


def _read_capacity(path: Path) -> int | None:
    sectors = _nonnegative_int(_read_text(path / "size"))
    return sectors * _SECTOR_BYTES if sectors is not None else None


def _temperature_path(path: Path) -> Path | None:
    """Find a sensor exported below this block device's own hwmon directory."""
    device = path / "device"
    sensors: set[Path] = set()
    for pattern in ("hwmon*/temp*_input", "hwmon/hwmon*/temp*_input"):
        try:
            sensors.update(
                candidate for candidate in device.glob(pattern) if _TEMP_INPUT.fullmatch(candidate.name)
            )
        except OSError:
            continue
    if not sensors:
        return None

    def rank(candidate: Path) -> tuple[int, str]:
        label = (_read_text(candidate.with_name(f"{candidate.stem}_label")) or "").lower()
        if label == "composite":
            priority = 0
        elif candidate.name == "temp1_input":
            priority = 1
        else:
            priority = 2
        return priority, str(candidate)

    return min(sensors, key=rank)


def _read_temperature(path: Path | None) -> float | None:
    if path is None:
        return None
    raw = _signed_int(_read_text(path))
    if raw is None or raw < -273_150 or raw > 1_000_000:
        return None
    value = raw / 1000.0
    return value if math.isfinite(value) else None


def _device_label(name: str, kind: str, path: Path, by_devnum: dict[tuple[int, int], _DeviceInfo]) -> str:
    mapped_name = _read_text(path / "dm" / "name")
    if mapped_name:
        return f"{mapped_name} ({name})"
    raid_level = _read_text(path / "md" / "level")
    if raid_level:
        return f"{raid_level.upper()} array ({name})"

    model = _read_text(path / "device" / "model")
    vendor = _read_text(path / "device" / "vendor")
    if kind == "Partition":
        parent_dev = _parse_devnum(_read_text(path.parent / "dev"))
        parent = by_devnum.get(parent_dev) if parent_dev is not None else None
        parent_model = parent.label.split(" (", 1)[0] if parent is not None else None
        if parent_model is None and parent is not None:
            parent_model = " ".join(
                part for part in (
                    _read_text(parent.sys_path / "device" / "vendor"),
                    _read_text(parent.sys_path / "device" / "model"),
                ) if part
            ) or None
        if parent_model:
            return f"{parent_model} partition ({name})"
        parent_model = " ".join(
            part for part in (
                _read_text(path.parent / "device" / "vendor"),
                _read_text(path.parent / "device" / "model"),
            ) if part
        ) or None
        if parent_model:
            return f"{parent_model} partition ({name})"
    identity = " ".join(part for part in (vendor, model) if part)
    return f"{identity} ({name})" if identity else f"{name} ({kind})"


def _counter_delta(previous: int | None, current: int | None) -> int | None:
    if previous is None or current is None:
        return None
    if current >= previous:
        return current - previous
    # Only infer rollover close to the counter boundary. A reset of a large
    # ordinary counter must not be converted into a large transfer.
    window = 1 << 22
    for bits in (64, 32):
        modulus = 1 << bits
        if modulus - window <= previous < modulus and current < window:
            return modulus - previous + current
    return None


class StorageSampler:
    """Sample local block devices and mounted filesystems without shell tools.

    ``timestamp`` passed to :meth:`sample` must use a monotonic clock. Device
    discovery is cached for five seconds and refreshed sooner when block or
    mount topology changes. Filesystem space is collected independently from
    block-device I/O and is never attributed to a particular device.
    """

    def __init__(self) -> None:
        self._device_cache: dict[str, _DeviceInfo] = {}
        self._all_devices: dict[tuple[int, int], _DeviceInfo] = {}
        self._generation = 0
        self._counter_states: dict[str, _CounterState] = {}
        self._filesystem_cache: dict[tuple[tuple[object, ...], str], _FilesystemCache] = {}
        self._last_discovery_time: float | None = None
        self._topology_signature: tuple[object, ...] | None = None
        self._last_mounts: list[_Mount] = []
        self._btrfs_uuid_by_dev: dict[tuple[int, int], str] = {}

    def reset(self) -> None:
        """Clear I/O rate baselines while retaining discovery and capability caches."""
        self._counter_states.clear()

    def sample(self, timestamp: float) -> StorageSample:
        diskstats, disk_signature = _read_diskstats()
        mounts, mount_signature = _read_mountinfo()
        block_signature = _block_names()
        valid_timestamp = timestamp if math.isfinite(timestamp) else float("nan")
        signature: tuple[object, ...] = (disk_signature, mount_signature, block_signature)
        elapsed_since_scan = (
            float("inf") if self._last_discovery_time is None else timestamp - self._last_discovery_time
        )
        topology_changed = self._topology_signature is None or signature != self._topology_signature
        refresh = topology_changed or elapsed_since_scan >= _DISCOVERY_INTERVAL or elapsed_since_scan < 0
        if refresh and block_signature is not None:
            if mounts is not None:
                self._last_mounts = mounts
            discovered = self._discover_devices(self._last_mounts, diskstats)
            if discovered is not None:
                self._device_cache, self._all_devices, self._btrfs_uuid_by_dev = discovered
                retained = set(self._device_cache)
                self._counter_states = {
                    identity: state
                    for identity, state in self._counter_states.items()
                    if identity in retained
                }
                self._last_discovery_time = timestamp
                self._topology_signature = signature
        elif self._topology_signature is None:
            self._topology_signature = signature

        devices: dict[str, DiskSample] = {}
        for identity, info in self._device_cache.items():
            counters = diskstats.get(info.devnum) if diskstats is not None else None
            devices[identity] = self._sample_device(info, counters, valid_timestamp)

        filesystems = ()
        if mounts is not None:
            filesystems = self._filesystems(mounts, self._all_devices, self._btrfs_uuid_by_dev, timestamp)
        return StorageSample(timestamp, devices, filesystems, filesystems_available=mounts is not None)

    @staticmethod
    def _mount_device(
        mount: _Mount,
        devices: dict[tuple[int, int], _DeviceInfo],
        by_name: dict[str, tuple[int, int]],
    ) -> tuple[int, int] | None:
        if mount.devnum in devices:
            return mount.devnum
        if not mount.source.startswith("/dev/"):
            return None
        source = Path(mount.source)
        try:
            source_stat = (DEV_ROOT / source.relative_to("/dev")).stat()
        except OSError:
            # A sandbox may expose sysfs but omit its corresponding /dev nodes.
            return by_name.get(source.name) if source.parent == Path("/dev") else None
        if not stat.S_ISBLK(source_stat.st_mode):
            return None
        devnum = (os.major(source_stat.st_rdev), os.minor(source_stat.st_rdev))
        return devnum if devnum in devices else None

    def _discover_devices(
        self,
        mounts: list[_Mount],
        diskstats: dict[tuple[int, int], _DiskCounters] | None,
    ) -> tuple[
        dict[str, _DeviceInfo], dict[tuple[int, int], _DeviceInfo], dict[tuple[int, int], str]
    ] | None:
        try:
            entries = sorted(SYS_BLOCK.iterdir(), key=lambda path: path.name)
        except OSError:
            return None

        previous_by_key = {info.key: info for info in self._all_devices.values()}
        raw: list[tuple[tuple[int, int, str], int, int, str, str, Path, bool, frozenset[tuple[int, int]]]] = []
        for entry in entries:
            try:
                path = entry.resolve(strict=True)
            except OSError:
                continue
            devnum = _parse_devnum(_read_text(path / "dev"))
            if devnum is None or devnum in {item[1:3] for item in raw}:
                continue
            name = entry.name
            partition = _nonnegative_int(_read_text(path / "partition")) is not None
            dm_name = _read_text(path / "dm" / "name")
            md_level = _read_text(path / "md" / "level")
            has_device = (path / "device").exists()
            virtual_path = "virtual" in path.parts
            if partition:
                kind = "Partition"
            elif md_level:
                kind = "RAID"
            elif dm_name or name.startswith(("loop", "ram", "zram", "nbd")) or virtual_path or not has_device:
                kind = "Logical"
            else:
                path_parts = {part.lower() for part in path.parts}
                transport = (_read_text(path / "device" / "transport") or "").lower()
                if any(part.startswith("usb") for part in path_parts) or transport == "usb":
                    kind = "USB storage"
                elif "nvme" in path_parts or "nvme" in transport:
                    kind = "NVMe SSD"
                elif transport in {"sata", "ata"} or any(
                    part.startswith(("ata", "sata")) for part in path_parts
                ):
                    rotational = _nonnegative_int(_read_text(path / "queue" / "rotational"))
                    kind = "SATA HDD" if rotational == 1 else "SATA SSD" if rotational == 0 else "SATA drive"
                else:
                    kind = "Physical drive"
            diskseq = _read_text(path / "diskseq")
            identity_path = f"{path}|diskseq={diskseq}" if diskseq is not None else str(path)
            key = (devnum[0], devnum[1], identity_path)
            parent = path.parent if partition else None
            dependencies: set[tuple[int, int]] = set()
            if parent is not None:
                parent_num = _parse_devnum(_read_text(parent / "dev"))
                if parent_num is not None:
                    dependencies.add(parent_num)
            try:
                slave_entries = sorted((path / "slaves").iterdir(), key=lambda child: child.name)
            except OSError:
                slave_entries = []
            for slave in slave_entries:
                try:
                    slave_path = slave.resolve(strict=True)
                except OSError:
                    continue
                slave_num = _parse_devnum(_read_text(slave_path / "dev"))
                if slave_num is not None:
                    dependencies.add(slave_num)
            raw.append((key, devnum[0], devnum[1], name, kind, path, partition, frozenset(dependencies)))

        provisional: dict[tuple[int, int], _DeviceInfo] = {}
        for item in raw:
            key, major, minor, name, kind, path, _, device_dependencies = item
            prior = previous_by_key.get(key)
            if prior is not None:
                identity = prior.identity
            else:
                self._generation += 1
                identity = f"{major}:{minor}@{path}#{self._generation}"
            if diskstats is not None and (major, minor) in diskstats:
                activity_supported = True
            else:
                activity_supported = prior.activity_supported if prior is not None else False
            temperature_path = _temperature_path(path) or (prior.temperature_path if prior is not None else None)
            temperature_supported = temperature_path is not None or (
                prior.temperature_supported if prior is not None else False
            )
            provisional[(major, minor)] = _DeviceInfo(
                identity, key, major, minor, name, "", kind, path, _read_capacity(path), temperature_path,
                temperature_supported, activity_supported, device_dependencies,
            )

        all_devices = {
            devnum: _DeviceInfo(
                info.identity, info.key, info.major, info.minor, info.name,
                _device_label(info.name, info.kind, info.sys_path, provisional), info.kind, info.sys_path,
                info.capacity, info.temperature_path, info.temperature_supported,
                info.activity_supported, info.dependencies,
            )
            for devnum, info in provisional.items()
        }

        by_name = {info.name: devnum for devnum, info in all_devices.items()}
        mounted_nums = {
            devnum for mount in mounts
            if (devnum := self._mount_device(mount, all_devices, by_name)) is not None
        }
        candidate_nums = {
            devnum for devnum, info in all_devices.items()
            if info.kind not in {"Partition", "Logical", "RAID"}
        }
        for devnum in mounted_nums:
            info = all_devices[devnum]
            if info.kind == "Partition":
                candidate_nums.update(info.dependencies)
            elif info.kind in {"Logical", "RAID"}:
                candidate_nums.add(devnum)
            else:
                candidate_nums.add(devnum)
        selected_nums = {devnum for devnum in candidate_nums if devnum in all_devices}
        selected = {
            info.identity: info for devnum, info in all_devices.items() if devnum in selected_nums
        }

        btrfs_uuid_by_dev: dict[tuple[int, int], str] = {}
        try:
            uuid_dirs = sorted(SYS_BTRFS.iterdir(), key=lambda path: path.name)
        except OSError:
            uuid_dirs = []
        for uuid_dir in uuid_dirs:
            try:
                dev_files = sorted((uuid_dir / "devices").glob("*"), key=lambda path: path.name)
            except OSError:
                continue
            for dev_file in dev_files:
                devnum = _parse_devnum(_read_text(dev_file / "dev"))
                if devnum is not None:
                    btrfs_uuid_by_dev[devnum] = uuid_dir.name
        return selected, all_devices, btrfs_uuid_by_dev

    def _sample_device(
        self, info: _DeviceInfo, counters: _DiskCounters | None, timestamp: float
    ) -> DiskSample:
        previous = self._counter_states.get(info.identity)
        read_sectors = counters.read_sectors if counters is not None else None
        write_sectors = counters.write_sectors if counters is not None else None
        io_ms = counters.io_ms if counters is not None else None
        read_delta = _counter_delta(previous.read_sectors, read_sectors) if previous is not None else None
        write_delta = _counter_delta(previous.write_sectors, write_sectors) if previous is not None else None
        busy_delta = _counter_delta(previous.io_ms, io_ms) if previous is not None else None

        elapsed = timestamp - previous.timestamp if previous is not None else float("nan")
        valid_elapsed = math.isfinite(elapsed) and elapsed > 0
        read_rate = read_delta * _SECTOR_BYTES / elapsed if read_delta is not None and valid_elapsed else None
        write_rate = write_delta * _SECTOR_BYTES / elapsed if write_delta is not None and valid_elapsed else None
        activity = min(100.0, busy_delta * 100.0 / (elapsed * 1000.0)) if busy_delta is not None and valid_elapsed else None

        self._counter_states[info.identity] = _CounterState(
            read_sectors, write_sectors, io_ms, timestamp,
        )
        bytes_read = read_sectors * _SECTOR_BYTES if read_sectors is not None else None
        bytes_written = write_sectors * _SECTOR_BYTES if write_sectors is not None else None

        return DiskSample(
            info.name, info.label, info.kind, info.capacity, info.temperature_supported,
            _read_temperature(info.temperature_path), read_rate, write_rate, activity, bytes_read,
            bytes_written, info.activity_supported,
        )

    def _filesystems(
        self,
        mounts: list[_Mount],
        devices: dict[tuple[int, int], _DeviceInfo],
        btrfs_uuid_by_dev: dict[tuple[int, int], str],
        timestamp: float,
    ) -> tuple[Filesystem, ...]:
        by_name = {info.name: devnum for devnum, info in devices.items()}
        representatives: dict[tuple[object, ...], tuple[_Mount, tuple[int, int]]] = {}
        for mount in mounts:
            devnum = self._mount_device(mount, devices, by_name)
            if devnum is None:
                continue
            if mount.fstype.lower() == "btrfs" and devnum in btrfs_uuid_by_dev:
                identity: tuple[object, ...] = ("btrfs", btrfs_uuid_by_dev[devnum])
            elif mount.fstype.lower() == "btrfs":
                # Without a visible Btrfs UUID, only merge mounts backed by the
                # same exact local block device; do not guess across devices.
                identity = ("btrfs-device", *devnum)
            else:
                identity = (*devnum, mount.fstype.lower())
            previous = representatives.get(identity)
            rank = (mount.mountpoint.count("/"), len(mount.mountpoint), mount.mountpoint)
            old_rank = (
                previous[0].mountpoint.count("/"), len(previous[0].mountpoint), previous[0].mountpoint
            ) if previous is not None else None
            if old_rank is None or rank < old_rank:
                representatives[identity] = (mount, devnum)

        result: list[Filesystem] = []
        active_cache_keys: set[tuple[tuple[object, ...], str]] = set()
        for identity, (mount, _) in sorted(
            representatives.items(), key=lambda item: item[1][0].mountpoint
        ):
            cache_key = (identity, mount.mountpoint)
            active_cache_keys.add(cache_key)
            cached = self._filesystem_cache.get(cache_key)
            age = timestamp - cached.timestamp if cached is not None else float("inf")
            if cached is not None and math.isfinite(age) and 0 <= age < _DISCOVERY_INTERVAL:
                filesystem = cached.filesystem
            else:
                try:
                    stats = os.statvfs(mount.mountpoint)
                except OSError:
                    total = used = available = None
                    percent = None
                else:
                    block_size = getattr(stats, "f_frsize", 0) or getattr(stats, "f_bsize", 0)
                    blocks = getattr(stats, "f_blocks", -1)
                    free_blocks = getattr(stats, "f_bfree", -1)
                    available_blocks = getattr(stats, "f_bavail", -1)
                    if block_size <= 0 or blocks < 0 or free_blocks < 0 or free_blocks > blocks:
                        total = used = None
                    else:
                        total = int(blocks * block_size)
                        used = int((blocks - free_blocks) * block_size)
                    available = (
                        int(available_blocks * block_size)
                        if block_size > 0 and available_blocks >= 0 else None
                    )
                    percent = (
                        100.0 * used / total
                        if total is not None and total > 0 and used is not None else None
                    )
                filesystem = Filesystem(mount.mountpoint, mount.fstype, total, used, available, percent)
                self._filesystem_cache[cache_key] = _FilesystemCache(timestamp, filesystem)
            result.append(filesystem)
        self._filesystem_cache = {
            key: cached for key, cached in self._filesystem_cache.items() if key in active_cache_keys
        }
        return tuple(result)
