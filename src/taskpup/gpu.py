"""Read-only DRM discovery and capability-based GPU measurements."""

from dataclasses import dataclass
from pathlib import Path
import re


_DEVICE_METRICS = {
    "utilization": "gpu_busy_percent",
    "memory_used": "mem_info_vram_used",
    "memory_total": "mem_info_vram_total",
    "gtt_used": "mem_info_gtt_used",
    "gtt_total": "mem_info_gtt_total",
}
_TEMPERATURE_NAMES = {"edge": "GPU temperature", "junction": "Hotspot temperature", "mem": "Memory temperature"}
_HWMON_METRICS = (
    ("freq1_input", "Core clock", 1_000_000),
    ("freq2_input", "Memory clock", 1_000_000),
    ("power1_input", "Power", 1_000_000),
    ("power1_cap", "Power limit", 1_000_000),
    ("fan1_input", "Fan", 1),
)


def _exposed(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(errors="replace").strip() or None
    except OSError:
        return None


def number(path: Path, maximum: int | None = None) -> int | None:
    try:
        value = int(read_text(path) or "")
    except ValueError:
        return None
    return value if value >= 0 and (maximum is None or value <= maximum) else None


def pci_name(vendor: str, device: str, database: Path = Path('/usr/share/misc/pci.ids')) -> str | None:
    try:
        with database.open(errors='replace') as stream:
            active = False
            for line in stream:
                if not line.startswith(('\t', '#', ' ')):
                    active = line[:4].lower() == vendor.removeprefix('0x').lower()
                elif active and line.startswith('\t') and not line.startswith('\t\t'):
                    if line[1:5].lower() == device.removeprefix('0x').lower():
                        return line[5:].strip() or None
    except OSError:
        pass
    return None


@dataclass(frozen=True, slots=True)
class GpuSample:
    identity: str
    name: str
    driver: str
    utilization: float | None
    memory_used: int | None
    memory_total: int | None
    gtt_used: int | None
    gtt_total: int | None
    sensors: dict[str, float]
    capabilities: frozenset[str] = frozenset()

    @property
    def memory_percent(self) -> float | None:
        if self.memory_used is None or not self.memory_total or self.memory_used > self.memory_total:
            return None
        return 100 * self.memory_used / self.memory_total


class GpuDevice:
    def __init__(self, path: Path, identity: str, name: str, driver: str, vendor: str) -> None:
        self.path, self.identity, self.name, self.driver, self.vendor = path, identity, name, driver, vendor
        self.amd = vendor == "0x1002" and driver == "amdgpu"
        self.capabilities = {
            key for key, filename in _DEVICE_METRICS.items() if self.amd and _exposed(path / filename)
        }
        self.hwmons: dict[Path, set[int]] = {}
        if self.amd:
            for hw in sorted((path / "hwmon").glob("hwmon*")):
                self.hwmons[hw] = {index for index in range(1, 4) if _exposed(hw / f"temp{index}_input")}
                self.capabilities.update(key for filename, key, _ in _HWMON_METRICS if _exposed(hw / filename))
                if _exposed(hw / "power1_average"):
                    self.capabilities.add("Power")

    def sample(self) -> GpuSample:
        def metric(name: str, maximum: int | None = None) -> int | None:
            return number(self.path / _DEVICE_METRICS[name], maximum) if self.amd else None

        sensors: dict[str, float] = {}
        for hw, temperature_indexes in self.hwmons.items():
            for index in range(1, 4):
                label = read_text(hw / f'temp{index}_label')
                key = _TEMPERATURE_NAMES.get(label or "")
                if key and index in temperature_indexes:
                    self.capabilities.add(key)
                value = number(hw / f'temp{index}_input')
                if key and value is not None:
                    sensors[key] = value / 1000
            for filename, key, divisor in _HWMON_METRICS:
                value = number(hw / filename)
                if value is not None and (not filename.startswith('freq') or value > 0):
                    sensors[key] = value / divisor
            if 'Power' not in sensors:
                value = number(hw / 'power1_average')
                if value is not None:
                    sensors['Power'] = value / 1_000_000
        busy = metric("utilization", 100)
        return GpuSample(self.identity, self.name, self.driver, float(busy) if busy is not None else None,
                         metric("memory_used"), metric("memory_total"), metric("gtt_used"), metric("gtt_total"),
                         sensors, frozenset(self.capabilities))


def discover(drm: Path = Path('/sys/class/drm')) -> list[GpuDevice]:
    devices: list[GpuDevice] = []
    seen: set[str] = set()
    for card in sorted(drm.glob('card*')):
        if not re.fullmatch(r'card\d+', card.name):
            continue
        try:
            path = (card / 'device').resolve(strict=True)
        except OSError:
            continue
        identity = str(path)
        if identity in seen:
            continue
        seen.add(identity)
        vendor, device = read_text(path / 'vendor'), read_text(path / 'device')
        if not vendor or not device:
            continue
        try:
            driver = (path / 'driver').resolve(strict=True).name
        except OSError:
            driver = 'Unknown'
        name = read_text(path / 'product_name') or pci_name(vendor, device) or f'GPU {vendor}:{device}'
        devices.append(GpuDevice(path, identity, name, driver, vendor.lower()))
    return devices
