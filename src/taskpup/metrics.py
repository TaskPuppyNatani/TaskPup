"""System-wide Linux resource measurements."""

from dataclasses import dataclass
import math
from pathlib import Path
import time

import psutil


PROC = Path("/proc")
_CPU_FIELDS = 8  # user through steal; guest fields duplicate user/nice.
_CPU_SENSOR_NAMES = ("cpu", "coretemp", "k10temp", "zenpower", "processor")
_CPU_SENSOR_LABELS = ("cpu", "package", "tdie", "tctl", "processor")
_NON_CPU_SENSOR_NAMES = ("gpu", "nvme", "drive", "disk", "ssd", "motherboard", "chipset", "vrm")


@dataclass(frozen=True, slots=True)
class MemorySample:
    total: int
    available: int
    used: int
    percent: float | None
    cached: int | None
    buffers: int | None


@dataclass(frozen=True, slots=True)
class SwapSample:
    total: int
    used: int
    available: int
    percent: float | None
    in_per_second: float | None
    out_per_second: float | None


@dataclass(frozen=True, slots=True)
class SystemSample:
    timestamp: float
    cpu_percent: float | None
    logical_percent: dict[int, float | None]
    cpu_model: str | None
    frequency_mhz: float | None
    physical_cores: int | None
    logical_cores: int | None
    temperature_c: float | None
    uptime_s: float | None
    memory: MemorySample | None
    swap: SwapSample | None


_CpuTimes = tuple[int, ...]


def _parse_cpu_line(values: list[str]) -> _CpuTimes | None:
    if len(values) < 4:
        return None
    try:
        parsed = [int(value) for value in values[:_CPU_FIELDS]]
    except ValueError:
        return None
    parsed.extend([0] * (_CPU_FIELDS - len(parsed)))
    return tuple(parsed)


def _cpu_delta_percent(previous: _CpuTimes, current: _CpuTimes) -> float | None:
    if any(now < before for before, now in zip(previous, current)):
        return None
    deltas = [now - before for before, now in zip(previous, current)]
    elapsed = sum(deltas)
    idle = deltas[3] + deltas[4]
    if elapsed <= 0 or idle < 0 or idle > elapsed:
        return None
    return 100.0 * (elapsed - idle) / elapsed


def _number(value: object) -> float | None:
    try:
        result = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return None
    return result if math.isfinite(result) else None


class SystemSampler:
    """Collect system metrics while keeping only the previous delta baselines."""

    def __init__(self) -> None:
        self._previous_cpu: _CpuTimes | None = None
        self._previous_logical: dict[int, _CpuTimes] = {}
        self._previous_cpu_ids: frozenset[int] = frozenset()
        self._previous_swap: tuple[int, int] | None = None
        self._previous_swap_time: float | None = None

        self._static_loaded = False
        self._cpu_model: str | None = None
        self._physical_cores: int | None = None

    def reset(self) -> None:
        """Clear CPU and swap activity baselines."""
        self._previous_cpu = None
        self._previous_logical.clear()
        self._previous_cpu_ids = frozenset()
        self._previous_swap = None
        self._previous_swap_time = None

    def sample(self, *, detailed: bool = True) -> SystemSample:
        timestamp = time.monotonic()
        aggregate, logical = self._read_cpu_times()
        cpu_percent, logical_percent = self._cpu_percentages(aggregate, logical)
        memory = self._read_memory()
        swap = self._read_swap(timestamp)
        uptime = self._read_uptime()

        frequency: float | None = None
        temperature: float | None = None
        if detailed:
            self._discover_static_cpu()
            frequency = self._read_frequency()
            temperature = self._read_temperature()

        return SystemSample(
            timestamp=timestamp,
            cpu_percent=cpu_percent,
            logical_percent=logical_percent,
            cpu_model=self._cpu_model,
            frequency_mhz=frequency,
            physical_cores=self._physical_cores,
            logical_cores=len(logical) if logical else None,
            temperature_c=temperature,
            uptime_s=uptime,
            memory=memory,
            swap=swap,
        )

    @staticmethod
    def _read_cpu_times() -> tuple[_CpuTimes | None, dict[int, _CpuTimes]]:
        try:
            lines = (PROC / "stat").read_text(errors="replace").splitlines()
        except OSError:
            return None, {}

        aggregate: _CpuTimes | None = None
        logical: dict[int, _CpuTimes] = {}
        for line in lines:
            fields = line.split()
            if not fields:
                continue
            name = fields[0]
            if name == "cpu":
                aggregate = _parse_cpu_line(fields[1:])
            elif name.startswith("cpu") and name[3:].isdecimal():
                index = int(name[3:])
                counters = _parse_cpu_line(fields[1:])
                if counters is not None:
                    logical[index] = counters
        return aggregate, logical

    def _cpu_percentages(
        self,
        aggregate: _CpuTimes | None,
        logical: dict[int, _CpuTimes],
    ) -> tuple[float | None, dict[int, float | None]]:
        cpu_ids = frozenset(logical)
        aggregate_percent = None
        if (
            aggregate is not None
            and self._previous_cpu is not None
            and cpu_ids == self._previous_cpu_ids
        ):
            aggregate_percent = _cpu_delta_percent(self._previous_cpu, aggregate)

        logical_percent = {
            index: (
                _cpu_delta_percent(self._previous_logical[index], counters)
                if index in self._previous_logical
                else None
            )
            for index, counters in sorted(logical.items())
        }

        self._previous_cpu = aggregate
        self._previous_logical = logical
        self._previous_cpu_ids = cpu_ids
        return aggregate_percent, logical_percent

    @staticmethod
    def _read_memory() -> MemorySample | None:
        try:
            value = psutil.virtual_memory()
            total = int(value.total)
            available = int(value.available)
            percent = _number(getattr(value, "percent", None))
            cached_value = getattr(value, "cached", None)
            buffers_value = getattr(value, "buffers", None)
            return MemorySample(
                total=total,
                available=available,
                used=total - available,
                percent=percent,
                cached=int(cached_value) if cached_value is not None else None,
                buffers=int(buffers_value) if buffers_value is not None else None,
            )
        except Exception:
            return None

    def _read_swap(self, timestamp: float) -> SwapSample | None:
        try:
            value = psutil.swap_memory()
            total = int(value.total)
            used = int(value.used)
            available = int(value.free)
            reported_percent = _number(getattr(value, "percent", None))
        except Exception:
            self._previous_swap = None
            self._previous_swap_time = None
            return None

        try:
            incoming = int(value.sin)
            outgoing = int(value.sout)
        except Exception:
            incoming = outgoing = None

        if total <= 0:
            self._previous_swap = None
            self._previous_swap_time = None
            return SwapSample(total, used, available, None, None, None)

        percent = reported_percent
        in_rate: float | None = None
        out_rate: float | None = None
        # psutil uses (0, 0) when Linux /proc/vmstat omits either swap counter.
        counters_available = self._swap_counters_available(incoming, outgoing)
        if (
            counters_available
            and incoming is not None
            and outgoing is not None
            and self._previous_swap is not None
            and self._previous_swap_time is not None
        ):
            elapsed = timestamp - self._previous_swap_time
            old_in, old_out = self._previous_swap
            if elapsed > 0 and incoming >= old_in and outgoing >= old_out:
                in_rate = (incoming - old_in) / elapsed
                out_rate = (outgoing - old_out) / elapsed

        if not counters_available:
            self._previous_swap = None
            self._previous_swap_time = None
        else:
            assert incoming is not None and outgoing is not None
            self._previous_swap = (incoming, outgoing)
            self._previous_swap_time = timestamp
        return SwapSample(total, used, available, percent, in_rate, out_rate)

    @staticmethod
    def _swap_counters_available(incoming: int | None, outgoing: int | None) -> bool:
        if incoming is None or outgoing is None or incoming < 0 or outgoing < 0:
            return False
        if incoming != 0 or outgoing != 0:
            return True

        # psutil reports (0, 0) both for genuine zero activity and when Linux
        # omits either vmstat key. Confirm only this ambiguous case.
        found: set[str] = set()
        try:
            with (PROC / "vmstat").open(errors="replace") as stream:
                for line in stream:
                    fields = line.split()
                    if len(fields) < 2 or fields[0] not in {"pswpin", "pswpout"}:
                        continue
                    try:
                        int(fields[1])
                    except ValueError:
                        continue
                    found.add(fields[0])
                    if len(found) == 2:
                        return True
        except OSError:
            return False
        return False

    @staticmethod
    def _read_uptime() -> float | None:
        try:
            value = float((PROC / "uptime").read_text().split()[0])
        except (OSError, ValueError, IndexError):
            return None
        return value if math.isfinite(value) and value >= 0 else None

    def _discover_static_cpu(self) -> None:
        if self._static_loaded:
            return
        self._static_loaded = True
        physical: set[tuple[str, str]] = set()
        try:
            cpuinfo = (PROC / "cpuinfo").read_text(errors="replace")
        except OSError:
            cpuinfo = ""

        for block in cpuinfo.split("\n\n"):
            fields: dict[str, str] = {}
            for line in block.splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    fields[key.strip().lower()] = value.strip()
            if self._cpu_model is None:
                for key in ("model name", "hardware", "processor", "cpu model"):
                    candidate = fields.get(key)
                    if candidate and not (key == "processor" and candidate.isdecimal()):
                        self._cpu_model = candidate
                        break
            core_id = fields.get("core id")
            if core_id is not None:
                physical.add((fields.get("physical id", "0"), core_id))

        if physical:
            self._physical_cores = len(physical)
        else:
            try:
                self._physical_cores = psutil.cpu_count(logical=False)
            except Exception:
                self._physical_cores = None

    @staticmethod
    def _read_frequency() -> float | None:
        try:
            frequency = psutil.cpu_freq()
        except Exception:
            return None
        return _number(getattr(frequency, "current", None)) if frequency is not None else None

    @staticmethod
    def _read_temperature() -> float | None:
        try:
            sensors = psutil.sensors_temperatures(fahrenheit=False)
        except Exception:
            return None

        readings: list[float] = []
        for sensor_name, entries in sensors.items():
            name = sensor_name.lower()
            cpu_group = any(token in name for token in _CPU_SENSOR_NAMES)
            for entry in entries:
                label = str(getattr(entry, "label", "") or "").lower()
                description = f"{name} {label}"
                if any(token in description for token in _NON_CPU_SENSOR_NAMES):
                    continue
                if not (
                    cpu_group or any(token in label for token in _CPU_SENSOR_LABELS)
                ):
                    continue
                current = _number(getattr(entry, "current", None))
                if current is not None:
                    readings.append(current)
        return max(readings) if readings else None
