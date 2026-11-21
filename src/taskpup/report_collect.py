"""Read-only collection of a privacy-aware system diagnostic snapshot.

The collector is deliberately data-only: it does not create or inspect Qt GUI
objects. Callers may pass screen details captured on the GUI thread through
``screen_info``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
import importlib.metadata
import ipaddress
import math
import os
from pathlib import Path
import platform as host_platform
import psutil
import re
import socket
import struct
import time
from typing import Any

from taskpup.gpu import discover as discover_gpus
from taskpup.metrics import SystemSampler
from taskpup.network import NetworkSampler
from taskpup.storage import StorageSample, StorageSampler


SECTIONS: dict[str, str] = {
    "os": "Operating system",
    "desktop": "Desktop environment",
    "cpu": "CPU",
    "memory": "Memory",
    "graphics": "Graphics hardware",
    "storage": "Storage hardware",
    "filesystems": "Filesystems and mounts",
    "network": "Network configuration",
    "sensors": "Hardware sensors",
}

PROC_ROOT = Path("/proc")
SYS_ROOT = Path("/sys")
FSTAB_PATH = Path("/etc/fstab")
RESOLV_CONF = Path("/etc/resolv.conf")
_MAX_TEXT_BYTES = 256 * 1024
_MAX_RECORDS = 2048
_SECRET_KEY = re.compile(
    r"(?:password|passwd|pwd|token|secret|credential|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|authorization|auth[_-]?token)",
    re.IGNORECASE,
)
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|token|secret|credentials?|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret)\s*[=:]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_URI_CREDENTIALS = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^\s/@:]+(?::[^\s/@]*)?@")
_UNC_CREDENTIALS = re.compile(r"(?<![A-Za-z0-9._+-])[^/\s:@]+:[^/\s@]*@")
_AUTH_HEADER = re.compile(r"(?i)(\b(?:authorization|proxy-authorization)\s*:\s*(?:basic|bearer)\s+)[^\s,;]+")
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?-----END [^-\n]*PRIVATE KEY-----",
    re.DOTALL,
)
_CMDLINE_SAFE_FLAGS = {
    "quiet", "splash", "ro", "rw", "nomodeset", "nosplash", "debug", "earlyprintk",
}
_CMDLINE_SAFE_VALUES = {
    "BOOT_IMAGE", "root", "loglevel", "systemd.show_status", "mitigations", "iommu", "intel_iommu",
    "amd_iommu", "transparent_hugepage", "usbcore.autosuspend", "elevator", "rootflags",
}
_FSTAB_SAFE_OPTIONS = {
    "defaults", "ro", "rw", "suid", "nosuid", "dev", "nodev", "exec", "noexec",
    "sync", "async", "atime", "noatime", "diratime", "nodiratime", "relatime",
    "strictatime", "lazytime", "discard", "nodiscard", "nofail", "auto", "noauto",
    "user", "users", "nouser", "owner", "bind", "rbind", "move", "remount",
    "loop", "flush", "utf8", "shortname", "casefold", "errors", "data", "barrier",
    "commit", "journal_checksum", "compress", "compress-force", "subvol", "subvolid",
    "uid", "gid", "umask", "fmask", "dmask", "iocharset", "codepage", "vers",
    "proto", "port", "addr", "server", "timeo", "retrans", "hard", "soft", "intr", "nointr",
    "x-systemd.automount", "x-systemd.device-timeout", "x-systemd.idle-timeout",
    "x-systemd.mount-timeout", "x-systemd.requires", "x-systemd.after", "x-systemd.before",
}


def _read_text(path: Path, limit: int = _MAX_TEXT_BYTES) -> str | None:
    try:
        with path.open("rb") as stream:
            content = stream.read(limit + 1)
    except OSError:
        return None
    if len(content) > limit:
        content = content[:limit]
    return content.decode("utf-8", errors="replace")


def _scrub_secrets(value: str) -> str:
    """Remove common inline credentials without depending on privacy mode."""
    value = _PRIVATE_KEY_BLOCK.sub("<redacted-private-key>", value)
    value = _URI_CREDENTIALS.sub(r"\1<redacted>@", value)
    value = _UNC_CREDENTIALS.sub("<redacted>@", value)
    value = _AUTH_HEADER.sub(r"\1<redacted>", value)
    return _ASSIGNMENT_SECRET.sub(r"\1<redacted>", value)


class _Privacy:
    """Consistent pseudonyms for identifiers within one report snapshot."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self._ids: dict[tuple[str, str], str] = {}
        self._counts: dict[str, int] = {}
        try:
            self._home = str(Path.home())
        except (RuntimeError, OSError):
            self._home = ""
        try:
            self._username = os.getlogin()
        except OSError:
            self._username = os.environ.get("USER", "")

    def mask(self, kind: str, value: str) -> str:
        if not self.enabled or not value:
            return _scrub_secrets(value)
        if re.fullmatch(rf"<{re.escape(kind)}-\d+>", value):
            return value
        key = (kind, value)
        if key not in self._ids:
            self._counts[kind] = self._counts.get(kind, 0) + 1
            self._ids[key] = f"<{kind}-{self._counts[kind]}>"
        return self._ids[key]

    def block_device(self, value: str) -> str:
        """Keep a disk and its partitions linked while hiding their names."""
        if not self.enabled:
            return _scrub_secrets(value)
        if re.fullmatch(r"<device-\d+>(?:-partition-\d+)?", value):
            return value
        name = value.removeprefix("/dev/")
        special = re.fullmatch(r"(nvme\d+n\d+|mmcblk\d+|loop\d+|md\d+|dm-\d+)(?:p(\d+))?", name)
        if special:
            base, partition = special.groups()
            masked = self.mask("device", base)
            return f"{masked}-partition-{partition}" if partition else masked
        match = re.fullmatch(r"([A-Za-z0-9_.+-]+?)(\d+)?", name)
        if not match:
            return self.mask("device", value)
        base, suffix = match.groups()
        masked = self.mask("device", base)
        if suffix:
            suffix_number = suffix.removeprefix("p")
            return f"{masked}-partition-{suffix_number}"
        return masked

    def sanitize_text(self, value: str) -> str:
        value = _scrub_secrets(value)
        if not self.enabled:
            return value
        if self._home:
            value = value.replace(self._home, "<home>")
        value = re.sub(r"(?i)(?<![A-Za-z0-9_.-])/home/[^/\s,:@]+", "<home>", value)
        value = re.sub(r"(?<![A-Za-z0-9_])/run/user/\d+", "/run/user/<uid>", value)
        if self._username:
            value = re.sub(rf"(?<![A-Za-z0-9_.-]){re.escape(self._username)}(?![A-Za-z0-9_.-])", self.mask("user", self._username), value)
        return value


def _sanitize(value: Any, privacy: _Privacy, key: str = "") -> Any:
    """Recursively scrub secrets and optionally pseudonymize known identifiers."""
    lowered = key.lower().replace("-", "_")
    if _SECRET_KEY.search(lowered):
        return "<redacted>"
    if isinstance(value, Mapping):
        named_secret = any(
            str(k).lower() in {"name", "option", "parameter"}
            and isinstance(v, str)
            and _SECRET_KEY.search(v)
            for k, v in value.items()
        )
        return {
            str(k): (
                "<redacted>"
                if named_secret and str(k).lower() in {"value", "setting", "current", "default"}
                else _sanitize(v, privacy, str(k))
            )
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_sanitize(item, privacy, key) for item in value]
    if not isinstance(value, str):
        return value

    clean = privacy.sanitize_text(value)
    if not privacy.enabled or not clean:
        return clean
    if lowered in {"hostname", "host_name", "host"}:
        return privacy.mask("host", clean)
    if lowered in {"username", "user_name", "owner", "user"}:
        return privacy.mask("user", clean)
    if lowered in {"home", "home_path", "homedir", "home_directory"}:
        return "<home>"
    if lowered in {"mountpoint", "mount_point", "mount_destination"}:
        return privacy.mask("mount", clean)
    if lowered in {"interface", "interface_name", "ifname"}:
        return privacy.mask("interface", clean)
    if lowered in {"mac", "mac_address", "hardware_address"}:
        return privacy.mask("mac", clean)
    if lowered in {"device_name", "partition_name"}:
        return privacy.block_device(clean)
    if lowered in {"name", "model"} and re.fullmatch(r"(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+(?:p\d+)?|mmcblk\d+(?:p\d+)?|loop\d+|dm-\d+|md\d+)", clean):
        return privacy.block_device(clean)
    if lowered in {"parent_device", "block_name"}:
        return privacy.block_device(clean)
    if lowered in {"identity", "hardware_identity", "pci_identity"}:
        if clean.startswith(("/sys/", "pci", "0000:")) or re.search(r"\b[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]\b", clean):
            return privacy.mask("hardware", clean)
    if lowered in {"uuid", "serial", "serial_number", "disk_uuid", "device_id", "identifier"}:
        return privacy.mask("identifier", clean)
    if lowered in {"device", "device_path", "source", "filesystem_source", "block_device", "parent_device"}:
        if clean.startswith("/dev/"):
            return privacy.block_device(clean.removeprefix("/dev/"))
        if clean.lower().startswith("uuid="):
            return privacy.mask("uuid", clean[5:])
        if clean.lower().startswith("partuuid="):
            return privacy.mask("uuid", clean[9:])
        if clean.lower().startswith("label="):
            return privacy.mask("label", clean[6:])
        if clean.lower().startswith("partlabel="):
            return privacy.mask("label", clean[10:])
        if lowered == "source" and (
            clean.startswith("//")
            or re.match(r"^(?:\[[0-9a-fA-F:.%]+\]|[^/\s:]+):/", clean)
        ):
            return privacy.mask("source", clean)
        if lowered == "source" and clean.startswith(("/sys/", "pci", "0000:")):
            return privacy.mask("hardware", clean)
        if lowered in {"device", "device_path"} and clean.startswith(("/sys/", "pci", "0000:")):
            return privacy.mask("hardware", clean)
        return clean
    if lowered in {"ip", "ip_address", "ipv4", "ipv6", "gateway", "nameserver", "nameservers", "next_hop", "destination", "route_destination", "netmask", "broadcast"}:
        try:
            candidate = clean.split("%", 1)[0]
            if "/" in candidate:
                ipaddress.ip_network(candidate, strict=False)
            else:
                ipaddress.ip_address(candidate)
        except ValueError:
            if lowered in {"nameserver", "nameservers"}:
                return privacy.mask("host", clean)
            return privacy.sanitize_text(clean)
        return privacy.mask("ip", clean)
    if lowered in {"address", "network_address"}:
        if re.fullmatch(r"(?i)(?:[0-9a-f]{2}[:-]){5,31}[0-9a-f]{2}", clean):
            return privacy.mask("mac", clean)
        try:
            candidate = clean.split("%", 1)[0]
            if "/" in candidate:
                ipaddress.ip_network(candidate, strict=False)
            else:
                ipaddress.ip_address(candidate)
        except ValueError:
            return privacy.sanitize_text(clean)
        return privacy.mask("ip", clean)
    if lowered in {"root", "subvol", "subvolume", "search_domains", "domain", "domains"}:
        if lowered in {"search_domains", "domain", "domains"}:
            return privacy.mask("host", clean)
        if lowered == "root" and clean.startswith("/"):
            return privacy.mask("mountroot", clean)
        return privacy.sanitize_text(clean)
    return clean


def _parse_kernel_cmdline(raw: str, privacy: _Privacy) -> list[dict[str, Any]]:
    """Retain known diagnostic arguments and omit all unknown values."""
    result: list[dict[str, Any]] = []
    for token in raw.split()[:256]:
        name, separator, value = token.partition("=")
        if name in _CMDLINE_SAFE_FLAGS and not separator:
            result.append({"parameter": name, "value": "present"})
        elif name in _CMDLINE_SAFE_VALUES and separator:
            if name == "root" or name == "BOOT_IMAGE":
                # Kernel paths and root identifiers can reveal mounted devices.
                safe_value = privacy.block_device(value.removeprefix("/dev/")) if value.startswith("/dev/") else _scrub_secrets(value)
                for prefix in ("PARTUUID=", "UUID="):
                    if privacy.enabled and value.upper().startswith(prefix):
                        safe_value = prefix + privacy.mask("uuid", value[len(prefix):])
                        break
                for prefix in ("PARTLABEL=", "LABEL="):
                    if privacy.enabled and value.upper().startswith(prefix):
                        safe_value = prefix + privacy.mask("label", value[len(prefix):])
                        break
            elif name == "rootflags":
                safe_value: str | list[dict[str, str]] = _safe_mount_options(value, privacy)
            else:
                safe_value = value if re.fullmatch(r"[A-Za-z0-9_.:,/+%-]{1,128}", value) else "<redacted>"
            safe_result = privacy.sanitize_text(safe_value) if isinstance(safe_value, str) else _sanitize(safe_value, privacy)
            result.append({"parameter": name, "value": safe_result})
        # Unrecognized parameters may carry arbitrary credentials. Do not export
        # either their names or values; the safe parameter list stays useful.
    return result


def _decode_mount_field(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _parse_mountinfo(raw: str) -> list[dict[str, Any]]:
    mounts: list[dict[str, Any]] = []
    for line in raw.splitlines()[:_MAX_RECORDS]:
        fields = line.split()
        try:
            separator = fields.index("-")
            if separator < 6 or separator + 2 >= len(fields):
                continue
            mounts.append({
                "device_number": fields[2],
                "root": _decode_mount_field(fields[3]),
                "mountpoint": _decode_mount_field(fields[4]),
                "mount_options": fields[5].split(","),
                "filesystem_type": fields[separator + 1],
                "source": _decode_mount_field(fields[separator + 2]),
                "super_options": fields[separator + 3].split(",") if separator + 3 < len(fields) else [],
            })
        except (ValueError, IndexError):
            continue
    return mounts


def _fstab_fields(line: str) -> list[str]:
    """Split fstab fields while retaining the documented octal escapes."""
    body = re.split(r"(?<!\\)#", line, maxsplit=1)[0]
    pattern = re.compile(r"(?:\\[0-7]{3}|\\\\|[^\s])+")
    fields = [match.group(0) for match in pattern.finditer(body)]
    return [re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), field) for field in fields]


def _safe_mount_options(raw_options: str, privacy: _Privacy) -> list[dict[str, str]]:
    safe: list[dict[str, str]] = []
    for raw in raw_options.split(",")[:128]:
        if not raw:
            continue
        name, separator, value = raw.partition("=")
        normalized = name.lower()
        if _SECRET_KEY.search(normalized):
            safe.append({"name": name, "value": "<redacted>"})
        elif not separator:
            # Keep familiar flags; omit arbitrary words that could be pasted secrets.
            if normalized in _FSTAB_SAFE_OPTIONS or normalized.startswith("x-systemd."):
                safe.append({"name": name})
        elif normalized in _FSTAB_SAFE_OPTIONS or normalized.startswith("x-systemd."):
            if normalized in {"uid", "gid"} and privacy.enabled:
                clean_value = "<user>"
            elif normalized in {"subvol", "x-systemd.requires", "x-systemd.after", "x-systemd.before"}:
                clean_value = privacy.sanitize_text(value)
            elif normalized in {"addr", "ip", "server"}:
                clean_value = privacy.mask("ip", value) if privacy.enabled else _scrub_secrets(value)
            elif re.fullmatch(r"[A-Za-z0-9_.:+/@%,-]{1,160}", value):
                clean_value = privacy.sanitize_text(value)
            else:
                clean_value = "<redacted>"
            safe.append({"name": name, "value": clean_value})
        # Unknown key/value options are omitted so arbitrary options cannot leak.
    return safe


def _parse_fstab(raw: str, privacy: _Privacy) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines()[:_MAX_RECORDS], start=1):
        stripped = line.strip()
        if not stripped:
            records.append({"line": line_number, "record_type": "blank"})
            continue
        if stripped.startswith("#"):
            records.append({"line": line_number, "record_type": "comment"})
            continue
        fields = _fstab_fields(line)
        if len(fields) != 6:
            records.append({"line": line_number, "record_type": "invalid", "field_count": len(fields)})
            continue
        source, destination, fstype, options, dump, pass_number = fields
        try:
            dump_value, pass_value = int(dump), int(pass_number)
            if dump_value < 0 or pass_value < 0:
                raise ValueError
        except ValueError:
            records.append({"line": line_number, "record_type": "invalid", "field_count": 6})
            continue
        source = _scrub_secrets(source)
        source = _sanitize(source, privacy, "source")
        destination = _sanitize(destination, privacy, "mountpoint")
        records.append({
            "line": line_number,
            "record_type": "entry",
            "source": source,
            "mountpoint": _scrub_secrets(destination),
            "filesystem_type": _scrub_secrets(fstype),
            "options": _safe_mount_options(options, privacy),
            "dump": dump_value,
            "pass": pass_value,
        })
    return records


def _app_version() -> str:
    try:
        return importlib.metadata.version("taskpup")
    except importlib.metadata.PackageNotFoundError:
        return "0.1.0"


def _kernel_cmdline(privacy: _Privacy) -> list[dict[str, str]]:
    raw = _read_text(PROC_ROOT / "cmdline", limit=8192) or ""
    return _parse_kernel_cmdline(raw.replace("\x00", " "), privacy)


def _uptime_seconds() -> float | None:
    raw = _read_text(PROC_ROOT / "uptime", limit=256)
    if raw:
        try:
            value = float(raw.split()[0])
            if math.isfinite(value) and value >= 0:
                return value
        except (ValueError, IndexError):
            pass
    try:
        value = time.time() - psutil.boot_time()
    except (OSError, psutil.Error):
        return None
    return value if math.isfinite(value) and value >= 0 else None


def _system_identification() -> dict[str, str | None]:
    base = SYS_ROOT / "class/dmi/id"
    return {
        key: _read_text(base / filename, limit=4096)
        for key, filename in (
            ("system_vendor", "sys_vendor"),
            ("product_name", "product_name"),
            ("product_version", "product_version"),
            ("bios_vendor", "bios_vendor"),
            ("bios_version", "bios_version"),
            ("bios_date", "bios_date"),
        )
    }


def _collect_os(privacy: _Privacy) -> dict[str, Any]:
    try:
        release = host_platform.freedesktop_os_release()
    except (OSError, AttributeError):
        release = {}
    uname = host_platform.uname()
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = None
    boot_mode = "UEFI" if (SYS_ROOT / "firmware/efi").exists() else "Legacy BIOS or unknown"
    return {
        "distribution": release.get("NAME"),
        "distribution_version": release.get("VERSION_ID") or release.get("VERSION"),
        "os_architecture": uname.machine or None,
        "kernel_name": uname.system or None,
        "kernel_version": uname.version or None,
        "kernel_release": uname.release or None,
        "kernel_command_line": _kernel_cmdline(privacy),
        "hostname": privacy.mask("host", hostname) if privacy.enabled and hostname else hostname,
        "uptime_seconds": _uptime_seconds(),
        "boot_mode": boot_mode,
        "identification": _system_identification(),
    }


def _collect_desktop(screen_info: Sequence[Mapping[str, object]] | None) -> dict[str, Any]:
    env = os.environ
    session_type = env.get("XDG_SESSION_TYPE")
    if session_type not in {"x11", "wayland", "tty"}:
        session_type = "wayland" if env.get("WAYLAND_DISPLAY") else ("x11" if env.get("DISPLAY") else None)
    screens: list[dict[str, int | float]] = []
    for item in (screen_info or ())[:32]:
        width, height, scale = item.get("width"), item.get("height"), item.get("scale")
        if (
            isinstance(width, int) and not isinstance(width, bool) and width > 0
            and isinstance(height, int) and not isinstance(height, bool) and height > 0
        ):
            screen: dict[str, int | float] = {"width": width, "height": height}
            if isinstance(scale, (int, float)) and not isinstance(scale, bool) and math.isfinite(float(scale)) and scale > 0:
                screen["scale"] = float(scale)
            screens.append(screen)
    try:
        import PySide6
        from PySide6.QtCore import qVersion
        qt_version = qVersion() or None
        pyside_version = PySide6.__version__
    except (ImportError, AttributeError):
        qt_version = pyside_version = None
    return {
        "desktop_environment": env.get("XDG_CURRENT_DESKTOP") or env.get("DESKTOP_SESSION"),
        "session": env.get("XDG_SESSION_DESKTOP") or env.get("GDMSESSION"),
        "session_type": session_type,
        "window_manager": None,
        "screens": screens,
        "qt_version": qt_version,
        "pyside_version": pyside_version,
    }


def _cpuinfo() -> tuple[str | None, list[str]]:
    raw = _read_text(PROC_ROOT / "cpuinfo") or ""
    model: str | None = None
    flags: list[str] = []
    for line in raw.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        normalized = key.strip().lower()
        value = value.strip()
        if model is None and normalized in {"model name", "hardware", "cpu model"} and value:
            model = value
        elif normalized in {"flags", "features"} and value:
            flags = sorted(set(value.split()))
            break
    return model, flags[:512]


def _collect_cpu() -> dict[str, Any]:
    model, flags = _cpuinfo()
    sampler = SystemSampler()
    try:
        sampler._discover_static_cpu()
    except Exception:
        pass
    try:
        logical = psutil.cpu_count(logical=True)
    except (OSError, psutil.Error):
        logical = None
    try:
        physical = psutil.cpu_count(logical=False)
    except (OSError, psutil.Error):
        physical = getattr(sampler, "_physical_cores", None)
    try:
        frequency = sampler._read_frequency()
    except Exception:
        frequency = None
    try:
        temperature = sampler._read_temperature()
    except Exception:
        temperature = None
    return {
        "model": model or getattr(sampler, "_cpu_model", None),
        "architecture": host_platform.machine() or None,
        "physical_cores": physical or getattr(sampler, "_physical_cores", None),
        "logical_processors": logical,
        "current_frequency_mhz": frequency,
        "capabilities": flags,
        "temperature_c": temperature,
    }


def _collect_memory() -> dict[str, Any]:
    try:
        memory = psutil.virtual_memory()
    except (OSError, psutil.Error):
        memory = None
    try:
        swap = psutil.swap_memory()
    except (OSError, psutil.Error):
        swap = None
    meminfo: dict[str, int] = {}
    for line in (_read_text(PROC_ROOT / "meminfo") or "").splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        parts = value.split()
        try:
            number = int(parts[0])
            multiplier = 1024 if len(parts) > 1 and parts[1].lower() == "kb" else 1
        except (ValueError, IndexError):
            continue
        if number >= 0 and key in {"Cached", "Buffers", "SwapCached", "HugePages_Total", "Hugepagesize"}:
            meminfo[key] = number * multiplier
    vm_config: dict[str, int] = {}
    for key in ("swappiness", "overcommit_memory", "overcommit_ratio"):
        raw = _read_text(SYS_ROOT / "module/vm/parameters" / key, limit=64)
        if raw is None:
            raw = _read_text(Path("/proc/sys/vm") / key, limit=64)
        try:
            value = int(raw.strip()) if raw is not None else None
        except ValueError:
            value = None
        if value is not None:
            vm_config[key] = value
    return {
        "ram": None if memory is None else {
            "total_bytes": memory.total,
            "available_bytes": memory.available,
            "used_bytes": max(0, memory.total - memory.available),
            "percent_used": (
                100.0 * max(0, memory.total - memory.available) / memory.total
                if memory.total else None
            ),
            "cached_bytes": getattr(memory, "cached", None),
            "buffers_bytes": getattr(memory, "buffers", None),
        },
        "swap": None if swap is None else {
            "total_bytes": swap.total,
            "available_bytes": swap.free,
            "used_bytes": swap.used,
            "percent_used": swap.percent,
        },
        "kernel_memory_details": meminfo,
        "configuration": vm_config,
    }


def _collect_graphics() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    devices = discover_gpus()
    gpus: list[dict[str, Any]] = []
    sensor_records: list[dict[str, Any]] = []
    for device in devices[:128]:
        sample = device.sample()
        try:
            vendor = _read_text(Path(device.identity) / "vendor")
            product = _read_text(Path(device.identity) / "device")
        except (OSError, TypeError):
            vendor = product = None
        gpus.append({
            "identity": device.identity,
            "model": device.name,
            "pci_vendor_id": vendor,
            "pci_device_id": product,
            "driver": device.driver,
            "memory_pools": {
                "driver_reported_vram": {
                    "used_bytes": sample.memory_used,
                    "total_bytes": sample.memory_total,
                    "classification": "driver-reported; dedicated/shared semantics are not assumed",
                },
                "driver_reported_gtt": {
                    "used_bytes": sample.gtt_used,
                    "total_bytes": sample.gtt_total,
                    "classification": "driver-reported; dedicated/shared semantics are not assumed",
                },
            },
            "utilization_percent": sample.utilization,
            "telemetry_capabilities": sorted(sample.capabilities),
            "sensors": sample.sensors,
        })
        for name, value in sample.sensors.items():
            sensor_records.append({"device": device.identity, "name": name, "value": value})
    return {"devices": gpus}, sensor_records


def _collect_storage(sample: StorageSample, privacy: _Privacy) -> dict[str, Any]:
    devices: list[dict[str, Any]] = []
    for disk in list(sample.devices.values())[:_MAX_RECORDS]:
        model = disk.label.split(" (", 1)[0]
        if model == disk.name:
            model = None
        devices.append({
            "device_path": f"/dev/{disk.name}",
            "device_name": disk.name,
            "model": model,
            "storage_type": disk.kind,
            "capacity_bytes": disk.capacity,
            "temperature_c": disk.temperature_c,
            "temperature_supported": disk.temperature_supported,
        })
    partitions: list[dict[str, Any]] = []
    try:
        entries = sorted((SYS_ROOT / "class/block").iterdir())[:_MAX_RECORDS]
    except OSError:
        entries = []
    for entry in entries:
        if not entry.name or not re.fullmatch(r"[A-Za-z0-9_.+-]+", entry.name):
            continue
        number_raw = _read_text(entry / "partition", limit=64)
        if number_raw is None:
            continue
        try:
            number = int(number_raw)
        except ValueError:
            continue
        size_raw = _read_text(entry / "size", limit=64)
        try:
            capacity = int(size_raw) * 512 if size_raw is not None and int(size_raw) >= 0 else None
        except ValueError:
            capacity = None
        try:
            parent = entry.resolve(strict=True).parent.name
        except OSError:
            parent = None
        partitions.append({
            "device_path": f"/dev/{entry.name}",
            "parent_device": parent,
            "partition_number": number if number > 0 else None,
            "capacity_bytes": capacity,
        })
    return {"devices": devices, "partitions": partitions}


def _mount_sample() -> StorageSample:
    return StorageSampler().sample(time.monotonic())


def _collect_filesystems(sample: StorageSample, privacy: _Privacy) -> dict[str, Any]:
    mountinfo = _read_text(PROC_ROOT / "self/mountinfo")
    mounts = _parse_mountinfo(mountinfo or "")
    usage_by_key = {(fs.mountpoint, fs.fstype): fs for fs in sample.filesystems}
    for mount in mounts:
        raw_options = ",".join(mount.pop("mount_options", []))
        raw_super_options = ",".join(mount.pop("super_options", []))
        mount["options"] = _safe_mount_options(raw_options, privacy)
        mount["super_options"] = _safe_mount_options(raw_super_options, privacy)
        fs = usage_by_key.get((mount["mountpoint"], mount["filesystem_type"]))
        mount["capacity"] = None if fs is None else {
            "total_bytes": fs.total,
            "used_bytes": fs.used,
            "available_bytes": fs.available,
            "percent_used": fs.percent,
        }
    raw_fstab = _read_text(FSTAB_PATH)
    return {
        "mounts": mounts,
        "mountinfo_available": mountinfo is not None,
        "fstab": {"available": raw_fstab is not None, "entries": _parse_fstab(raw_fstab, privacy) if raw_fstab is not None else []},
    }


def _read_routes_v4() -> list[dict[str, Any]] | None:
    routes: list[dict[str, Any]] = []
    raw = _read_text(PROC_ROOT / "net/route")
    if raw is None:
        return None
    for line in raw.splitlines()[1:_MAX_RECORDS + 1]:
        fields = line.split()
        if len(fields) < 8:
            continue
        try:
            destination = socket.inet_ntoa(struct.pack("<I", int(fields[1], 16)))
            gateway = socket.inet_ntoa(struct.pack("<I", int(fields[2], 16)))
            mask = socket.inet_ntoa(struct.pack("<I", int(fields[7], 16)))
            metric = int(fields[6], 10)
        except (ValueError, OSError, struct.error):
            continue
        routes.append({"interface": fields[0], "destination": destination, "gateway": gateway, "netmask": mask, "metric": metric})
    return routes


def _read_routes_v6() -> list[dict[str, Any]] | None:
    routes: list[dict[str, Any]] = []
    raw = _read_text(PROC_ROOT / "net/ipv6_route")
    if raw is None:
        return None
    for line in raw.splitlines()[:_MAX_RECORDS]:
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            destination = str(ipaddress.IPv6Address(bytes.fromhex(fields[0])))
            prefix = int(fields[1], 16)
            gateway = str(ipaddress.IPv6Address(bytes.fromhex(fields[4])))
            metric = int(fields[5], 16)
        except (ValueError, ipaddress.AddressValueError):
            continue
        routes.append({"interface": fields[9], "destination": f"{destination}/{prefix}", "gateway": gateway, "metric": metric})
    return routes


def _collect_network() -> dict[str, Any]:
    addresses_available = stats_available = counters_available = True
    try:
        addresses = psutil.net_if_addrs()
    except (OSError, psutil.Error):
        addresses = {}
        addresses_available = False
    try:
        stats = psutil.net_if_stats()
    except (OSError, psutil.Error):
        stats = {}
        stats_available = False
    try:
        counters = psutil.net_io_counters(pernic=True, nowrap=False) or {}
    except (OSError, psutil.Error):
        counters = {}
        counters_available = False
    try:
        samples = NetworkSampler().sample(time.monotonic()) or {}
    except (OSError, psutil.Error):
        samples = {}
    interfaces: list[dict[str, Any]] = []
    names = sorted(set(addresses) | set(stats) | set(counters))[:_MAX_RECORDS]
    for name in names:
        address_records: list[dict[str, Any]] = []
        for address in addresses.get(name, ()):
            family = getattr(address, "family", None)
            label = "IPv4" if family == socket.AF_INET else "IPv6" if family == socket.AF_INET6 else "MAC" if family == getattr(psutil, "AF_LINK", object()) else "other"
            address_records.append({
                "family": label,
                "address": getattr(address, "address", None),
                "netmask": getattr(address, "netmask", None),
                "broadcast": getattr(address, "broadcast", None),
            })
        stat = stats.get(name)
        counter = counters.get(name)
        sample = next((item for item in samples.values() if item.name == name), None)
        driver_path = SYS_ROOT / "class/net" / name / "device/driver"
        try:
            driver = driver_path.resolve(strict=True).name
        except OSError:
            driver = None
        interfaces.append({
            "interface": name,
            "type": sample.kind if sample else None,
            "auxiliary": sample.auxiliary if sample else None,
            "connection_state": sample.status if sample else (
                "Connected" if getattr(stat, "isup", None) else "Disconnected" if stat is not None else "Unavailable"
            ),
            "driver": driver,
            "link_speed_mbps": sample.speed_mbps if sample else (
                getattr(stat, "speed", None) if stat is not None else None
            ),
            "addresses": address_records,
            "counters": None if counter is None else {
                "bytes_received": getattr(counter, "bytes_recv", None),
                "bytes_transmitted": getattr(counter, "bytes_sent", None),
                "packets_received": getattr(counter, "packets_recv", None),
                "packets_transmitted": getattr(counter, "packets_sent", None),
                "errors_in": getattr(counter, "errin", None),
                "errors_out": getattr(counter, "errout", None),
                "dropped_in": getattr(counter, "dropin", None),
                "dropped_out": getattr(counter, "dropout", None),
            },
            "rates": None if sample is None else {
                "receive_bytes_per_second": sample.receive_rate,
                "transmit_bytes_per_second": sample.transmit_rate,
            },
        })
    dns: dict[str, list[str]] = {"nameservers": [], "search_domains": []}
    resolv_conf = _read_text(RESOLV_CONF)
    for line in (resolv_conf or "").splitlines()[:1024]:
        fields = line.split("#", 1)[0].split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            dns["nameservers"].append(fields[1])
        elif len(fields) >= 2 and fields[0] in {"search", "domain"}:
            dns["search_domains"].extend(fields[1:64])
    return {
        "interfaces": interfaces,
        "addresses_available": addresses_available,
        "interface_stats_available": stats_available,
        "counters_available": counters_available,
        "ipv4_routes": _read_routes_v4(),
        "ipv6_routes": _read_routes_v6(),
        "dns": dns if resolv_conf is not None else None,
    }


def _collect_sensors(storage_sample: StorageSample | None, graphics_sensors: list[dict[str, Any]]) -> dict[str, Any]:
    temperatures: list[dict[str, Any]] = []
    fans: list[dict[str, Any]] = []
    power: list[dict[str, Any]] = []
    clocks: list[dict[str, Any]] = []
    temperatures_available = fans_available = True
    try:
        temp_groups = psutil.sensors_temperatures(fahrenheit=False)
    except (AttributeError, NotImplementedError, OSError, psutil.Error):
        temp_groups = {}
        temperatures_available = False
    for group, entries in (temp_groups or {}).items():
        for entry in list(entries)[:_MAX_RECORDS]:
            current = getattr(entry, "current", None)
            if isinstance(current, (int, float)) and math.isfinite(float(current)):
                temperatures.append({"device": group, "name": getattr(entry, "label", None) or group, "value_c": float(current)})
    try:
        fan_groups = psutil.sensors_fans()
    except (AttributeError, NotImplementedError, OSError, psutil.Error):
        fan_groups = {}
        fans_available = False
    for group, entries in (fan_groups or {}).items():
        for entry in list(entries)[:_MAX_RECORDS]:
            current = getattr(entry, "current", None)
            if isinstance(current, (int, float)) and math.isfinite(float(current)):
                fans.append({"device": group, "name": getattr(entry, "label", None) or group, "value_rpm": float(current)})
    for sensor in graphics_sensors:
        name = str(sensor.get("name") or "")
        value = sensor.get("value")
        if "temperature" in name.lower() and isinstance(value, (int, float)):
            temperatures.append({"device": sensor.get("device"), "name": name, "value_c": value})
        elif "fan" in name.lower() and isinstance(value, (int, float)):
            fans.append({"device": sensor.get("device"), "name": name, "value_rpm": value})
        elif "power" in name.lower() and isinstance(value, (int, float)):
            power.append({"device": sensor.get("device"), "name": name, "value_w": value})
        elif "clock" in name.lower() and isinstance(value, (int, float)):
            clocks.append({"device": sensor.get("device"), "name": name, "value_mhz": value})
    drives: list[dict[str, Any]] = []
    if storage_sample is not None:
        for disk in storage_sample.devices.values():
            if disk.temperature_c is not None:
                drives.append({"device": f"/dev/{disk.name}", "name": "Drive temperature", "value_c": disk.temperature_c})
    return {
        "temperatures": temperatures,
        "temperatures_available": temperatures_available,
        "fan_speeds": fans,
        "fan_speeds_available": fans_available,
        "drive_temperatures": drives,
        "power_readings": power,
        "clock_readings": clocks,
    }


def collect_report(
    selected: set[str],
    private: bool = True,
    *,
    screen_info: Sequence[Mapping[str, object]] | None = None,
) -> dict[str, Any]:
    """Collect selected report sections into one JSON-serializable snapshot.

    ``screen_info`` must be copied by the GUI caller before dispatching this
    function to a worker. This module never queries a Qt screen or application.
    """
    privacy = _Privacy(bool(private))
    chosen = [key for key in SECTIONS if key in selected]
    errors: list[dict[str, str]] = []
    for unknown in sorted(set(selected) - SECTIONS.keys()):
        errors.append({"section": unknown, "message": "Unknown report section; skipped."})

    # Reuse costly discovery within this snapshot and collect only when needed.
    storage_sample: StorageSample | None = None
    graphics_sensors: list[dict[str, Any]] = []
    graphics_data: dict[str, Any] | None = None

    def need_storage() -> StorageSample:
        nonlocal storage_sample
        if storage_sample is None:
            storage_sample = _mount_sample()
        assert storage_sample is not None
        return storage_sample

    def need_graphics() -> tuple[dict[str, Any], list[dict[str, Any]]]:
        nonlocal graphics_data, graphics_sensors
        if graphics_data is None:
            graphics_data, graphics_sensors = _collect_graphics()
        return graphics_data, graphics_sensors

    def collect_storage_section() -> dict[str, Any]:
        sample = need_storage()
        return _collect_storage(sample, privacy)

    def collect_filesystems_section() -> dict[str, Any]:
        sample = need_storage()
        return _collect_filesystems(sample, privacy)

    def collect_sensors_section() -> dict[str, Any]:
        sample = need_storage()
        return _collect_sensors(sample, need_graphics()[1])

    sections: dict[str, Any] = {}
    collectors = {
        "os": lambda: _collect_os(privacy),
        "desktop": lambda: _collect_desktop(screen_info),
        "cpu": _collect_cpu,
        "memory": _collect_memory,
        "graphics": lambda: need_graphics()[0],
        "storage": collect_storage_section,
        "filesystems": collect_filesystems_section,
        "network": _collect_network,
        "sensors": collect_sensors_section,
    }
    for key in chosen:
        try:
            sections[key] = _sanitize(collectors[key](), privacy)
        except Exception as error:
            # Exception text may include identifying paths or option values.
            sections[key] = {"available": False}
            errors.append({"section": key, "message": f"Collection failed ({type(error).__name__})."})

    return {
        "schema_version": "1",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "app_version": _app_version(),
        "selected_sections": chosen,
        "privacy": bool(private),
        "sections": sections,
        "errors": errors,
    }
