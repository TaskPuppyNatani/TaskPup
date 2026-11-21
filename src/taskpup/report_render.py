"""Render sanitized diagnostic snapshots and write them safely to disk."""

from __future__ import annotations

import errno
from html import escape as _html_escape
import io
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, TypeGuard
import zipfile


_REPORT_MEMBERS = ("report.md", "report.jsonl", "report.html")
_MARKDOWN_SPECIAL = frozenset("\\`*_{}[]!|~")
_LABEL_ABBREVIATIONS = {
    "api": "API",
    "cpu": "CPU",
    "dns": "DNS",
    "gpu": "GPU",
    "html": "HTML",
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "jsonl": "JSONL",
    "mac": "MAC",
    "nvme": "NVMe",
    "os": "OS",
    "raid": "RAID",
    "ram": "RAM",
    "usb": "USB",
    "utc": "UTC",
    "uuid": "UUID",
    "vram": "VRAM",
    "x11": "X11",
}
_MD_LABEL_ABBREVIATIONS = {
    **_LABEL_ABBREVIATIONS,
    "bios": "BIOS",
    "fstab": "fstab",
    "ghz": "GHz",
    "gtt": "GTT",
    "hdd": "HDD",
    "mbps": "Mbps",
    "mhz": "MHz",
    "pci": "PCI",
    "pyside": "PySide",
    "qt": "Qt",
    "rpm": "RPM",
    "ssd": "SSD",
    "uefi": "UEFI",
}
_MD_SECTION_TITLES = {
    "os": "Operating System",
    "desktop": "Desktop Environment",
    "cpu": "CPU",
    "memory": "Memory and Swap",
    "graphics": "Graphics Hardware",
    "storage": "Storage Hardware",
    "filesystems": "Filesystems and Mounts",
    "network": "Network Configuration",
    "sensors": "Hardware Sensors",
}
_MD_FIELD_OVERRIDES = {
    "available_bytes": "Available",
    "buffers_bytes": "Buffers",
    "bytes_received": "Received",
    "bytes_transmitted": "Transmitted",
    "cached_bytes": "Cached",
    "capacity_bytes": "Capacity",
    "current_frequency_mhz": "Current Frequency",
    "hugepages_total": "Huge Pages Total",
    "hugepagesize": "Huge Page Size",
    "link_speed_mbps": "Link Speed",
    "percent_used": "Usage",
    "receive_bytes_per_second": "Receive Rate",
    "swapcached": "Swap Cached",
    "temperature_c": "Temperature",
    "total_bytes": "Total",
    "transmit_bytes_per_second": "Transmit Rate",
    "uptime_seconds": "Uptime",
    "used_bytes": "Used",
    "utilization_percent": "Utilization",
    "value_c": "Temperature",
    "value_mhz": "Frequency",
    "value_rpm": "Speed",
    "value_w": "Power",
}


def _validate_json_value(value: Any, path: str = "snapshot") -> None:
    """Reject values that would make a report invalid or have ambiguous JSON types."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} contains a non-string object key")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise TypeError(f"{path} contains a non-JSON value")


def _validate_snapshot(snapshot: dict[str, Any]) -> None:
    if not isinstance(snapshot, dict):
        raise TypeError("snapshot must be a dictionary")

    required = {
        "schema_version": str,
        "timestamp": str,
        "app_version": str,
        "selected_sections": list,
        "privacy": bool,
        "sections": dict,
        "errors": list,
    }
    for key, expected_type in required.items():
        if key not in snapshot or not isinstance(snapshot[key], expected_type):
            raise ValueError(f"snapshot field {key!r} must be {expected_type.__name__}")
    if any(not isinstance(section, str) for section in snapshot["selected_sections"]):
        raise ValueError("snapshot selected_sections must contain strings")
    if any(not isinstance(section, str) for section in snapshot["sections"]):
        raise ValueError("snapshot sections must have string keys")
    _validate_json_value(snapshot)


def _json_dumps(value: Any, *, indent: int | None = None) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, indent=indent)


def _humanize_label(value: str) -> str:
    """Turn internal snake/kebab/camel-case names into readable report labels."""
    separated = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", value)
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", separated)
    words = re.split(r"[_\-\s]+", separated.strip())
    return " ".join(
        _LABEL_ABBREVIATIONS.get(word.casefold(), word if word.isupper() or any(char.isupper() for char in word[1:]) else word.capitalize())
        for word in words
        if word
    )


def format_bytes(value: int) -> str:
    """Format a byte quantity using the binary units shown in TaskPup."""
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if amount < 1024 or unit == "PiB":
            return f"{amount:,.0f} {unit}" if unit == "B" else f"{amount:,.2f} {unit}"
        amount /= 1024
    return f"{amount:,.2f} PiB"


def _byte_field(key: str) -> bool:
    normalized = key.casefold()
    return normalized.endswith("_bytes") or normalized in {
        "bytes_received", "bytes_transmitted", "receive_bytes_per_second", "transmit_bytes_per_second",
    }


def _display_value(value: Any, key: str = "", parent: str = "") -> str:
    if value is None:
        return "Not available"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, int) and (
        _byte_field(key) or (parent == "kernel_memory_details" and key.casefold() != "hugepages_total")
    ):
        suffix = "/s" if key.casefold().endswith("_per_second") else ""
        return format_bytes(value) + suffix
    if isinstance(value, dict):
        return "; ".join(
            f"{_humanize_label(child_key)}: {_display_value(child, child_key, key.casefold())}"
            for child_key, child in value.items()
        ) or "No details"
    if isinstance(value, list):
        return "; ".join(_display_value(item) for item in value) or "No entries"
    return str(value)


def _record_columns(records: list[dict[str, Any]]) -> list[str]:
    columns: list[str] = []
    for record in records:
        for key in record:
            if key not in columns:
                columns.append(key)
    return columns


def _md_normalize_text(value: str) -> str:
    """Strip stray carriage returns/edge whitespace and collapse multiline text cleanly."""
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    parts: list[str] = []
    for raw_line in normalized.split("\n"):
        cleaned_chars: list[str] = []
        for character in raw_line:
            codepoint = ord(character)
            if character == "\t":
                cleaned_chars.append(" ")
            elif codepoint < 0x20 or codepoint == 0x7F:
                cleaned_chars.append("")
            else:
                cleaned_chars.append(character)
        line = "".join(cleaned_chars).strip()
        if line:
            parts.append(line)
    return "; ".join(parts)


def _md_escape(value: str) -> str:
    """Keep dynamic Markdown text on one line and escape Markdown/HTML-sensitive syntax."""
    normalized = _md_normalize_text(value)
    clean: list[str] = []
    for character in normalized:
        if character == "&":
            clean.append("&amp;")
        elif character == "<":
            clean.append("&lt;")
        elif character == ">":
            clean.append("&gt;")
        elif character in _MARKDOWN_SPECIAL:
            clean.append("\\" + character)
        else:
            clean.append(character)
    return "".join(clean)


def _md_code_span(value: str) -> str:
    """Wrap sanitized single-line text in a safe Markdown inline code span."""
    text = _md_normalize_text(value)
    if not text:
        return "` `"
    longest_run = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
    fence = "`" * (longest_run + 1)
    if text.startswith(("`", " ")) or text.endswith(("`", " ")):
        return f"{fence} {text} {fence}"
    return f"{fence}{text}{fence}"


def _md_code_block(value: str, language: str = "text") -> list[str]:
    """Wrap sanitized text in a Markdown fenced code block with safe fence length."""
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    safe_lines: list[str] = []
    for raw_line in normalized.split("\n"):
        cleaned = "".join(
            ch if (ch == "\t" or (ord(ch) >= 0x20 and ord(ch) != 0x7F)) else ""
            for ch in raw_line
        ).rstrip()
        safe_lines.append(cleaned)
    body = "\n".join(safe_lines).strip("\n")
    longest_run = max((len(match.group(0)) for match in re.finditer(r"`+", body)), default=0)
    fence = "`" * max(3, longest_run + 1)
    return [f"{fence}{language}", body, fence]


def _md_label(value: str) -> str:
    """Turn internal field names into clean Markdown headings without redundant unit suffixes."""
    lowered = value.strip().casefold()
    if lowered in _MD_FIELD_OVERRIDES:
        return _MD_FIELD_OVERRIDES[lowered]
    if lowered.endswith("_bytes") and len(lowered) > 6:
        value = value[: -len("_bytes")]
    separated = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", value)
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", separated)
    words = re.split(r"[_\-\s]+", separated.strip())
    return " ".join(
        _MD_LABEL_ABBREVIATIONS.get(
            word.casefold(),
            word if word.isupper() or any(char.isupper() for char in word[1:]) else word.capitalize(),
        )
        for word in words
        if word
    )


def _md_section_title(name: str) -> str:
    return _MD_SECTION_TITLES.get(name.casefold(), _md_label(name))


def _md_heading(level: int, text: str) -> str:
    clamped = max(1, min(6, level))
    return f"{'#' * clamped} {_md_escape(text)}"


def _md_sublabel(level: int, text: str) -> str:
    if level <= 4:
        return _md_heading(level, text)
    return f"**{_md_escape(text)}**"


def _md_table(headers: list[str], rows: list[list[str]], *, humanize_headers: bool = False) -> list[str]:
    rendered_headers = " | ".join(
        _md_escape(_md_label(header) if humanize_headers else header)
        for header in headers
    )
    lines = [f"| {rendered_headers} |", f"| {' | '.join('---' for _ in headers)} |"]
    lines.extend(
        "| " + " | ".join(_md_escape(cell) for cell in row) + " |"
        for row in rows
    )
    return lines


def _is_number(value: Any) -> TypeGuard[int | float]:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _md_text(value: Any, *, empty: str = "Not reported", missing: str = "Not available") -> str:
    if value is None:
        return missing
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, str):
        cleaned = _md_normalize_text(value)
        return cleaned if cleaned else empty
    return str(value)


def _md_bytes(value: Any) -> str:
    if not _is_number(value):
        return "Not available"
    return format_bytes(int(round(float(value))))


def _md_rate(value: Any) -> str:
    if not _is_number(value):
        return "Not available"
    return f"{format_bytes(int(round(float(value))))}/s"


def _md_percent(value: Any) -> str:
    if not _is_number(value):
        return "Not available"
    return f"{float(value):.1f}%"


def _md_temp(value: Any) -> str:
    if not _is_number(value):
        return "Not available"
    return f"{float(value):.1f} °C"


def _md_freq_mhz(value: Any) -> str:
    if not _is_number(value):
        return "Not available"
    return f"{float(value):,.1f} MHz"


def _md_rpm(value: Any) -> str:
    if not _is_number(value):
        return "Not available"
    return f"{round(float(value)):,} RPM"


def _md_watts(value: Any) -> str:
    if not _is_number(value):
        return "Not available"
    return f"{float(value):.1f} W"


def _md_speed_mbps(value: Any) -> str:
    if not _is_number(value) or float(value) <= 0:
        return "Not available"
    numeric = float(value)
    if numeric.is_integer():
        return f"{int(numeric):,} Mbps"
    return f"{numeric:,.1f} Mbps"


def _md_uptime(value: Any) -> str:
    if not _is_number(value) or float(value) < 0:
        return "Not available"
    seconds = float(value)
    if seconds < 60:
        return f"{int(round(seconds))} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    days = int(seconds // 86400)
    hours = (seconds % 86400) / 3600
    return f"{days}d {hours:.1f}h"


def _md_int_count(value: Any) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{value:,}"
    if _is_number(value):
        return f"{float(value):,.2f}".rstrip("0").rstrip(".")
    return "Not available"


def _md_float(value: float) -> str:
    formatted = f"{value:.2f}".rstrip("0").rstrip(".")
    return "0" if formatted == "-0" else formatted


def _is_option_list(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    return all(
        isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and set(item.keys()) <= {"name", "value"}
        for item in value
    )


def _format_option_list(options: Any) -> str:
    if not isinstance(options, list) or not options:
        return "None"
    parts: list[str] = []
    for item in options:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            name = _md_normalize_text(item["name"])
            if not name:
                continue
            val = item.get("value")
            if val is not None and _md_normalize_text(str(val)):
                parts.append(f"{name}={_md_normalize_text(str(val))}")
            else:
                parts.append(name)
        elif isinstance(item, str):
            cleaned = _md_normalize_text(item)
            if cleaned:
                parts.append(cleaned)
    return ", ".join(parts) if parts else "None"


def _md_gpu_sensor_reading(name: str, value: Any) -> str:
    lowered = name.casefold()
    if _is_number(value):
        if "temperature" in lowered:
            return _md_temp(value)
        if "clock" in lowered:
            return _md_freq_mhz(value)
        if "power" in lowered:
            return _md_watts(value)
        if "fan" in lowered:
            return _md_rpm(value)
        if "utilization" in lowered or "percent" in lowered:
            return _md_percent(value)
    return _md_value(value)


def _md_value(value: Any, key: str = "", parent: str = "") -> str:
    if value is None:
        return "Not available"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, str):
        cleaned = _md_normalize_text(value)
        return cleaned if cleaned else "Not reported"
    lowered = key.casefold()
    if _is_number(value):
        if _byte_field(key) or (parent == "kernel_memory_details" and lowered != "hugepages_total"):
            return _md_rate(value) if lowered.endswith("_per_second") else _md_bytes(value)
        if lowered in {"percent_used", "utilization_percent", "percent"} or lowered.endswith("_percent"):
            return _md_percent(value)
        if lowered in {"temperature_c", "value_c"} or lowered.endswith("_c"):
            return _md_temp(value)
        if lowered in {"current_frequency_mhz", "value_mhz"} or lowered.endswith("_mhz"):
            return _md_freq_mhz(value)
        if lowered in {"value_rpm"} or lowered.endswith("_rpm"):
            return _md_rpm(value)
        if lowered in {"value_w"} or lowered.endswith("_w"):
            return _md_watts(value)
        if lowered == "link_speed_mbps":
            return _md_speed_mbps(value)
        if lowered == "uptime_seconds":
            return _md_uptime(value)
        if isinstance(value, float):
            return _md_float(value)
        return str(value)
    if _is_option_list(value):
        return _format_option_list(value)
    if isinstance(value, dict):
        return "; ".join(
            f"{_md_label(child_key)}: {_md_value(child, child_key, lowered)}"
            for child_key, child in value.items()
        ) or "No details"
    if isinstance(value, list):
        return ", ".join(_md_value(item) for item in value) or "No entries"
    return str(value)


def _md_render_generic(data: Any, *, heading_level: int = 3) -> list[str]:
    """Render arbitrary structured data cleanly into compact Markdown tables and subsections."""
    if isinstance(data, dict) and data == {"available": False}:
        return ["This section could not be collected."]

    simple_rows: list[list[str]] = []
    nested_dicts: list[tuple[str, dict[str, Any]]] = []
    record_tables: list[tuple[str, list[dict[str, Any]]]] = []

    if isinstance(data, dict):
        if not data:
            return ["No details were available."]
        for key, child in data.items():
            label = _md_label(key)
            if isinstance(child, dict):
                if child:
                    nested_dicts.append((key, child))
                else:
                    simple_rows.append([label, "No details"])
            elif _is_option_list(child):
                simple_rows.append([label, _format_option_list(child)])
            elif isinstance(child, list) and all(isinstance(item, dict) for item in child):
                if child:
                    record_tables.append((label, child))
                else:
                    simple_rows.append([label, "No entries"])
            else:
                simple_rows.append([label, _md_value(child, key)])
    elif isinstance(data, list) and data and all(isinstance(item, dict) for item in data):
        record_tables.append(("", data))
    elif isinstance(data, list):
        if not data:
            return ["No entries were reported."]
        simple_rows.extend([[f"Item {index}", _md_value(item)] for index, item in enumerate(data, 1)])
    else:
        simple_rows.append(["Value", _md_value(data)])

    lines: list[str] = []
    if simple_rows:
        lines.extend(_md_table(["Field", "Value"], simple_rows))

    for key, child_dict in nested_dicts:
        if lines:
            lines.append("")
        lines.extend([_md_sublabel(heading_level, _md_label(key)), ""])
        child_rows: list[list[str]] = []
        deeper_sections: list[tuple[str, Any]] = []
        for subkey, subval in child_dict.items():
            if isinstance(subval, dict) and subval:
                deeper_sections.append((subkey, subval))
            elif isinstance(subval, list) and subval and all(isinstance(item, dict) for item in subval) and not _is_option_list(subval):
                deeper_sections.append((subkey, subval))
            else:
                child_rows.append([_md_label(subkey), _md_value(subval, subkey, key.casefold())])
        if child_rows:
            lines.extend(_md_table(["Field", "Value"], child_rows))
        for subkey, subval in deeper_sections:
            if lines and lines[-1] != "":
                lines.append("")
            lines.extend([_md_sublabel(heading_level + 1, _md_label(subkey)), ""])
            lines.extend(_md_render_generic(subval, heading_level=heading_level + 2))

    for title, records in record_tables:
        if lines:
            lines.append("")
        if title:
            lines.extend([_md_sublabel(heading_level, title), ""])
        columns = _record_columns(records)
        if not columns:
            lines.extend(_md_table(["#", "Details"], [["1", "No details"]]))
            continue
        has_complex_cells = any(
            isinstance(record.get(col), dict)
            or (isinstance(record.get(col), list) and bool(record.get(col)) and not _is_option_list(record.get(col))
                and any(isinstance(item, dict) for item in record[col]))
            for record in records
            for col in columns
        )
        if has_complex_cells or len(columns) > 6:
            for index, record in enumerate(records, 1):
                if index > 1:
                    lines.append("")
                item_title = f"{title or 'Entry'} {index}"
                lines.extend([_md_sublabel(heading_level + 1, item_title), ""])
                lines.extend(_md_render_generic(record, heading_level=heading_level + 2))
        else:
            rows = [
                [str(index), *[_md_value(record.get(col), col) for col in columns]]
                for index, record in enumerate(records, 1)
            ]
            lines.extend(_md_table(["#", *[_md_label(col) for col in columns]], rows))

    return lines or ["No details were available."]


def _md_overview(sections: dict[str, Any]) -> list[str]:
    """Build a concise 'At a glance' table from available snapshot sections only."""
    rows: list[list[str]] = []

    os_data = sections.get("os")
    desktop_data = sections.get("desktop")
    os_summary_parts: list[str] = []
    if isinstance(os_data, dict) and os_data.get("available") is not False:
        distro = _md_normalize_text(str(os_data.get("distribution") or ""))
        version = _md_normalize_text(str(os_data.get("distribution_version") or ""))
        if distro and version and version not in distro:
            os_summary_parts.append(f"{distro} {version}")
        elif distro or version:
            os_summary_parts.append(distro or version)
        else:
            kernel = " ".join(
                part
                for part in (
                    _md_normalize_text(str(os_data.get("kernel_name") or "")),
                    _md_normalize_text(str(os_data.get("kernel_release") or "")),
                )
                if part
            )
            if kernel:
                os_summary_parts.append(kernel)
    desktop_parts: list[str] = []
    if isinstance(desktop_data, dict) and desktop_data.get("available") is not False:
        de = _md_normalize_text(str(desktop_data.get("desktop_environment") or ""))
        stype = _md_normalize_text(str(desktop_data.get("session_type") or ""))
        if de:
            desktop_parts.append(de)
        if stype:
            desktop_parts.append("X11" if stype.casefold() == "x11" else stype.capitalize())
    if os_summary_parts or desktop_parts:
        base = os_summary_parts[0] if os_summary_parts else ""
        if base and desktop_parts:
            rows.append(["Operating system", f"{base} ({', '.join(desktop_parts)})"])
        elif base:
            rows.append(["Operating system", base])
        else:
            rows.append(["Desktop", ", ".join(desktop_parts)])

    cpu_data = sections.get("cpu")
    if isinstance(cpu_data, dict) and cpu_data.get("available") is not False:
        cpu_parts: list[str] = []
        model = _md_normalize_text(str(cpu_data.get("model") or ""))
        if model:
            cpu_parts.append(model)
        physical = cpu_data.get("physical_cores")
        logical = cpu_data.get("logical_processors")
        if isinstance(physical, int) and not isinstance(physical, bool) and isinstance(logical, int) and not isinstance(logical, bool):
            cpu_parts.append(f"{physical} cores" if physical == logical else f"{physical} cores / {logical} threads")
        elif isinstance(physical, int) and not isinstance(physical, bool):
            cpu_parts.append(f"{physical} physical cores")
        elif isinstance(logical, int) and not isinstance(logical, bool):
            cpu_parts.append(f"{logical} logical processors")
        if cpu_parts:
            rows.append(["CPU", " · ".join(cpu_parts)])

    memory_data = sections.get("memory")
    if isinstance(memory_data, dict) and memory_data.get("available") is not False:
        ram = memory_data.get("ram")
        if isinstance(ram, dict):
            summary = _md_pool_summary(ram)
            if summary:
                rows.append(["RAM", summary])
        swap = memory_data.get("swap")
        if isinstance(swap, dict):
            total = swap.get("total_bytes")
            if _is_number(total) and float(total) == 0:
                rows.append(["Swap", "Not configured (0 B)"])
            else:
                summary = _md_pool_summary(swap)
                if summary:
                    rows.append(["Swap", summary])

    graphics_data = sections.get("graphics")
    if isinstance(graphics_data, dict) and graphics_data.get("available") is not False:
        devices = graphics_data.get("devices")
        if isinstance(devices, list):
            gpu_names: list[str] = []
            for gpu in devices:
                if not isinstance(gpu, dict):
                    continue
                label = _md_normalize_text(str(gpu.get("model") or gpu.get("identity") or gpu.get("driver") or ""))
                if label:
                    gpu_names.append(label)
            if gpu_names:
                rows.append(["Graphics", "; ".join(gpu_names)])
            elif not devices:
                rows.append(["Graphics", "No GPUs reported"])

    storage_data = sections.get("storage")
    if isinstance(storage_data, dict) and storage_data.get("available") is not False:
        devices = storage_data.get("devices")
        if isinstance(devices, list):
            dict_devices = [d for d in devices if isinstance(d, dict)]
            primary_candidates = [
                d for d in dict_devices
                if "optical" not in str(d.get("storage_type") or "").casefold()
            ] or dict_devices
            drive_summaries: list[str] = []
            for drive in primary_candidates[:2]:
                name = _md_normalize_text(str(drive.get("model") or drive.get("device_name") or drive.get("device_path") or ""))
                cap = _md_bytes(drive.get("capacity_bytes")) if _is_number(drive.get("capacity_bytes")) else ""
                if name and cap:
                    drive_summaries.append(f"{name} · {cap}")
                elif name or cap:
                    drive_summaries.append(name or cap)
            if drive_summaries:
                extra = len(primary_candidates) - len(drive_summaries)
                text = "; ".join(drive_summaries)
                if extra > 0:
                    text += f" (+{extra} more)"
                rows.append(["Primary storage", text])

    network_data = sections.get("network")
    if isinstance(network_data, dict) and network_data.get("available") is not False:
        interfaces = network_data.get("interfaces")
        if isinstance(interfaces, list):
            dict_ifaces = [item for item in interfaces if isinstance(item, dict)]
            total_count = len(dict_ifaces)
            connected = sum(
                1 for item in dict_ifaces
                if str(item.get("connection_state") or "").casefold() == "connected"
            )
            if total_count == 0:
                rows.append(["Network", "No interfaces reported"])
            else:
                noun = "interface" if total_count == 1 else "interfaces"
                rows.append(["Network", f"{total_count} {noun} ({connected} connected)"])

    if not rows:
        return []
    return ["", "## At a glance", "", *_md_table(["Component", "Summary"], rows)]


def _md_pool_summary(pool: dict[str, Any]) -> str:
    used = pool.get("used_bytes")
    total = pool.get("total_bytes")
    pct = pool.get("percent_used")
    if _is_number(used) and _is_number(total):
        base = f"{_md_bytes(used)} used / {_md_bytes(total)} total"
        return f"{base} ({_md_percent(pct)})" if _is_number(pct) else base
    if _is_number(total):
        return f"{_md_bytes(total)} total"
    if _is_number(used):
        return f"{_md_bytes(used)} used"
    return ""


def _md_render_os(data: dict[str, Any]) -> list[str]:
    if data.get("available") is False:
        return ["Operating system information could not be collected."]
    handled = {
        "distribution", "distribution_version", "os_architecture", "kernel_name",
        "kernel_release", "kernel_version", "hostname", "uptime_seconds",
        "boot_mode", "identification", "kernel_command_line",
    }
    distro = _md_normalize_text(str(data.get("distribution") or ""))
    version = _md_normalize_text(str(data.get("distribution_version") or ""))
    if distro and version and version not in distro:
        distro_text = f"{distro} {version}"
    else:
        distro_text = distro or version or "Not available"

    kernel_name = _md_normalize_text(str(data.get("kernel_name") or ""))
    kernel_release = _md_normalize_text(str(data.get("kernel_release") or ""))
    kernel_text = " ".join(part for part in (kernel_name, kernel_release) if part) or "Not available"

    rows: list[list[str]] = [
        ["Distribution", distro_text],
        ["Architecture", _md_text(data.get("os_architecture"))],
        ["Kernel", kernel_text],
        ["Kernel build", _md_text(data.get("kernel_version"))],
        ["Hostname", _md_text(data.get("hostname"))],
        ["Uptime", _md_uptime(data.get("uptime_seconds"))],
        ["Boot mode", _md_text(data.get("boot_mode"))],
    ]
    for key, value in data.items():
        if key not in handled and not isinstance(value, (dict, list)):
            rows.append([_md_label(key), _md_value(value, key)])
    lines = _md_table(["Property", "Value"], rows)

    identification = data.get("identification")
    if isinstance(identification, dict) and identification:
        id_rows = [[_md_label(key), _md_text(val)] for key, val in identification.items()]
        lines.extend(["", "### Machine and Firmware", "", *_md_table(["Property", "Value"], id_rows)])

    cmdline = data.get("kernel_command_line")
    if isinstance(cmdline, list):
        lines.extend(["", "### Kernel Command Line", ""])
        tokens: list[str] = []
        for item in cmdline:
            if isinstance(item, dict):
                param = _md_normalize_text(str(item.get("parameter") or ""))
                val = item.get("value")
                if not param:
                    continue
                if val == "present" or val is None:
                    tokens.append(param)
                elif _is_option_list(val):
                    tokens.append(f"{param}={_format_option_list(val).replace(', ', ',')}")
                else:
                    tokens.append(f"{param}={_md_normalize_text(str(val))}")
            elif isinstance(item, str):
                cleaned = _md_normalize_text(item)
                if cleaned:
                    tokens.append(cleaned)
        if tokens:
            lines.extend(_md_code_block(" ".join(tokens), "text"))
        else:
            lines.append("No safe kernel command-line parameters were reported.")

    for key, value in data.items():
        if key not in handled and isinstance(value, (dict, list)):
            lines.extend(["", _md_heading(3, _md_label(key)), "", *_md_render_generic(value, heading_level=4)])
    return lines


def _md_render_desktop(data: dict[str, Any]) -> list[str]:
    if data.get("available") is False:
        return ["Desktop environment information could not be collected."]
    handled = {
        "desktop_environment", "session", "session_type", "window_manager",
        "screens", "qt_version", "pyside_version",
    }
    session_type = data.get("session_type")
    if isinstance(session_type, str) and session_type.strip().casefold() == "x11":
        session_type_text = "X11"
    elif isinstance(session_type, str) and session_type.strip():
        session_type_text = _md_normalize_text(session_type)
    else:
        session_type_text = "Not available"

    qt_ver = _md_normalize_text(str(data.get("qt_version") or ""))
    pyside_ver = _md_normalize_text(str(data.get("pyside_version") or ""))
    qt_pyside = f"{qt_ver or 'Not available'} / {pyside_ver or 'Not available'}" if (qt_ver or pyside_ver) else "Not available"

    rows: list[list[str]] = [
        ["Desktop environment", _md_text(data.get("desktop_environment"))],
        ["Session", _md_text(data.get("session"))],
        ["Session type", session_type_text],
        ["Window manager", _md_text(data.get("window_manager"))],
        ["Qt / PySide", qt_pyside],
    ]
    for key, value in data.items():
        if key not in handled and not isinstance(value, (dict, list)):
            rows.append([_md_label(key), _md_value(value, key)])
    lines = _md_table(["Property", "Value"], rows)

    screens = data.get("screens")
    if isinstance(screens, list):
        lines.extend(["", "### Displays", ""])
        screen_rows: list[list[str]] = []
        for idx, screen in enumerate(screens, 1):
            if not isinstance(screen, dict):
                continue
            width = screen.get("width")
            height = screen.get("height")
            resolution = f"{width} × {height}" if (_is_number(width) and _is_number(height)) else "Not available"
            scale = screen.get("scale")
            if _is_number(scale):
                numeric_scale = float(scale)
                scale_text = f"{numeric_scale:.1f}x" if round(numeric_scale, 1) == round(numeric_scale, 2) else f"{numeric_scale:.2f}x"
            else:
                scale_text = "Not available"
            screen_rows.append([str(idx), resolution, scale_text])
        if screen_rows:
            lines.extend(_md_table(["Display", "Resolution", "Scale"], screen_rows))
        else:
            lines.append("No display details were reported.")

    for key, value in data.items():
        if key not in handled and isinstance(value, (dict, list)):
            lines.extend(["", _md_heading(3, _md_label(key)), "", *_md_render_generic(value, heading_level=4)])
    return lines


def _md_render_cpu(data: dict[str, Any]) -> list[str]:
    if data.get("available") is False:
        return ["CPU information could not be collected."]
    handled = {
        "model", "architecture", "physical_cores", "logical_processors",
        "current_frequency_mhz", "capabilities", "temperature_c",
    }
    physical = data.get("physical_cores")
    logical = data.get("logical_processors")
    if physical is None and logical is None:
        cores_text = "Not available"
    else:
        p_text = str(physical) if physical is not None else "Not available"
        l_text = str(logical) if logical is not None else "Not available"
        cores_text = f"{p_text} / {l_text}"

    rows: list[list[str]] = [
        ["Model", _md_text(data.get("model"))],
        ["Architecture", _md_text(data.get("architecture"))],
        ["Physical / logical cores", cores_text],
        ["Current frequency", _md_freq_mhz(data.get("current_frequency_mhz"))],
        ["Temperature", _md_temp(data.get("temperature_c"))],
    ]
    for key, value in data.items():
        if key not in handled and not isinstance(value, (dict, list)):
            rows.append([_md_label(key), _md_value(value, key)])
    lines = _md_table(["Metric", "Value"], rows)

    capabilities = data.get("capabilities")
    if isinstance(capabilities, list):
        clean_flags = [_md_normalize_text(str(flag)) for flag in capabilities if _md_normalize_text(str(flag))]
        lines.extend(["", "### CPU Capabilities", ""])
        if clean_flags:
            lines.extend([f"{len(clean_flags)} reported flags:", ""])
            for start in range(0, len(clean_flags), 10):
                chunk = clean_flags[start : start + 10]
                lines.append("- " + ", ".join(_md_code_span(flag) for flag in chunk))
        else:
            lines.append("No CPU capability flags were reported.")

    for key, value in data.items():
        if key not in handled and isinstance(value, (dict, list)):
            lines.extend(["", _md_heading(3, _md_label(key)), "", *_md_render_generic(value, heading_level=4)])
    return lines


def _md_render_memory(data: dict[str, Any]) -> list[str]:
    if data.get("available") is False:
        return ["Memory information could not be collected."]
    handled = {"ram", "swap", "kernel_memory_details", "configuration"}
    pool_rows: list[list[str]] = []

    ram = data.get("ram")
    if isinstance(ram, dict):
        pool_rows.append([
            "RAM",
            _md_bytes(ram.get("used_bytes")),
            _md_bytes(ram.get("available_bytes")),
            _md_bytes(ram.get("total_bytes")),
            _md_percent(ram.get("percent_used")),
        ])
    elif "ram" in data:
        pool_rows.append(["RAM", "Not available", "Not available", "Not available", "Not available"])

    swap = data.get("swap")
    if isinstance(swap, dict):
        total = swap.get("total_bytes")
        usage = "Not configured" if (_is_number(total) and float(total) == 0) else _md_percent(swap.get("percent_used"))
        pool_rows.append([
            "Swap",
            _md_bytes(swap.get("used_bytes")),
            _md_bytes(swap.get("available_bytes")),
            _md_bytes(total),
            usage,
        ])
    elif "swap" in data:
        pool_rows.append(["Swap", "Not available", "Not available", "Not available", "Not available"])

    lines: list[str] = []
    if pool_rows:
        lines.extend(_md_table(["Pool", "Used", "Available", "Total", "Usage"], pool_rows))

    detail_rows: list[list[str]] = []
    if isinstance(ram, dict):
        if "cached_bytes" in ram:
            detail_rows.append(["RAM Cached", _md_bytes(ram.get("cached_bytes"))])
        if "buffers_bytes" in ram:
            detail_rows.append(["RAM Buffers", _md_bytes(ram.get("buffers_bytes"))])
        for key, value in ram.items():
            if key not in {"total_bytes", "available_bytes", "used_bytes", "percent_used", "cached_bytes", "buffers_bytes"}:
                detail_rows.append([f"RAM {_md_label(key)}", _md_value(value, key)])
    if isinstance(swap, dict):
        for key, value in swap.items():
            if key not in {"total_bytes", "available_bytes", "used_bytes", "percent_used"}:
                detail_rows.append([f"Swap {_md_label(key)}", _md_value(value, key)])

    kernel_details = data.get("kernel_memory_details")
    if isinstance(kernel_details, dict) and kernel_details:
        for key, value in kernel_details.items():
            lowered = key.casefold()
            if lowered == "cached":
                label = "Kernel Cached"
            elif lowered == "buffers":
                label = "Kernel Buffers"
            else:
                label = _md_label(key)
            formatted = _md_int_count(value) if lowered == "hugepages_total" else _md_value(value, key, "kernel_memory_details")
            detail_rows.append([label, formatted])

    if detail_rows:
        if lines:
            lines.append("")
        lines.extend(["### Memory Details", "", *_md_table(["Metric", "Value"], detail_rows)])

    config = data.get("configuration")
    if isinstance(config, dict) and config:
        if lines:
            lines.append("")
        config_rows = [[_md_label(key), _md_value(val, key)] for key, val in config.items()]
        lines.extend(["### Virtual Memory Configuration", "", *_md_table(["Parameter", "Value"], config_rows)])

    for key, value in data.items():
        if key not in handled:
            if lines:
                lines.append("")
            lines.extend([_md_heading(3, _md_label(key)), "", *_md_render_generic(value, heading_level=4)])
    return lines or ["No memory details were available."]


def _md_render_graphics(data: dict[str, Any]) -> list[str]:
    if data.get("available") is False:
        return ["Graphics hardware information could not be collected."]
    devices = data.get("devices")
    lines: list[str] = []
    if isinstance(devices, list):
        if not devices:
            lines.append("No graphics devices were reported.")
        for index, gpu in enumerate(devices, 1):
            if not isinstance(gpu, dict):
                continue
            if lines:
                lines.append("")
            title_name = _md_normalize_text(str(gpu.get("model") or gpu.get("identity") or f"Device {index}"))
            lines.extend([_md_heading(3, f"GPU {index}: {title_name}"), ""])
            handled_gpu = {
                "identity", "model", "pci_vendor_id", "pci_device_id", "driver",
                "memory_pools", "utilization_percent", "telemetry_capabilities", "sensors",
            }
            vendor = _md_normalize_text(str(gpu.get("pci_vendor_id") or ""))
            device_id = _md_normalize_text(str(gpu.get("pci_device_id") or ""))
            if vendor and device_id:
                pci_text = f"{vendor} / {device_id}"
            elif vendor or device_id:
                pci_text = vendor or device_id
            else:
                pci_text = "Not available"

            prop_rows: list[list[str]] = [
                ["Identity", _md_text(gpu.get("identity"))],
                ["Driver", _md_text(gpu.get("driver"))],
                ["PCI Vendor / Device", pci_text],
                ["Utilization", _md_percent(gpu.get("utilization_percent"))],
            ]
            for key, value in gpu.items():
                if key not in handled_gpu and not isinstance(value, (dict, list)):
                    prop_rows.append([_md_label(key), _md_value(value, key)])
            lines.extend(_md_table(["Property", "Value"], prop_rows))

            pools = gpu.get("memory_pools")
            if isinstance(pools, dict) and pools:
                pool_rows: list[list[str]] = []
                notes: list[str] = []
                for pool_key, pool_data in pools.items():
                    if not isinstance(pool_data, dict):
                        continue
                    lowered_pool = pool_key.casefold()
                    if "vram" in lowered_pool:
                        pool_label = "VRAM"
                    elif "gtt" in lowered_pool:
                        pool_label = "GTT"
                    else:
                        pool_label = _md_label(pool_key)
                    pool_rows.append([
                        pool_label,
                        _md_bytes(pool_data.get("used_bytes")),
                        _md_bytes(pool_data.get("total_bytes")),
                    ])
                    classification = _md_normalize_text(str(pool_data.get("classification") or ""))
                    if classification and classification not in notes:
                        notes.append(classification)
                if pool_rows:
                    lines.extend(["", "#### Memory Pools", "", *_md_table(["Reported Pool", "Used", "Total"], pool_rows)])
                    for note in notes:
                        lines.extend(["", f"*{_md_escape(note)}*"])

            sensors = gpu.get("sensors")
            if isinstance(sensors, dict):
                lines.extend(["", "#### Sensors", ""])
                if sensors:
                    sensor_rows = [
                        [_md_label(sensor_name), _md_gpu_sensor_reading(sensor_name, sensor_val)]
                        for sensor_name, sensor_val in sensors.items()
                    ]
                    lines.extend(_md_table(["Sensor", "Reading"], sensor_rows))
                else:
                    lines.append("No GPU sensor readings were reported.")

            caps = gpu.get("telemetry_capabilities")
            if isinstance(caps, list):
                clean_caps = [_md_normalize_text(str(cap)) for cap in caps if _md_normalize_text(str(cap))]
                lines.extend(["", "#### Telemetry Capabilities", ""])
                if clean_caps:
                    lines.append(", ".join(_md_code_span(cap) for cap in clean_caps))
                else:
                    lines.append("No telemetry capabilities were reported.")

            for key, value in gpu.items():
                if key not in handled_gpu and isinstance(value, (dict, list)):
                    lines.extend(["", _md_heading(4, _md_label(key)), "", *_md_render_generic(value, heading_level=4)])

    for key, value in data.items():
        if key != "devices":
            if lines:
                lines.append("")
            lines.extend([_md_heading(3, _md_label(key)), "", *_md_render_generic(value, heading_level=4)])
    return lines or ["No graphics hardware details were available."]


def _md_render_storage(data: dict[str, Any]) -> list[str]:
    if data.get("available") is False:
        return ["Storage hardware information could not be collected."]
    lines: list[str] = []

    devices = data.get("devices")
    if isinstance(devices, list):
        lines.extend(["### Physical Storage Devices", ""])
        dev_rows: list[list[str]] = []
        for disk in devices:
            if not isinstance(disk, dict):
                continue
            dev_name = _md_normalize_text(str(disk.get("device_name") or ""))
            dev_path = _md_normalize_text(str(disk.get("device_path") or ""))
            if dev_name and dev_path and dev_path not in {dev_name, f"/dev/{dev_name}"}:
                dev_label = f"{dev_name} ({dev_path})"
            else:
                dev_label = dev_name or dev_path or "Not available"
            dev_rows.append([
                dev_label,
                _md_text(disk.get("model")),
                _md_text(disk.get("storage_type")),
                _md_bytes(disk.get("capacity_bytes")),
                _md_temp(disk.get("temperature_c")),
                _md_text(disk.get("temperature_supported")),
            ])
        if dev_rows:
            lines.extend(
                _md_table(["Device", "Model", "Type", "Capacity", "Temperature", "Temp. Supported"], dev_rows)
            )
        else:
            lines.append("No storage devices were reported.")

    partitions = data.get("partitions")
    if isinstance(partitions, list):
        if lines:
            lines.append("")
        lines.extend(["### Partitions", ""])
        part_rows: list[list[str]] = []
        for part in partitions:
            if not isinstance(part, dict):
                continue
            part_rows.append([
                _md_text(part.get("device_path")),
                _md_text(part.get("parent_device")),
                _md_text(part.get("partition_number")),
                _md_bytes(part.get("capacity_bytes")),
            ])
        if part_rows:
            lines.extend(_md_table(["Partition", "Parent", "Number", "Capacity"], part_rows))
        else:
            lines.append("No partitions were reported.")

    for key, value in data.items():
        if key not in {"devices", "partitions"}:
            if lines:
                lines.append("")
            lines.extend([_md_heading(3, _md_label(key)), "", *_md_render_generic(value, heading_level=4)])
    return lines or ["No storage details were available."]


def _md_render_filesystems(data: dict[str, Any]) -> list[str]:
    if data.get("available") is False:
        return ["Filesystem and mount information could not be collected."]
    lines: list[str] = []

    mountinfo_avail = data.get("mountinfo_available")
    fstab = data.get("fstab")
    fstab_avail = fstab.get("available") if isinstance(fstab, dict) else None
    status_items: list[str] = []
    if mountinfo_avail is not None:
        status_items.append(f"- **Mount data available:** {_md_text(mountinfo_avail)}")
    if fstab_avail is not None:
        status_items.append(f"- **fstab available:** {_md_text(fstab_avail)}")
    if status_items:
        lines.extend(status_items)

    mounts = data.get("mounts")
    if isinstance(mounts, list):
        dict_mounts = [m for m in mounts if isinstance(m, dict)]
        volume_rows: list[list[str]] = []
        virtual_rows: list[list[str]] = []
        option_bullets: list[str] = []

        for mount in dict_mounts:
            mountpoint = _md_text(mount.get("mountpoint"))
            fstype = _md_text(mount.get("filesystem_type"))
            source = _md_text(mount.get("source"))
            capacity = mount.get("capacity")
            if isinstance(capacity, dict):
                used_total = f"{_md_bytes(capacity.get('used_bytes'))} / {_md_bytes(capacity.get('total_bytes'))}"
                volume_rows.append([
                    mountpoint,
                    fstype,
                    source,
                    used_total,
                    _md_bytes(capacity.get("available_bytes")),
                    _md_percent(capacity.get("percent_used")),
                ])
            else:
                virtual_rows.append([mountpoint, fstype, source])

            dev_num = _md_normalize_text(str(mount.get("device_number") or ""))
            root_path = _md_normalize_text(str(mount.get("root") or ""))
            opts_text = _format_option_list(mount.get("options"))
            super_text = _format_option_list(mount.get("super_options"))
            id_bits: list[str] = []
            if dev_num:
                id_bits.append(f"device {_md_code_span(dev_num)}")
            if root_path:
                id_bits.append(f"root {_md_code_span(root_path)}")
            id_prefix = f" ({', '.join(id_bits)})" if id_bits else ""
            option_bullets.append(
                f"- **{_md_escape(mountpoint)}**{id_prefix}: "
                f"options {_md_code_span(opts_text)}; super options {_md_code_span(super_text)}"
            )

        if volume_rows:
            if lines:
                lines.append("")
            lines.extend([
                "### Mounted Volumes",
                "",
                *_md_table(["Mount", "Filesystem", "Source", "Used / Total", "Available", "Usage"], volume_rows),
            ])
        if virtual_rows:
            if lines:
                lines.append("")
            lines.extend([
                "### System and Virtual Mounts",
                "",
                *_md_table(["Mount", "Filesystem", "Source"], virtual_rows),
            ])
        if not volume_rows and not virtual_rows:
            if lines:
                lines.append("")
            lines.extend(["### Mounted Volumes", "", "No mounted filesystems were reported."])
        if option_bullets:
            if lines:
                lines.append("")
            lines.extend(["### Mount Options and Identifiers", "", *option_bullets])

    if isinstance(fstab, dict):
        entries = fstab.get("entries")
        if isinstance(entries, list):
            if lines:
                lines.append("")
            lines.extend(["### Configured `/etc/fstab` Entries", ""])
            comment_count = 0
            blank_count = 0
            entry_rows: list[list[str]] = []
            invalid_notes: list[str] = []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                rtype = entry.get("record_type")
                if rtype == "comment":
                    comment_count += 1
                elif rtype == "blank":
                    blank_count += 1
                elif rtype == "invalid":
                    line_no = entry.get("line", "?")
                    fields_n = entry.get("field_count", "?")
                    invalid_notes.append(f"- Line {_md_escape(str(line_no))}: invalid entry ({_md_escape(str(fields_n))} fields)")
                else:
                    dump_val = entry.get("dump")
                    pass_val = entry.get("pass")
                    dump_pass = f"{dump_val} / {pass_val}" if (dump_val is not None or pass_val is not None) else "Not available"
                    entry_rows.append([
                        _md_text(entry.get("line")),
                        _md_text(entry.get("source")),
                        _md_text(entry.get("mountpoint")),
                        _md_text(entry.get("filesystem_type")),
                        _format_option_list(entry.get("options")),
                        dump_pass,
                    ])
            omitted: list[str] = []
            if comment_count:
                omitted.append(f"{comment_count} comment {'line' if comment_count == 1 else 'lines'}")
            if blank_count:
                omitted.append(f"{blank_count} blank {'line' if blank_count == 1 else 'lines'}")
            if omitted:
                lines.extend([f"*{', '.join(omitted)} omitted.*", ""])
            if entry_rows:
                lines.extend(_md_table(["Line", "Source", "Mount", "Type", "Options", "Dump / Pass"], entry_rows))
            elif not invalid_notes:
                lines.append("No active fstab entries were reported.")
            if invalid_notes:
                if entry_rows:
                    lines.append("")
                lines.extend(["#### Invalid fstab Lines", "", *invalid_notes])

    for key, value in data.items():
        if key not in {"mounts", "mountinfo_available", "fstab"}:
            if lines:
                lines.append("")
            lines.extend([_md_heading(3, _md_label(key)), "", *_md_render_generic(value, heading_level=4)])
    return lines or ["No filesystem details were available."]


def _md_render_network(data: dict[str, Any]) -> list[str]:
    if data.get("available") is False:
        return ["Network configuration could not be collected."]
    lines: list[str] = []

    meta_items: list[str] = []
    for key, label in (
        ("addresses_available", "Address data"),
        ("interface_stats_available", "Interface statistics"),
        ("counters_available", "Traffic counters"),
    ):
        if key in data:
            meta_items.append(f"- **{label}:** {_md_text(data.get(key))}")
    dns = data.get("dns")
    if isinstance(dns, dict):
        ns = [_md_normalize_text(str(item)) for item in (dns.get("nameservers") or []) if _md_normalize_text(str(item))]
        sd = [_md_normalize_text(str(item)) for item in (dns.get("search_domains") or []) if _md_normalize_text(str(item))]
        meta_items.append(f"- **DNS nameservers:** {_md_escape(', '.join(ns)) if ns else 'None'}")
        meta_items.append(f"- **DNS search domains:** {_md_escape(', '.join(sd)) if sd else 'None'}")
    elif "dns" in data:
        meta_items.append("- **DNS configuration:** Not available")
    if meta_items:
        lines.extend(meta_items)

    interfaces = data.get("interfaces")
    if isinstance(interfaces, list):
        dict_ifaces = [item for item in interfaces if isinstance(item, dict)]
        if lines:
            lines.append("")
        lines.extend(["### Interface Summary", ""])
        if not dict_ifaces:
            lines.append("No network interfaces were reported.")
        else:
            summary_rows: list[list[str]] = []
            for index, iface in enumerate(dict_ifaces, 1):
                counters = iface.get("counters") if isinstance(iface.get("counters"), dict) else None
                summary_rows.append([
                    _md_text(iface.get("interface"), missing=f"Interface {index}"),
                    _md_text(iface.get("type")),
                    _md_text(iface.get("connection_state")),
                    _md_text(iface.get("driver")),
                    _md_bytes(counters.get("bytes_received")) if counters else "Not available",
                    _md_bytes(counters.get("bytes_transmitted")) if counters else "Not available",
                ])
            lines.extend(
                _md_table(["Interface", "Type", "State", "Driver", "Received", "Transmitted"], summary_rows)
            )

            lines.extend(["", "### Interface Details"])
            for index, iface in enumerate(dict_ifaces, 1):
                name = _md_text(iface.get("interface"), missing=f"Interface {index}")
                kind = _md_normalize_text(str(iface.get("type") or ""))
                heading_text = f"{name} ({kind})" if kind else name
                lines.extend(["", _md_heading(4, heading_text), ""])
                lines.extend([
                    f"- **State:** {_md_escape(_md_text(iface.get('connection_state')))}",
                    f"- **Driver:** {_md_escape(_md_text(iface.get('driver')))}",
                    f"- **Link speed:** {_md_escape(_md_speed_mbps(iface.get('link_speed_mbps')))}",
                    f"- **Auxiliary:** {_md_escape(_md_text(iface.get('auxiliary')))}",
                ])

                addresses = iface.get("addresses")
                if isinstance(addresses, list):
                    lines.extend(["", "**Addresses**", ""])
                    addr_rows = [
                        [
                            _md_text(addr.get("family")),
                            _md_text(addr.get("address")),
                            _md_text(addr.get("netmask")),
                            _md_text(addr.get("broadcast")),
                        ]
                        for addr in addresses
                        if isinstance(addr, dict)
                    ]
                    if addr_rows:
                        lines.extend(_md_table(["Family", "Address", "Netmask", "Broadcast"], addr_rows))
                    else:
                        lines.append("No addresses reported.")

                counters = iface.get("counters") if isinstance(iface.get("counters"), dict) else None
                rates = iface.get("rates") if isinstance(iface.get("rates"), dict) else None
                if counters is not None or rates is not None:
                    lines.extend(["", "**Traffic**", ""])
                    traffic_rows = [
                        [
                            "Received",
                            _md_bytes(counters.get("bytes_received")) if counters else "Not available",
                            _md_rate(rates.get("receive_bytes_per_second")) if rates else "Not available",
                            _md_int_count(counters.get("packets_received")) if counters else "Not available",
                            _md_int_count(counters.get("errors_in")) if counters else "Not available",
                            _md_int_count(counters.get("dropped_in")) if counters else "Not available",
                        ],
                        [
                            "Transmitted",
                            _md_bytes(counters.get("bytes_transmitted")) if counters else "Not available",
                            _md_rate(rates.get("transmit_bytes_per_second")) if rates else "Not available",
                            _md_int_count(counters.get("packets_transmitted")) if counters else "Not available",
                            _md_int_count(counters.get("errors_out")) if counters else "Not available",
                            _md_int_count(counters.get("dropped_out")) if counters else "Not available",
                        ],
                    ]
                    lines.extend(
                        _md_table(["Direction", "Data", "Rate", "Packets", "Errors", "Dropped"], traffic_rows)
                    )

                handled_iface = {
                    "interface", "type", "auxiliary", "connection_state", "driver",
                    "link_speed_mbps", "addresses", "counters", "rates",
                }
                for key, value in iface.items():
                    if key not in handled_iface:
                        lines.extend(["", f"**{_md_escape(_md_label(key))}**", "", *_md_render_generic(value, heading_level=4)])

    ipv4_routes = data.get("ipv4_routes")
    if "ipv4_routes" in data:
        if lines:
            lines.append("")
        lines.extend(["### IPv4 Routes", ""])
        if ipv4_routes is None:
            lines.append("IPv4 route information is not available.")
        elif isinstance(ipv4_routes, list) and ipv4_routes:
            route_rows = [
                [
                    _md_text(r.get("interface")),
                    _md_text(r.get("destination")),
                    _md_text(r.get("gateway")),
                    _md_text(r.get("netmask")),
                    _md_text(r.get("metric")),
                ]
                for r in ipv4_routes
                if isinstance(r, dict)
            ]
            lines.extend(_md_table(["Interface", "Destination", "Gateway", "Netmask", "Metric"], route_rows))
        else:
            lines.append("No IPv4 routes were reported.")

    ipv6_routes = data.get("ipv6_routes")
    if "ipv6_routes" in data:
        if lines:
            lines.append("")
        lines.extend(["### IPv6 Routes", ""])
        if ipv6_routes is None:
            lines.append("IPv6 route information is not available.")
        elif isinstance(ipv6_routes, list) and ipv6_routes:
            route_rows = [
                [
                    _md_text(r.get("interface")),
                    _md_text(r.get("destination")),
                    _md_text(r.get("gateway")),
                    _md_text(r.get("metric")),
                ]
                for r in ipv6_routes
                if isinstance(r, dict)
            ]
            lines.extend(_md_table(["Interface", "Destination", "Gateway", "Metric"], route_rows))
        else:
            lines.append("No IPv6 routes were reported.")

    handled_net = {
        "interfaces", "addresses_available", "interface_stats_available",
        "counters_available", "ipv4_routes", "ipv6_routes", "dns",
    }
    for key, value in data.items():
        if key not in handled_net:
            if lines:
                lines.append("")
            lines.extend([_md_heading(3, _md_label(key)), "", *_md_render_generic(value, heading_level=4)])
    return lines or ["No network details were available."]


def _md_render_sensors(data: dict[str, Any]) -> list[str]:
    if data.get("available") is False:
        return ["Hardware sensor information could not be collected."]
    lines: list[str] = []

    availability: list[str] = []
    if "temperatures_available" in data:
        availability.append(f"- **Temperature sensors available:** {_md_text(data.get('temperatures_available'))}")
    if "fan_speeds_available" in data:
        availability.append(f"- **Fan sensors available:** {_md_text(data.get('fan_speeds_available'))}")
    if availability:
        lines.extend(availability)

    groups = (
        ("temperatures", "Temperatures", "Temperature", "value_c", _md_temp),
        ("drive_temperatures", "Drive Temperatures", "Temperature", "value_c", _md_temp),
        ("fan_speeds", "Fan Speeds", "Speed", "value_rpm", _md_rpm),
        ("power_readings", "Power Readings", "Power", "value_w", _md_watts),
        ("clock_readings", "Clock Readings", "Frequency", "value_mhz", _md_freq_mhz),
    )
    empty_groups: list[str] = []
    for key, heading, metric_col, value_key, formatter in groups:
        entries = data.get(key)
        if not isinstance(entries, list):
            continue
        rows = [
            [
                _md_text(item.get("device")),
                _md_text(item.get("name")),
                formatter(item.get(value_key)),
            ]
            for item in entries
            if isinstance(item, dict)
        ]
        if rows:
            if lines:
                lines.append("")
            lines.extend([f"### {heading}", "", *_md_table(["Device", "Sensor", metric_col], rows)])
        else:
            empty_groups.append(heading.casefold())

    if empty_groups:
        if lines:
            lines.append("")
        lines.append(f"No readings were reported for: {', '.join(empty_groups)}.")

    handled = {
        "temperatures_available", "fan_speeds_available",
        "temperatures", "drive_temperatures", "fan_speeds", "power_readings", "clock_readings",
    }
    for key, value in data.items():
        if key not in handled:
            if lines:
                lines.append("")
            lines.extend([_md_heading(3, _md_label(key)), "", *_md_render_generic(value, heading_level=4)])
    return lines or ["No hardware sensor details were available."]


def _md_render_section(name: str, data: Any) -> list[str]:
    if isinstance(data, dict):
        renderers = {
            "os": _md_render_os,
            "desktop": _md_render_desktop,
            "cpu": _md_render_cpu,
            "memory": _md_render_memory,
            "graphics": _md_render_graphics,
            "storage": _md_render_storage,
            "filesystems": _md_render_filesystems,
            "network": _md_render_network,
            "sensors": _md_render_sensors,
        }
        renderer = renderers.get(name)
        if renderer is not None:
            return renderer(data)
    return _md_render_generic(data, heading_level=3)


def _md_render_errors(errors: list[Any]) -> list[str]:
    if not errors:
        return ["No collection errors were reported."]
    if all(isinstance(item, dict) and set(item.keys()) <= {"section", "message"} for item in errors):
        rows = [
            [
                _md_section_title(item["section"]) if isinstance(item.get("section"), str) and item["section"].strip() else "General",
                _md_text(item.get("message")),
            ]
            for item in errors
        ]
        return _md_table(["Section", "Message"], rows)
    return _md_render_generic(errors, heading_level=3)


def render_markdown(snapshot: dict[str, Any]) -> str:
    """Render a human-readable Markdown document from one sanitized snapshot."""
    _validate_snapshot(snapshot)
    selected = snapshot["selected_sections"]
    selected_value = ", ".join(_md_section_title(item) for item in selected) if selected else "None"
    privacy_status = "Enabled" if snapshot["privacy"] else "Disabled"
    lines = [
        "# TaskPup System Diagnostic Report",
        "",
        f"> **Privacy protection: {privacy_status}.** Automated redaction may not catch every sensitive value. Review this report before sharing it.",
        "",
        f"- **Generated (UTC):** {_md_escape(snapshot['timestamp'])}",
        f"- **TaskPup version:** {_md_escape(snapshot['app_version'])}",
        f"- **Schema version:** {_md_escape(snapshot['schema_version'])}",
        f"- **Selected sections:** {_md_escape(selected_value)}",
    ]

    sections = snapshot["sections"]
    if sections:
        lines.extend(_md_overview(sections))
        for name, data in sections.items():
            lines.extend(["", _md_heading(2, _md_section_title(name)), ""])
            lines.extend(_md_render_section(name, data))
    else:
        lines.extend(["", "## Diagnostic Sections", "", "No diagnostic sections were available."])

    errors = snapshot["errors"]
    lines.extend(["", "## Collection Errors", ""])
    lines.extend(_md_render_errors(errors))
    return "\n".join(lines).rstrip() + "\n"


def render_jsonl(snapshot: dict[str, Any]) -> str:
    """Render schema-versioned JSON Lines records from one sanitized snapshot."""
    _validate_snapshot(snapshot)
    timestamp = snapshot["timestamp"]
    common = {"schema_version": snapshot["schema_version"], "timestamp": timestamp}
    records: list[dict[str, Any]] = [
        {
            **common,
            "record_type": "metadata",
            "section": None,
            "data": {
                "app_version": snapshot["app_version"],
                "selected_sections": snapshot["selected_sections"],
                "privacy": snapshot["privacy"],
            },
        }
    ]
    records.extend(
        {
            **common,
            "record_type": "section",
            "section": name,
            "data": data,
        }
        for name, data in snapshot["sections"].items()
    )
    records.extend(
        {
            **common,
            "record_type": "error",
            "section": error.get("section") if isinstance(error, dict) and isinstance(error.get("section"), str) else None,
            "data": error,
        }
        for error in snapshot["errors"]
    )
    return "".join(_json_dumps(record) + "\n" for record in records)


def render_html(snapshot: dict[str, Any]) -> str:
    """Render a standalone offline HTML document with safely escaped snapshot data."""
    _validate_snapshot(snapshot)

    def make_table(headers: list[str], rows: list[list[str]]) -> str:
        head = "".join(f'<th scope="col">{_html_escape(_humanize_label(header))}</th>' for header in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{_html_escape(cell)}</td>" for cell in row) + "</tr>"
            for row in rows
        )
        return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'

    def render_data(data: Any) -> str:
        simple_rows: list[tuple[str, str]] = []
        record_tables: list[tuple[str, list[dict[str, Any]]]] = []

        def visit(value: Any, prefix: str = "", parent_key: str = "") -> None:
            if isinstance(value, dict):
                if not value:
                    simple_rows.append((prefix or "Details", "No details"))
                    return
                for key, child in value.items():
                    label = f"{prefix} / {_humanize_label(key)}" if prefix else _humanize_label(key)
                    if isinstance(child, dict):
                        visit(child, label, key)
                    elif isinstance(child, list) and (not child or all(isinstance(item, dict) for item in child)):
                        if child:
                            record_tables.append((label, child))
                        else:
                            simple_rows.append((label, "No entries"))
                    else:
                        simple_rows.append((label, _display_value(child, key, parent_key.casefold())))
                return
            if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
                record_tables.append((prefix or "Records", value))
            elif isinstance(value, list):
                simple_rows.extend((f"{prefix or 'Value'} [{index}]", _display_value(item)) for index, item in enumerate(value, 1))
                if not value:
                    simple_rows.append((prefix or "Value", "No entries"))
            else:
                simple_rows.append((prefix or "Value", _display_value(value)))

        visit(data)
        parts: list[str] = []
        if simple_rows:
            parts.append(make_table(["Field", "Value"], [[field, value] for field, value in simple_rows]))
        for title, records in record_tables:
            columns = _record_columns(records)
            parts.append(f"<h3>{_html_escape(title)}</h3>")
            if columns:
                rows = [
                    [str(index), *[_display_value(record.get(column), column) for column in columns]]
                    for index, record in enumerate(records, 1)
                ]
                parts.append(make_table(["#", *columns], rows))
            else:
                parts.append(make_table(["#", "Details"], [["1", "No details"]]))
        return "".join(parts) if parts else "<p>No details were available.</p>"

    def render_group(title: str, data: Any) -> str:
        return f"<section><h2>{_html_escape(_humanize_label(title))}</h2>{render_data(data)}</section>"

    selected = ", ".join(_humanize_label(item) for item in snapshot["selected_sections"]) or "None"
    sections = "".join(render_group(name, data) for name, data in snapshot["sections"].items())
    if not sections:
        sections = "<section><h2>Diagnostic sections</h2><p>No diagnostic sections were available.</p></section>"
    errors = render_group("Collection Errors", snapshot["errors"])
    privacy = "Enabled" if snapshot["privacy"] else "Disabled"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TaskPup System Diagnostic Report</title>
  <style>
    :root {{ color-scheme: dark; font-family: system-ui, sans-serif; background: #17171c; color: #eeeeF4; }}
    body {{ max-width: 1100px; margin: 0 auto; padding: 1.5rem; line-height: 1.55; }}
    header {{ border-bottom: 2px solid #8f6bff; margin-bottom: 1.5rem; padding-bottom: 1rem; }}
    h1 {{ color: #bca7ff; margin-bottom: .25rem; }}
    h2 {{ color: #bca7ff; border-bottom: 1px solid #45424f; padding-bottom: .35rem; }}
    h3 {{ color: #cfc4ec; margin-bottom: .5rem; }}
    dl {{ display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: .35rem 1rem; }}
    dt {{ color: #b5b0c2; font-weight: 650; }}
    dd {{ margin: 0; overflow-wrap: anywhere; }}
    section {{ margin: 1.5rem 0; }}
    .table-wrap {{ overflow-x: auto; margin: .75rem 0 1.25rem; }}
    table {{ width: 100%; border-collapse: collapse; background: #222229; }}
    th, td {{ border: 1px solid #45424f; padding: .55rem .7rem; text-align: left; vertical-align: top; overflow-wrap: anywhere; }}
    th {{ color: #cfc4ec; background: #2c2933; }}
    tbody tr:nth-child(even) {{ background: #25242b; }}
    .privacy {{ color: #9de6b1; }}
    @media (max-width: 600px) {{ body {{ padding: 1rem; }} dl {{ grid-template-columns: 1fr; gap: .15rem; }} dd {{ margin-bottom: .45rem; }} }}
    @media print {{ :root {{ color-scheme: light; background: white; color: #111; }} body {{ max-width: none; padding: 0; }} h1, h2, h3, dt, th {{ color: #33235e; }} table, th, td {{ background: white !important; color: #111; border-color: #999; }} section {{ break-inside: avoid; }} }}
  </style>
</head>
<body>
  <header>
    <h1>TaskPup System Diagnostic Report</h1>
    <p>Sit. Stay. SIGKILL.</p>
    <dl>
      <dt>Schema version</dt><dd>{_html_escape(snapshot['schema_version'])}</dd>
      <dt>Generated (UTC)</dt><dd>{_html_escape(snapshot['timestamp'])}</dd>
      <dt>TaskPup version</dt><dd>{_html_escape(snapshot['app_version'])}</dd>
      <dt>Privacy protection</dt><dd class="privacy">{privacy}</dd>
      <dt>Selected sections</dt><dd>{_html_escape(selected)}</dd>
    </dl>
    <p>Automated redaction may not catch every sensitive value. Review this report before sharing it.</p>
  </header>
  {sections}
  {errors}
</body>
</html>
"""


def _make_zip(snapshot: dict[str, Any]) -> bytes:
    reports = (
        ("report.md", render_markdown(snapshot)),
        ("report.jsonl", render_jsonl(snapshot)),
        ("report.html", render_html(snapshot)),
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, text in reports:
            member = zipfile.ZipInfo(name)
            member.compress_type = zipfile.ZIP_DEFLATED
            member.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(member, text.encode("utf-8"))

    payload = output.getvalue()
    with zipfile.ZipFile(io.BytesIO(payload), mode="r") as archive:
        names = archive.namelist()
        if len(names) != len(_REPORT_MEMBERS) or set(names) != set(_REPORT_MEMBERS):
            raise ValueError("generated ZIP has unexpected report members")
        if archive.testzip() is not None:
            raise ValueError("generated ZIP failed its integrity check")
    return payload


def _atomic_write(destination: Path, payload: bytes, *, overwrite: bool) -> None:
    """Atomically install a 0600 file without following its final path component."""
    destination = Path(destination)
    name = destination.name
    if not name or name in {".", ".."}:
        raise ValueError("destination must name a file")

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open(destination.parent or Path("."), flags)
    temporary_name: str | None = None
    try:
        for _ in range(100):
            candidate = f".taskpup-report-{secrets.token_hex(8)}.tmp"
            create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            try:
                file_fd = os.open(candidate, create_flags, 0o600, dir_fd=directory_fd)
                temporary_name = candidate
                break
            except FileExistsError:
                continue
        else:
            raise FileExistsError("could not allocate a temporary report file")

        try:
            os.fchmod(file_fd, 0o600)
            with os.fdopen(file_fd, "wb", closefd=True) as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            # fdopen owns file_fd after construction; if construction itself failed,
            # closing an already-closed descriptor is harmlessly guarded below.
            try:
                os.close(file_fd)
            except OSError:
                pass
            raise

        try:
            existing = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None

        if existing is not None:
            if stat.S_ISLNK(existing.st_mode):
                raise OSError(f"refusing to write through symbolic-link destination: {destination}")
            if not stat.S_ISREG(existing.st_mode):
                raise OSError(f"destination is not a regular file: {destination}")
            if not overwrite:
                raise FileExistsError(errno.EEXIST, "destination already exists", str(destination))
            os.replace(temporary_name, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            temporary_name = None
        else:
            # Hard-linking the fully written temporary file gives atomic no-clobber
            # semantics even if another process creates the destination concurrently.
            os.link(
                temporary_name,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.unlink(temporary_name, dir_fd=directory_fd)
            temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def write_report(
    snapshot: dict[str, Any],
    destination: Path,
    format: str,
    *,
    overwrite: bool = False,
) -> None:
    """Render and atomically write one report format to ``destination``.

    ``format`` is one of ``md``, ``jsonl``, ``html`` or ``zip``. By default an
    existing destination is preserved. Callers should set ``overwrite=True``
    only after the user has explicitly approved replacement in the UI.
    """
    _validate_snapshot(snapshot)
    if not isinstance(overwrite, bool):
        raise TypeError("overwrite must be a bool")
    if format == "md":
        payload = render_markdown(snapshot).encode("utf-8")
    elif format == "jsonl":
        payload = render_jsonl(snapshot).encode("utf-8")
    elif format == "html":
        payload = render_html(snapshot).encode("utf-8")
    elif format == "zip":
        payload = _make_zip(snapshot)
    else:
        raise ValueError("format must be one of: md, jsonl, html, zip")
    _atomic_write(Path(destination), payload, overwrite=overwrite)

