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
import sys
from typing import Any, TypeGuard
import zipfile


_REPORT_MEMBERS = ("report.md", "report.json", "report.jsonl", "report.html")
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


def _md_numeric_valid(value: Any) -> TypeGuard[int | float]:
    return _is_number(value) and abs(value) <= sys.float_info.max and (not isinstance(value, float) or math.isfinite(value))


def _md_numeric_fallback(value: Any) -> str:
    return "Out of range" if _is_number(value) else "Not available"


def _md_bytes(value: Any) -> str:
    if not _md_numeric_valid(value):
        return _md_numeric_fallback(value)
    return format_bytes(int(round(float(value))))


def _md_rate(value: Any) -> str:
    if not _md_numeric_valid(value):
        return _md_numeric_fallback(value)
    return f"{format_bytes(int(round(float(value))))}/s"


def _md_percent(value: Any) -> str:
    if not _md_numeric_valid(value):
        return _md_numeric_fallback(value)
    return f"{float(value):.1f}%"


def _md_temp(value: Any) -> str:
    if not _md_numeric_valid(value):
        return _md_numeric_fallback(value)
    return f"{float(value):.1f} °C"


def _md_freq_mhz(value: Any) -> str:
    if not _md_numeric_valid(value):
        return _md_numeric_fallback(value)
    return f"{float(value):,.1f} MHz"


def _md_rpm(value: Any) -> str:
    if not _md_numeric_valid(value):
        return _md_numeric_fallback(value)
    return f"{round(float(value)):,} RPM"


def _md_watts(value: Any) -> str:
    if not _md_numeric_valid(value):
        return _md_numeric_fallback(value)
    return f"{float(value):.1f} W"


def _md_speed_mbps(value: Any) -> str:
    if not _md_numeric_valid(value):
        return _md_numeric_fallback(value)
    if float(value) <= 0:
        return "Not available"
    numeric = float(value)
    if numeric.is_integer():
        return f"{int(numeric):,} Mbps"
    return f"{numeric:,.1f} Mbps"


def _md_uptime(value: Any) -> str:
    if not _md_numeric_valid(value):
        return _md_numeric_fallback(value)
    if float(value) < 0:
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
            if _is_number(total) and total == 0:
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
            if _md_numeric_valid(scale):
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
        usage = "Not configured" if (_is_number(total) and total == 0) else _md_percent(swap.get("percent_used"))
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
    result = "\n".join(lines).rstrip() + "\n"
    result = re.sub(r"&lt;device-(\d+)&gt;-partition-(\d+)", r"Device \1, Partition \2", result)
    return re.sub(r"&lt;device-(\d+)&gt;", r"Device \1", result)


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


def render_json(snapshot: dict[str, Any]) -> str:
    """Render the sanitized, schema-versioned snapshot as formatted JSON."""
    _validate_snapshot(snapshot)
    return _json_dumps(snapshot, indent=2) + "\n"


_HTML_SECTION_TITLES = {
    "os": "Operating System & Firmware",
    "desktop": "Desktop & Displays",
    "cpu": "Processor (CPU)",
    "memory": "System Memory (RAM & Swap)",
    "graphics": "Graphics Hardware (GPU)",
    "storage": "Storage Hardware",
    "filesystems": "Filesystems & Mounts",
    "network": "Network Configuration",
    "sensors": "Hardware Sensors",
}

_HTML_VIRTUAL_FS_TYPES = frozenset({
    "anon_inodefs",
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fuse.gvfsd-fuse",
    "fuse.portal",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "nsfs",
    "overlay",
    "pipefs",
    "proc",
    "pstore",
    "ramfs",
    "rpc_pipefs",
    "securityfs",
    "selinuxfs",
    "sockfs",
    "sysfs",
    "tmpfs",
    "tracefs",
})

_HTML_HALF_WIDTH_SECTIONS = frozenset({"os", "desktop", "cpu", "memory"})

_HTML_ICONS = {
    "logo": (
        '<svg viewBox="0 0 48 48" width="40" height="40" fill="none" aria-hidden="true">'
        '<rect width="48" height="48" rx="12" fill="#21262d" stroke="#30363d" stroke-width="1.5"/>'
        '<circle cx="16.5" cy="18.5" r="3.5" fill="#bc8cff"/>'
        '<circle cx="24" cy="14" r="3.5" fill="#87cf3e"/>'
        '<circle cx="31.5" cy="18.5" r="3.5" fill="#bc8cff"/>'
        '<path d="M15.5 29.5c0-4.4 3.8-7.5 8.5-7.5s8.5 3.1 8.5 7.5c0 3.2-2.4 5.5-5.5 5.5-1.4 0-2.1-.6-3-.6s-1.6.6-3 .6c-3.1 0-5.5-2.3-5.5-5.5z" fill="#87cf3e"/>'
        "</svg>"
    ),
    "os": (
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#87cf3e" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<circle cx="12" cy="12" r="10"/>'
        '<path d="m4.93 4.93 4.24 4.24M14.83 9.17l4.24-4.24M14.83 14.83l4.24 4.24M9.17 14.83l-4.24 4.24"/>'
        "</svg>"
    ),
    "desktop": (
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<rect width="20" height="14" x="2" y="3" rx="2"/>'
        '<line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>'
        "</svg>"
    ),
    "cpu": (
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#87cf3e" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/>'
        '<path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>'
        "</svg>"
    ),
    "memory": (
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<path d="M6 19v-3M10 19v-3M14 19v-3M18 19v-3M2 8a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2Z"/>'
        '<path d="M2 12h20"/>'
        "</svg>"
    ),
    "graphics": (
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#bc8cff" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<rect x="2" y="5" width="20" height="14" rx="2"/>'
        '<circle cx="9" cy="12" r="3"/><path d="M15 9h3M15 12h3M15 15h3"/>'
        "</svg>"
    ),
    "storage": (
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<rect x="3" y="4" width="18" height="7" rx="2"/>'
        '<rect x="3" y="13" width="18" height="7" rx="2"/>'
        '<line x1="7" x2="7.01" y1="7.5" y2="7.5"/><line x1="7" x2="7.01" y1="16.5" y2="16.5"/>'
        "</svg>"
    ),
    "filesystems": (
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#87cf3e" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<path d="M3 6a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/>'
        "</svg>"
    ),
    "network": (
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/>'
        '<line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/>'
        "</svg>"
    ),
    "sensors": (
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#e3b341" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<path d="M14 4v10.54a4 4 0 1 1-4 0V4a2 2 0 0 1 4 0Z"/>'
        "</svg>"
    ),
    "errors_ok": (
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#87cf3e" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>'
        "</svg>"
    ),
    "errors_warn": (
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f85149" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>'
        '<line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/>'
        "</svg>"
    ),
    "generic": (
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#bc8cff" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<rect x="3" y="3" width="18" height="18" rx="2"/>'
        '<path d="M7 8h10M7 12h10M7 16h6"/>'
        "</svg>"
    ),
    "shield": (
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
        "</svg>"
    ),
    "print": (
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<path d="M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/>'
        '<rect x="6" y="14" width="12" height="8"/>'
        "</svg>"
    ),
    "search": (
        '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>'
        "</svg>"
    ),
}

_HTML_STYLESHEET = """\
:root {
  color-scheme: dark;
  --bg-base: #0d1117;
  --bg-card: #161b22;
  --bg-card-header: #21262d;
  --bg-subtle: #1f242c;
  --bg-badge: #21262d;
  --border-main: #30363d;
  --border-light: #484f58;
  --text-primary: #e6edf3;
  --text-secondary: #8b949e;
  --text-muted: #7d8590;
  --mint-green: #87cf3e;
  --mint-glow: rgba(135, 207, 62, 0.14);
  --accent-purple: #bc8cff;
  --purple-glow: rgba(188, 140, 255, 0.14);
  --accent-blue: #58a6ff;
  --blue-glow: rgba(88, 166, 255, 0.14);
  --accent-yellow: #e3b341;
  --yellow-glow: rgba(227, 179, 65, 0.14);
  --accent-red: #f85149;
  --red-glow: rgba(248, 81, 73, 0.14);
  --font-sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
}
*, *::before, *::after { box-sizing: border-box; }
[hidden] { display: none !important; }
html, body { margin: 0; padding: 0; max-width: 100%; overflow-x: clip; }
body {
  background-color: var(--bg-base);
  color: var(--text-primary);
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.5;
  padding: 20px;
  -webkit-font-smoothing: antialiased;
}
.container { max-width: 1420px; margin: 0 auto; width: 100%; }

/* Header */
.report-header {
  background-color: var(--bg-card);
  border: 1px solid var(--border-main);
  border-radius: 12px;
  margin-bottom: 20px;
  box-shadow: 0 4px 14px rgba(0, 0, 0, 0.38);
  overflow: hidden;
}
.header-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
  padding: 20px 24px;
}
.header-left { display: flex; align-items: center; gap: 14px; min-width: 0; }
.header-logo { flex-shrink: 0; display: flex; align-items: center; }
.header-title { min-width: 0; }
.header-title h1 {
  margin: 0;
  font-size: 1.5rem;
  font-weight: 700;
  line-height: 1.25;
  color: var(--text-primary);
  overflow-wrap: anywhere;
}
.header-title h1 .mint-accent { color: var(--mint-green); }
.header-subtitle {
  margin: 3px 0 0;
  font-size: 0.88rem;
  color: var(--text-secondary);
}
.header-badges { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.header-meta-strip {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px 24px;
  background-color: var(--bg-subtle);
  border-top: 1px solid var(--border-main);
  font-size: 0.83rem;
}
.privacy-notice {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 8px;
  border: 1px solid var(--border-main);
  background-color: var(--bg-card);
  color: var(--text-primary);
}
.privacy-notice.privacy-on {
  border-color: rgba(135, 207, 62, 0.45);
  background-color: rgba(135, 207, 62, 0.08);
}
.privacy-notice.privacy-on svg { color: var(--mint-green); flex-shrink: 0; margin-top: 2px; }
.privacy-notice.privacy-off {
  border-color: rgba(227, 179, 65, 0.55);
  background-color: rgba(227, 179, 65, 0.1);
}
.privacy-notice.privacy-off svg { color: var(--accent-yellow); flex-shrink: 0; margin-top: 2px; }
.header-meta-line {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 18px;
  color: var(--text-secondary);
}
.header-meta-line strong { color: var(--text-primary); font-weight: 600; }

/* Badges */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 9px;
  border-radius: 6px;
  font-size: 0.78rem;
  font-weight: 600;
  line-height: 1.35;
  background-color: var(--bg-badge);
  border: 1px solid var(--border-main);
  color: var(--text-secondary);
  max-width: 100%;
  overflow-wrap: break-word;
}
.badge.mint { background-color: var(--mint-glow); border-color: var(--mint-green); color: var(--mint-green); }
.badge.purple { background-color: var(--purple-glow); border-color: var(--accent-purple); color: var(--accent-purple); }
.badge.blue { background-color: var(--blue-glow); border-color: var(--accent-blue); color: var(--accent-blue); }
.badge.warn { background-color: var(--yellow-glow); border-color: var(--accent-yellow); color: var(--accent-yellow); }
.badge.crit { background-color: var(--red-glow); border-color: var(--accent-red); color: var(--accent-red); }
.badge.status-up { background-color: rgba(57, 211, 83, 0.14); border-color: #39d353; color: #39d353; }
.badge.status-down { background-color: var(--red-glow); border-color: var(--accent-red); color: var(--accent-red); }
.badge.mono { font-family: var(--font-mono); font-size: 0.76rem; }

/* Toolbar */
.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 20px;
}
.toolbar-left { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; flex: 1 1 280px; min-width: 0; }
.toolbar-right { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
.search-box {
  position: relative;
  display: flex;
  align-items: center;
  flex: 1 1 240px;
  max-width: 380px;
  min-width: 0;
}
.search-icon {
  position: absolute;
  left: 11px;
  color: var(--text-secondary);
  pointer-events: none;
  display: flex;
  align-items: center;
}
.search-input {
  width: 100%;
  background-color: var(--bg-card);
  border: 1px solid var(--border-main);
  color: var(--text-primary);
  padding: 8px 12px 8px 34px;
  border-radius: 8px;
  font-size: 0.88rem;
  font-family: var(--font-sans);
  outline: none;
  transition: border-color 0.15s ease;
}
.search-input:focus { border-color: var(--mint-green); }
.filter-status { font-size: 0.82rem; color: var(--text-secondary); }
.btn {
  background-color: var(--bg-card);
  color: var(--text-primary);
  border: 1px solid var(--border-main);
  padding: 8px 13px;
  border-radius: 8px;
  font-size: 0.84rem;
  font-family: var(--font-sans);
  cursor: pointer;
  font-weight: 600;
  display: inline-flex;
  align-items: center;
  gap: 7px;
  transition: background-color 0.15s ease, border-color 0.15s ease;
}
.btn:hover { background-color: var(--bg-subtle); border-color: var(--mint-green); }
.btn-subtle { padding: 7px 11px; font-size: 0.8rem; color: var(--text-secondary); }

/* Executive Summary Cards */
.exec-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
  margin-bottom: 22px;
}
.exec-grid.cols-1 { grid-template-columns: minmax(0, 1fr); }
.exec-grid.cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.exec-card {
  background-color: var(--bg-card);
  border: 1px solid var(--border-main);
  border-radius: 10px;
  padding: 15px 16px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  min-width: 0;
  transition: transform 0.15s ease, border-color 0.15s ease;
}
.exec-card:hover { transform: translateY(-2px); border-color: var(--border-light); }
.exec-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
}
.exec-card-title {
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.55px;
  color: var(--text-secondary);
}
.exec-card-value {
  font-size: 1.06rem;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 4px;
  overflow-wrap: anywhere;
}
.exec-card-sub {
  font-size: 0.81rem;
  color: var(--text-secondary);
  overflow-wrap: anywhere;
}

/* Progress Bars */
.progress-wrap { margin-top: 10px; }
.progress-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 8px;
  font-size: 0.82rem;
  margin-bottom: 5px;
}
.progress-bar-bg {
  background-color: var(--bg-badge);
  height: 8px;
  border-radius: 4px;
  overflow: hidden;
  border: 1px solid var(--border-main);
  width: 100%;
}
.progress-bar-fill {
  height: 100%;
  border-radius: 3px;
  -webkit-print-color-adjust: exact;
  print-color-adjust: exact;
}
.progress-bar-fill.bar-ok { background-color: var(--mint-green); }
.progress-bar-fill.bar-warn { background-color: var(--accent-yellow); }
.progress-bar-fill.bar-crit { background-color: var(--accent-red); }
.pct-ok { color: var(--mint-green); font-weight: 600; }
.pct-warn { color: var(--accent-yellow); font-weight: 600; }
.pct-crit { color: var(--accent-red); font-weight: 600; }
.inline-progress { display: flex; align-items: center; gap: 8px; min-width: 120px; }
.inline-progress .progress-bar-bg { width: 72px; flex-shrink: 0; }
.inline-progress .pct-label { font-size: 0.8rem; font-family: var(--font-mono); white-space: nowrap; }

/* Main Grid & Section Cards */
.main-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 20px;
  align-items: start;
}
.card {
  background-color: var(--bg-card);
  border: 1px solid var(--border-main);
  border-radius: 10px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.card.full-width { grid-column: 1 / -1; }
.card.card-error { border-color: rgba(248, 81, 73, 0.55); }
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
  padding: 13px 18px;
  background-color: var(--bg-card-header);
  border-bottom: 1px solid var(--border-main);
}
.card-header-title { display: flex; align-items: center; gap: 10px; min-width: 0; }
.card-header h2 {
  margin: 0;
  font-size: 1.02rem;
  font-weight: 650;
  color: var(--text-primary);
  overflow-wrap: anywhere;
}
.card-header-badges { display: flex; flex-wrap: wrap; gap: 6px; }
.card-body {
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  gap: 16px;
  min-width: 0;
}

/* Sub-cards (GPUs, Network Interfaces, Sensor Groups) */
.sub-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 480px), 1fr));
  gap: 16px;
  align-items: start;
}
.sensor-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
  align-items: start;
}
.fstab-badges { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
.fstab-subblock { margin-top: 10px; }
.sub-card {
  background-color: rgba(255, 255, 255, 0.015);
  border: 1px solid var(--border-main);
  border-radius: 8px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.sub-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  padding: 10px 14px;
  background-color: var(--bg-subtle);
  border-bottom: 1px solid var(--border-main);
}
.sub-card-header h3 {
  margin: 0;
  font-size: 0.94rem;
  font-weight: 650;
  color: var(--text-primary);
  overflow-wrap: anywhere;
}
.sub-card-body {
  padding: 14px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-width: 0;
}

/* Section Labels & Notes */
.section-label {
  font-size: 0.77rem;
  font-weight: 700;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.55px;
  margin: 0 0 8px;
}
.note-text {
  margin: 0;
  font-size: 0.82rem;
  color: var(--text-secondary);
  overflow-wrap: anywhere;
}
.caveat-text {
  margin: 4px 0 0;
  font-size: 0.8rem;
  color: var(--text-muted);
  font-style: italic;
  overflow-wrap: anywhere;
}
.val-muted { color: var(--text-muted); font-style: italic; }
.cell-sub { display: block; font-size: 0.77rem; color: var(--text-secondary); margin-top: 2px; }

/* Tables */
.table-wrap {
  width: 100%;
  max-width: 100%;
  overflow-x: auto;
  border: 1px solid var(--border-main);
  border-radius: 8px;
}
.table-wrap.routes-scroll { max-height: 360px; overflow-y: auto; }
.table-wrap table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.86rem;
}
.table-wrap th,
.table-wrap td {
  padding: 8px 10px;
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid var(--border-main);
  overflow-wrap: break-word;
}
.table-wrap th {
  color: var(--text-secondary);
  font-weight: 600;
  background-color: var(--bg-subtle);
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.45px;
  white-space: nowrap;
}
.table-wrap tbody tr:last-child td { border-bottom: none; }
.table-wrap tbody tr:hover { background-color: rgba(255, 255, 255, 0.02); }
.table-wrap.kv-wrap { border: none; border-radius: 0; }
.table-wrap.kv-wrap table { border: none; }
.table-wrap.kv-wrap td:first-child {
  color: var(--text-secondary);
  font-weight: 500;
  width: 34%;
  min-width: 120px;
}
.table-wrap.kv-wrap td:nth-child(2) { color: var(--text-primary); overflow-wrap: anywhere; }
.num-cell { font-family: var(--font-mono); font-size: 0.82rem; white-space: nowrap; }

/* Monospace & Code Blocks */
.mono-span {
  font-family: var(--font-mono);
  font-size: 0.81rem;
  background-color: var(--bg-subtle);
  padding: 2px 6px;
  border-radius: 4px;
  border: 1px solid var(--border-main);
  color: var(--text-primary);
  display: inline-block;
  max-width: 100%;
  overflow-wrap: break-word;
}
.mount-detail-list { display: flex; flex-direction: column; gap: 8px; }
.mount-detail-item {
  border: 1px solid var(--border-main);
  border-radius: 6px;
  padding: 9px 11px;
  background-color: rgba(255, 255, 255, 0.015);
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.mount-detail-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px 12px;
  font-size: 0.82rem;
}
.mount-detail-meta { color: var(--text-secondary); }
.mount-detail-opts {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 0.81rem;
  color: var(--text-secondary);
}
.mount-detail-opts strong { color: var(--text-primary); font-weight: 600; }
.mount-detail-opts .mono-span { overflow-wrap: anywhere; }
.code-block {
  font-family: var(--font-mono);
  font-size: 0.81rem;
  background-color: var(--bg-base);
  border: 1px solid var(--border-main);
  border-radius: 6px;
  padding: 10px 12px;
  margin: 0;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  color: var(--text-primary);
}

/* Stat Pills & Flag Chips */
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 135px), 1fr));
  gap: 8px;
}
.stat-pill {
  background-color: var(--bg-subtle);
  border: 1px solid var(--border-main);
  border-radius: 6px;
  padding: 8px 10px;
  min-width: 0;
}
.stat-pill-label { font-size: 0.74rem; color: var(--text-secondary); font-weight: 600; }
.stat-pill-val {
  font-size: 0.92rem;
  font-weight: 700;
  color: var(--mint-green);
  font-family: var(--font-mono);
  margin-top: 2px;
  overflow-wrap: anywhere;
}
.chip-list { display: flex; flex-wrap: wrap; gap: 6px; }
.chip {
  font-family: var(--font-mono);
  font-size: 0.76rem;
  background-color: var(--bg-subtle);
  border: 1px solid var(--border-main);
  border-radius: 5px;
  padding: 2px 7px;
  color: var(--text-primary);
  max-width: 100%;
  overflow-wrap: anywhere;
}

/* Native Expandable Details */
details.details-panel {
  border: 1px solid var(--border-main);
  border-radius: 8px;
  background-color: var(--bg-subtle);
  overflow: hidden;
}
details.details-panel > summary {
  list-style: none;
  cursor: pointer;
  padding: 10px 14px;
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--text-primary);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  user-select: none;
}
details.details-panel > summary::-webkit-details-marker { display: none; }
details.details-panel > summary::before {
  content: "\\25B6";
  font-size: 0.7rem;
  color: var(--mint-green);
  transition: transform 0.15s ease;
  margin-right: 6px;
  flex-shrink: 0;
}
details.details-panel[open] > summary::before { transform: rotate(90deg); }
details.details-panel > summary .summary-title { display: flex; align-items: center; flex: 1; min-width: 0; }
details.details-panel > .details-body {
  padding: 12px 14px;
  background-color: var(--bg-card);
  border-top: 1px solid var(--border-main);
  display: flex;
  flex-direction: column;
  gap: 10px;
}

/* Empty Filter Banner & Footer */
.empty-state {
  background-color: var(--bg-card);
  border: 1px dashed var(--border-light);
  border-radius: 10px;
  padding: 28px 20px;
  text-align: center;
  color: var(--text-secondary);
  margin-bottom: 20px;
}
.report-footer {
  margin-top: 28px;
  padding: 18px 12px;
  text-align: center;
  border-top: 1px solid var(--border-main);
  color: var(--text-muted);
  font-size: 0.82rem;
}

/* Responsive Breakpoints */
@media (max-width: 1080px) {
  .main-grid { grid-template-columns: minmax(0, 1fr); }
}
@media (max-width: 1020px) {
  .exec-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 900px) {
  .sensor-grid { grid-template-columns: minmax(0, 1fr); }
}
@media (max-width: 640px) {
  body { padding: 12px; }
  .header-top, .header-meta-strip { padding: 14px 16px; }
  .card-header { padding: 12px 14px; }
  .card-body { padding: 14px; }
  .exec-grid, .exec-grid.cols-2 { grid-template-columns: minmax(0, 1fr); }
  .search-box { max-width: none; }
  .table-wrap.kv-wrap td:first-child { width: auto; min-width: 96px; }
}

/* Print Stylesheet */
@media print {
  :root {
    color-scheme: light;
    --bg-base: #ffffff;
    --bg-card: #ffffff;
    --bg-card-header: #f3f4f6;
    --bg-subtle: #f8f9fa;
    --bg-badge: #f3f4f6;
    --border-main: #d0d7de;
    --border-light: #adb5bd;
    --text-primary: #111827;
    --text-secondary: #374151;
    --text-muted: #4b5563;
  }
  body { background: #ffffff !important; color: #111827 !important; padding: 0; font-size: 11px; }
  .container { max-width: 100%; }
  .no-print, .toolbar, .empty-state { display: none !important; }
  .report-header, .card, .exec-card, .sub-card, details.details-panel {
    background: #ffffff !important;
    border: 1px solid #cbd5e1 !important;
    box-shadow: none !important;
    color: #111827 !important;
  }
  .header-meta-strip, .card-header, .sub-card-header, .table-wrap th, details.details-panel > summary {
    background: #f3f4f6 !important;
    color: #111827 !important;
  }
  .exec-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin-bottom: 12px; }
  .main-grid { display: block; }
  .card, .card-body, .sub-card, .sub-card-body, details.details-panel > .details-body {
    display: block !important;
  }
  .card { margin-bottom: 12px; break-inside: auto; overflow: visible !important; }
  .card-header, .sub-card-header, .section-label { break-after: avoid; }
  .card-body > * + * { margin-top: 10px; }
  .sub-card-body > * + * { margin-top: 8px; }
  details.details-panel > .details-body > * + * { margin-top: 8px; }
  .exec-card, tr { break-inside: avoid; }
  .sub-grid, .sensor-grid { display: block; }
  .sub-card { margin-bottom: 10px; break-inside: auto; overflow: visible !important; }
  .table-wrap, .table-wrap.routes-scroll { overflow: visible !important; max-height: none !important; }
  .table-wrap th { white-space: normal; font-size: 9.5px; padding: 5px 6px; }
  .table-wrap td { padding: 5px 6px; font-size: 10px; }
  .mono-span, .chip, .code-block, .stat-pill, .mount-detail-item {
    background: #f8fafc !important;
    border-color: #cbd5e1 !important;
    color: #111827 !important;
  }
  .badge { color: #111827 !important; border-color: #94a3b8 !important; background: #f1f5f9 !important; font-size: 9.5px; padding: 2px 6px; }
  .badge.crit, .badge.status-down { border-color: #b91c1c !important; color: #991b1b !important; }
  .badge.warn { border-color: #b45309 !important; color: #92400e !important; }
  .badge.mint, .badge.status-up { border-color: #15803d !important; color: #166534 !important; }
  .header-title h1 .mint-accent { color: #166534 !important; }
  .stat-pill-val { color: #166534 !important; }
  .pct-ok { color: #166534 !important; }
  .pct-warn { color: #92400e !important; }
  .pct-crit { color: #991b1b !important; }
  .progress-bar-bg { border-color: #94a3b8 !important; background: #e2e8f0 !important; }
  .mount-detail-list { display: block; }
  .mount-detail-item { display: block; padding: 3px 4px; margin: 0; border: 0; border-bottom: 1px solid #cbd5e1; border-radius: 0; break-inside: auto; }
  .mount-detail-head { display: block; font-size: 9px; }
  .mount-detail-head > * { margin-right: 6px; }
  .mount-detail-opts { display: block; font-size: 9px; }
  .mount-detail-opts > span { display: block; }
  .mount-detail-item .mono-span { padding: 0; border: 0; background: transparent !important; overflow-wrap: anywhere; }
  .fstab-table table { table-layout: fixed; width: 100%; }
  .fstab-table th, .fstab-table td { overflow-wrap: anywhere; }
  .fstab-table th:first-child { width: 7%; }
  .fstab-table th:nth-child(2), .fstab-table th:nth-child(4) { width: 19%; }
  .fstab-table th:nth-child(3) { width: 10%; }
  .fstab-table th:nth-child(5) { width: 32%; }
  .fstab-table th:last-child { width: 13%; }
  .fstab-table td:last-child .mono-span { white-space: nowrap; padding: 0; border: 0; }
}
"""

_HTML_SCRIPT = """\
(function () {
  var input = document.getElementById("filterInput");
  var clearBtn = document.getElementById("clearFilterBtn");
  var statusEl = document.getElementById("filterStatus");
  var emptyState = document.getElementById("filterEmptyState");
  var toggleDetailsBtn = document.getElementById("toggleDetailsBtn");
  var printBtn = document.getElementById("printBtn");

  function getTokens(raw) {
    return raw.trim().toLowerCase().split(/\\s+/).filter(Boolean);
  }

  function matches(text, tokens) {
    var lower = text.toLowerCase();
    for (var i = 0; i < tokens.length; i++) {
      if (lower.indexOf(tokens[i]) === -1) return false;
    }
    return true;
  }

  function applyFilter() {
    if (!input) return;
    var tokens = getTokens(input.value);
    if (clearBtn) clearBtn.hidden = tokens.length === 0;

    var execGrid = document.querySelector(".exec-grid");
    if (execGrid) {
      var execCards = execGrid.querySelectorAll(".exec-card");
      var visibleExec = 0;
      execCards.forEach(function (ec) {
        var ok = tokens.length === 0 || matches(ec.textContent || "", tokens);
        ec.hidden = !ok;
        if (ok) visibleExec += 1;
      });
      execGrid.hidden = tokens.length > 0 && visibleExec === 0;
    }

    var cards = document.querySelectorAll(".spec-card");
    var visibleCards = 0;

    cards.forEach(function (card) {
      var detailsList = card.querySelectorAll("details.details-panel");
      if (tokens.length === 0) {
        card.hidden = false;
        card.querySelectorAll(".filter-group, .filter-block, .filter-item").forEach(function (el) {
          el.hidden = false;
        });
        detailsList.forEach(function (d) {
          if (d.getAttribute("data-search-opened") === "1") {
            d.open = false;
            d.removeAttribute("data-search-opened");
          }
        });
        visibleCards += 1;
        return;
      }

      var header = card.querySelector(".card-header");
      var cardHeaderMatch = header ? matches(header.textContent || "", tokens) : false;

      var allItems = card.querySelectorAll(".filter-item");
      allItems.forEach(function (item) {
        item.hidden = !(cardHeaderMatch || matches(item.textContent || "", tokens));
      });

      var allBlocks = card.querySelectorAll(".filter-block");
      allBlocks.forEach(function (block) {
        var bLabel = block.querySelector(":scope > .section-label, :scope > summary");
        var bHeaderMatch = cardHeaderMatch || (bLabel ? matches(bLabel.textContent || "", tokens) : false);
        var bItems = block.querySelectorAll(".filter-item");
        if (bHeaderMatch) {
          bItems.forEach(function (item) { item.hidden = false; });
        }
        var hasVisibleItem = false;
        bItems.forEach(function (item) { if (!item.hidden) hasVisibleItem = true; });
        var blockMatch = bHeaderMatch || hasVisibleItem || (bItems.length === 0 && matches(block.textContent || "", tokens));
        block.hidden = !blockMatch;
      });

      var allGroups = card.querySelectorAll(".filter-group");
      allGroups.forEach(function (group) {
        var gHeader = group.querySelector(".sub-card-header");
        var gHeaderMatch = cardHeaderMatch || (gHeader ? matches(gHeader.textContent || "", tokens) : false);
        var gItems = group.querySelectorAll(".filter-item");
        var gBlocks = group.querySelectorAll(".filter-block");
        if (gHeaderMatch) {
          gItems.forEach(function (item) { item.hidden = false; });
          gBlocks.forEach(function (block) { block.hidden = false; });
        }
        var anyVisible = gHeaderMatch;
        if (!anyVisible) {
          gItems.forEach(function (item) { if (!item.hidden) anyVisible = true; });
        }
        if (!anyVisible) {
          gBlocks.forEach(function (block) { if (!block.hidden) anyVisible = true; });
        }
        if (!anyVisible && gItems.length === 0 && gBlocks.length === 0) {
          anyVisible = matches(group.textContent || "", tokens);
        }
        group.hidden = !anyVisible;
      });

      detailsList.forEach(function (d) {
        var dItems = d.querySelectorAll(".filter-item");
        var hasVisibleInside = false;
        if (dItems.length > 0) {
          dItems.forEach(function (item) { if (!item.hidden) hasVisibleInside = true; });
        } else {
          hasVisibleInside = !d.hidden && matches(d.textContent || "", tokens);
        }
        if (!d.hidden && hasVisibleInside && !cardHeaderMatch) {
          if (!d.open) {
            d.open = true;
            d.setAttribute("data-search-opened", "1");
          }
        } else if (d.getAttribute("data-search-opened") === "1") {
          d.open = false;
          d.removeAttribute("data-search-opened");
        }
      });

      var cardHasMatch = cardHeaderMatch;
      if (!cardHasMatch) {
        allGroups.forEach(function (g) { if (!g.hidden) cardHasMatch = true; });
      }
      if (!cardHasMatch) {
        allBlocks.forEach(function (b) { if (!b.hidden) cardHasMatch = true; });
      }
      if (!cardHasMatch) {
        allItems.forEach(function (item) { if (!item.hidden) cardHasMatch = true; });
      }
      if (!cardHasMatch && allGroups.length === 0 && allBlocks.length === 0 && allItems.length === 0) {
        cardHasMatch = matches(card.textContent || "", tokens);
      }

      card.hidden = !cardHasMatch;
      if (cardHasMatch) visibleCards += 1;
    });

    if (emptyState) emptyState.hidden = tokens.length === 0 || visibleCards > 0;
    if (statusEl) {
      if (tokens.length === 0) {
        statusEl.textContent = "";
      } else if (visibleCards === 0) {
        statusEl.textContent = "No matching sections";
      } else {
        statusEl.textContent = "Showing " + visibleCards + " " + (visibleCards === 1 ? "section" : "sections");
      }
    }
    updateToggleLabel();
  }

  function updateToggleLabel() {
    if (!toggleDetailsBtn) return;
    var allDetails = document.querySelectorAll("details.details-panel");
    if (allDetails.length === 0) {
      toggleDetailsBtn.hidden = true;
      return;
    }
    toggleDetailsBtn.hidden = false;
    var anyClosed = false;
    allDetails.forEach(function (d) { if (!d.open) anyClosed = true; });
    toggleDetailsBtn.textContent = anyClosed ? "Expand All Details" : "Collapse All Details";
  }

  if (input) input.addEventListener("input", applyFilter);
  if (clearBtn && input) {
    clearBtn.addEventListener("click", function () {
      input.value = "";
      applyFilter();
      input.focus();
    });
  }
  if (toggleDetailsBtn) {
    toggleDetailsBtn.addEventListener("click", function () {
      var allDetails = document.querySelectorAll("details.details-panel");
      var anyClosed = false;
      allDetails.forEach(function (d) { if (!d.open) anyClosed = true; });
      allDetails.forEach(function (d) {
        d.open = anyClosed;
        d.removeAttribute("data-search-opened");
      });
      updateToggleLabel();
    });
    document.querySelectorAll("details.details-panel").forEach(function (d) {
      d.addEventListener("toggle", updateToggleLabel);
    });
    updateToggleLabel();
  }
  if (printBtn) {
    printBtn.addEventListener("click", function () { window.print(); });
  }
  window.addEventListener("beforeprint", function () {
    document.querySelectorAll("details.details-panel").forEach(function (d) {
      if (!d.open) {
        d.open = true;
        d.setAttribute("data-print-opened", "1");
      }
    });
  });
  window.addEventListener("afterprint", function () {
    document.querySelectorAll("details.details-panel").forEach(function (d) {
      if (d.getAttribute("data-print-opened") === "1") {
        d.open = false;
        d.removeAttribute("data-print-opened");
      }
    });
  });
})();
"""


def _html_esc(value: str) -> str:
    return _html_escape(value, quote=True)


def _html_section_title(name: str) -> str:
    return _HTML_SECTION_TITLES.get(name.casefold(), _humanize_label(name))


def _html_muted(label: str) -> str:
    return f'<span class="val-muted">{_html_esc(label)}</span>'


def _html_mono(value: str) -> str:
    return f'<span class="mono-span">{_html_esc(value)}</span>'


def _html_badge(text: str, variant: str = "") -> str:
    cls = f"badge {variant}".strip()
    return f'<span class="{cls}">{_html_esc(text)}</span>'


def _html_numeric_valid(value: Any) -> TypeGuard[int | float]:
    # Keep both conversion and subsequent arithmetic within a bounded range.
    return _is_number(value) and abs(value) <= 1e100 and (not isinstance(value, float) or math.isfinite(value))


def _html_numeric_unavailable(value: Any) -> str:
    return "Out of range" if _is_number(value) else "Not available"


def _html_bytes_plain(value: Any) -> str:
    if not _html_numeric_valid(value):
        return _html_numeric_unavailable(value)
    numeric = float(value)
    if not math.isfinite(numeric):
        return "Not available"
    if numeric < 0:
        return f"-{format_bytes(int(round(abs(numeric))))}"
    return format_bytes(int(round(numeric)))


def _html_bytes_cell(value: Any) -> str:
    text = _html_bytes_plain(value)
    return _html_muted(text) if text == "Not available" else _html_esc(text)


def _html_rate_plain(value: Any) -> str:
    if not _html_numeric_valid(value):
        return _html_numeric_unavailable(value)
    numeric = float(value)
    if not math.isfinite(numeric):
        return "Not available"
    return f"{_html_bytes_plain(numeric)}/s"


def _html_rate_cell(value: Any) -> str:
    text = _html_rate_plain(value)
    return _html_muted(text) if text == "Not available" else _html_esc(text)


def _html_percent_plain(value: Any) -> str:
    if not _html_numeric_valid(value):
        return _html_numeric_unavailable(value)
    return f"{float(value):.1f}%"


def _html_temp_plain(value: Any) -> str:
    if not _html_numeric_valid(value):
        return _html_numeric_unavailable(value)
    return f"{float(value):.1f} °C"


def _html_temp_cell(value: Any, *, supported: Any = None) -> str:
    if not _html_numeric_valid(value):
        if supported is False:
            return _html_badge("Unsupported")
        return _html_muted(_html_numeric_unavailable(value))
    temp = float(value)
    text = f"{temp:.1f} °C"
    if temp >= 85.0:
        return _html_badge(text, "crit mono")
    if temp >= 70.0:
        return _html_badge(text, "warn mono")
    return _html_mono(text)


def _html_freq_plain(value: Any) -> str:
    if not _html_numeric_valid(value):
        return _html_numeric_unavailable(value)
    mhz = float(value)
    if abs(mhz) >= 1000.0:
        return f"{mhz / 1000.0:.2f} GHz"
    return f"{mhz:,.1f} MHz"


def _html_watts_plain(value: Any) -> str:
    if not _html_numeric_valid(value):
        return _html_numeric_unavailable(value)
    watts = float(value)
    if watts == 0.0:
        return "0.0 W"
    if 0.0 < abs(watts) < 0.1:
        return f"{watts:.3f} W"
    return f"{watts:.1f} W"


def _html_rpm_plain(value: Any) -> str:
    if not _html_numeric_valid(value):
        return _html_numeric_unavailable(value)
    return f"{round(float(value)):,} RPM"


def _html_speed_mbps_plain(value: Any) -> str:
    if not _html_numeric_valid(value):
        return _html_numeric_unavailable(value)
    if float(value) <= 0:
        return "Not available"
    mbps = float(value)
    if mbps >= 1000.0:
        gbps = mbps / 1000.0
        gbps_str = f"{int(gbps)}" if gbps.is_integer() else f"{gbps:.1f}".rstrip("0").rstrip(".")
        mbps_str = f"{int(mbps):,}" if mbps.is_integer() else f"{mbps:,.1f}"
        return f"{gbps_str} Gbps ({mbps_str} Mbps)"
    return f"{int(mbps):,} Mbps" if mbps.is_integer() else f"{mbps:,.1f} Mbps"


def _html_uptime_plain(value: Any) -> str:
    if not _html_numeric_valid(value):
        return _html_numeric_unavailable(value)
    if float(value) < 0:
        return "Not available"
    total = int(round(float(value)))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _html_text_cell(value: Any, *, empty: str = "Not reported", missing: str = "Not available", mono: bool = False) -> str:
    if value is None:
        return _html_muted(missing)
    if isinstance(value, bool):
        return _html_esc("Yes" if value else "No")
    if isinstance(value, str):
        cleaned = _md_normalize_text(value)
        if not cleaned:
            return _html_muted(empty)
        return _html_mono(cleaned) if mono else _html_esc(cleaned)
    text = str(value)
    return _html_mono(text) if mono else _html_esc(text)


def _html_format_options(options: Any) -> str:
    if options is None:
        return "None"
    if isinstance(options, list):
        return _format_option_list(options)
    if isinstance(options, str):
        cleaned = _md_normalize_text(options)
        return cleaned if cleaned else "None"
    return _html_value_plain(options)


def _html_gpu_sensor_plain(name: str, value: Any) -> str:
    lowered = name.casefold()
    if _is_number(value):
        if "temperature" in lowered:
            return _html_temp_plain(value)
        if "clock" in lowered:
            return _html_freq_plain(value)
        if "power" in lowered:
            return _html_watts_plain(value)
        if "fan" in lowered:
            return _html_rpm_plain(value)
        if "utilization" in lowered or "percent" in lowered:
            return _html_percent_plain(value)
    return _html_value_plain(value)


def _html_value_plain(value: Any, key: str = "", parent: str = "") -> str:
    if value is None:
        return "Not available"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, str):
        cleaned = _md_normalize_text(value)
        return cleaned if cleaned else "Not reported"
    lowered = key.casefold()
    if _is_number(value):
        if not _html_numeric_valid(value):
            return "Out of range"
        if _byte_field(key) or (parent == "kernel_memory_details" and lowered != "hugepages_total"):
            return _html_rate_plain(value) if lowered.endswith("_per_second") else _html_bytes_plain(value)
        if lowered in {"percent_used", "utilization_percent", "percent"} or lowered.endswith("_percent"):
            return _html_percent_plain(value)
        if lowered in {"temperature_c", "value_c"} or lowered.endswith("_c"):
            return _html_temp_plain(value)
        if lowered in {"current_frequency_mhz", "value_mhz"} or lowered.endswith("_mhz"):
            return _html_freq_plain(value)
        if lowered in {"value_rpm"} or lowered.endswith("_rpm"):
            return _html_rpm_plain(value)
        if lowered in {"value_w"} or lowered.endswith("_w"):
            return _html_watts_plain(value)
        if lowered == "link_speed_mbps":
            return _html_speed_mbps_plain(value)
        if lowered == "uptime_seconds":
            return _html_uptime_plain(value)
        if isinstance(value, float):
            return _md_float(value)
        return str(value)
    if _is_option_list(value):
        return _format_option_list(value)
    if isinstance(value, dict):
        return "; ".join(
            f"{_md_label(child_key)}: {_html_value_plain(child, child_key, lowered)}"
            for child_key, child in value.items()
        ) or "No details"
    if isinstance(value, list):
        return ", ".join(_html_value_plain(item) for item in value) or "No entries"
    return str(value)


def _html_value_cell(value: Any, key: str = "", parent: str = "") -> str:
    text = _html_value_plain(value, key, parent)
    if text in {"Not available", "Not reported", "No details", "No entries"}:
        return _html_muted(text)
    return _html_esc(text)


def _html_pct_level(clamped: float) -> tuple[str, str, str]:
    if clamped >= 85.0:
        return "bar-crit", "pct-crit", "crit"
    if clamped >= 70.0:
        return "bar-warn", "pct-warn", "warn"
    return "bar-ok", "pct-ok", "mint"


def _html_progress_bar(percent: Any, *, label: str = "", detail: str = "", inline: bool = False) -> str:
    if not _html_numeric_valid(percent):
        return _html_muted(_html_numeric_unavailable(percent))
    raw = float(percent)
    clamped = max(0.0, min(100.0, raw))
    bar_cls, pct_cls, _ = _html_pct_level(clamped)
    pct_text = f"{raw:.1f}%"
    width_style = f"width: {clamped:.1f}%;"
    bar = (
        '<div class="progress-bar-bg">'
        f'<div class="progress-bar-fill {bar_cls}" style="{width_style}"></div>'
        "</div>"
    )
    if inline:
        return (
            '<div class="inline-progress">'
            f"{bar}"
            f'<span class="pct-label {pct_cls}">{_html_esc(pct_text)}</span>'
            "</div>"
        )
    header_html = ""
    if label or detail:
        left = _html_esc(label) if label else ""
        if detail:
            left = f"{left}: {_html_esc(detail)}" if left else _html_esc(detail)
        header_html = (
            '<div class="progress-header">'
            f"<span>{left}</span>"
            f'<span class="{pct_cls}">{_html_esc(pct_text)}</span>'
            "</div>"
        )
    return f'<div class="progress-wrap">{header_html}{bar}</div>'


def _html_percent_badge(percent: Any) -> str:
    if not _html_numeric_valid(percent):
        return _html_muted(_html_numeric_unavailable(percent))
    raw = float(percent)
    clamped = max(0.0, min(100.0, raw))
    _, _, badge_cls = _html_pct_level(clamped)
    return _html_badge(f"{raw:.1f}%", f"{badge_cls} mono")


def _html_kv_table(rows: list[tuple[str, str]]) -> str:
    body = "".join(
        f'<tr class="filter-item"><td>{_html_esc(label)}</td><td>{value_html}</td></tr>'
        for label, value_html in rows
    )
    return f'<div class="table-wrap kv-wrap"><table><tbody>{body}</tbody></table></div>'


def _html_data_table(
    headers: list[str],
    rows: list[list[str]],
    *,
    raw_cells: bool = False,
    wrap_class: str = "table-wrap",
) -> str:
    head = "".join(f'<th scope="col">{_html_esc(header)}</th>' for header in headers)
    body_rows: list[str] = []
    for row in rows:
        cells = "".join(
            f"<td>{cell if raw_cells else _html_esc(cell)}</td>"
            for cell in row
        )
        body_rows.append(f'<tr class="filter-item">{cells}</tr>')
    return (
        f'<div class="{wrap_class}">'
        f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"
        "</div>"
    )


def _html_details(title: str, body_html: str, *, badge: str = "", open_default: bool = False) -> str:
    open_attr = " open" if open_default else ""
    badge_html = _html_badge(badge, "mono") if badge else ""
    return (
        f'<details class="details-panel filter-block"{open_attr}>'
        f'<summary><span class="summary-title">{_html_esc(title)}</span>{badge_html}</summary>'
        f'<div class="details-body">{body_html}</div>'
        "</details>"
    )


def _html_is_virtual_fs(mount: dict[str, Any]) -> bool:
    fstype = _md_normalize_text(str(mount.get("filesystem_type") or "")).casefold()
    if fstype == "fuseblk":
        return False
    if fstype in _HTML_VIRTUAL_FS_TYPES:
        return True
    return fstype.startswith(("cgroup", "fuse."))


def _html_render_generic(data: Any) -> str:
    """Render arbitrary structured snapshot data cleanly with full HTML escaping."""
    if isinstance(data, dict) and data == {"available": False}:
        return '<p class="note-text">This section could not be collected.</p>'

    simple_rows: list[tuple[str, str]] = []
    nested_dicts: list[tuple[str, dict[str, Any]]] = []
    record_tables: list[tuple[str, list[dict[str, Any]]]] = []

    if isinstance(data, dict):
        if not data:
            return '<p class="note-text">No details were available.</p>'
        for key, child in data.items():
            label = _humanize_label(key)
            if isinstance(child, dict):
                if child:
                    nested_dicts.append((key, child))
                else:
                    simple_rows.append((label, _html_muted("No details")))
            elif _is_option_list(child):
                simple_rows.append((label, _html_mono(_format_option_list(child))))
            elif isinstance(child, list) and all(isinstance(item, dict) for item in child):
                if child:
                    record_tables.append((label, child))
                else:
                    simple_rows.append((label, _html_muted("No entries")))
            else:
                simple_rows.append((label, _html_value_cell(child, key)))
    elif isinstance(data, list) and data and all(isinstance(item, dict) for item in data):
        record_tables.append(("", data))
    elif isinstance(data, list):
        if not data:
            return '<p class="note-text">No entries were reported.</p>'
        simple_rows.extend((f"Item {idx}", _html_value_cell(item)) for idx, item in enumerate(data, 1))
    else:
        simple_rows.append(("Value", _html_value_cell(data)))

    parts: list[str] = []
    if simple_rows:
        parts.append(f'<div class="filter-block">{_html_kv_table(simple_rows)}</div>')

    for key, child_dict in nested_dicts:
        child_rows: list[tuple[str, str]] = []
        deeper: list[tuple[str, Any]] = []
        for subkey, subval in child_dict.items():
            if isinstance(subval, dict) and subval:
                deeper.append((subkey, subval))
            elif (
                isinstance(subval, list)
                and subval
                and all(isinstance(item, dict) for item in subval)
                and not _is_option_list(subval)
            ):
                deeper.append((subkey, subval))
            else:
                child_rows.append((_humanize_label(subkey), _html_value_cell(subval, subkey, key.casefold())))
        inner: list[str] = [f'<div class="section-label">{_html_esc(_humanize_label(key))}</div>']
        if child_rows:
            inner.append(_html_kv_table(child_rows))
        for subkey, subval in deeper:
            inner.append(f'<div class="section-label">{_html_esc(_humanize_label(subkey))}</div>')
            inner.append(_html_render_generic(subval))
        parts.append(f'<div class="filter-block">{"".join(inner)}</div>')

    for title, records in record_tables:
        columns = _record_columns(records)
        heading = f'<div class="section-label">{_html_esc(title)}</div>' if title else ""
        if not columns:
            table_html = _html_data_table(["#", "Details"], [["1", "No details"]])
        else:
            headers = ["#", *[_humanize_label(col) for col in columns]]
            rows = [
                [str(index), *[_html_value_cell(record.get(col), col) for col in columns]]
                for index, record in enumerate(records, 1)
            ]
            table_html = _html_data_table(headers, rows, raw_cells=True)
        parts.append(f'<div class="filter-block">{heading}{table_html}</div>')

    return "".join(parts) if parts else '<p class="note-text">No details were available.</p>'


_HTML_REDACTED_ID_RE = re.compile(
    r"^<(?:hardware|device|interface|mount|mountroot|source|uuid|label|host|ip|mac|identifier|user|home|redacted)(?:-\d+)?>"
    r"(?:-partition-\d+)?$",
    re.IGNORECASE,
)
_HTML_REDACTED_PARTITION_RE = re.compile(
    r"^(<device-\d+>)-partition-(\d+)$",
    re.IGNORECASE,
)
_HTML_REDACTED_KIND_NUM_RE = re.compile(
    r"^<(hardware|device|interface|mount|source|uuid|label)-(\d+)>$",
    re.IGNORECASE,
)
_HTML_FS_FRIENDLY_LABELS = {
    "btrfs": "Btrfs Volume",
    "ext2": "ext2 Volume",
    "ext3": "ext3 Volume",
    "ext4": "ext4 Volume",
    "xfs": "XFS Volume",
    "zfs": "ZFS Volume",
    "f2fs": "F2FS Volume",
    "vfat": "FAT Volume",
    "fat32": "FAT32 Volume",
    "exfat": "exFAT Volume",
    "ntfs": "NTFS Volume",
    "ntfs3": "NTFS Volume",
    "ntfs-3g": "NTFS Volume",
    "fuseblk": "Storage Volume",
    "cifs": "Network Share",
    "smb3": "Network Share",
    "nfs": "Network Share",
    "nfs4": "Network Share",
    "sshfs": "Network Share",
    "fuse.sshfs": "Network Share",
    "iso9660": "Optical Volume",
    "udf": "Optical Volume",
    "swap": "Swap Space",
}
_HTML_NIC_TYPE_LABELS = {
    "ethernet": "Ethernet Adapter",
    "wi-fi": "Wi-Fi Adapter",
    "wifi": "Wi-Fi Adapter",
    "wireless": "Wi-Fi Adapter",
    "bridge": "Bridge Interface",
    "loopback": "Loopback Interface",
    "virtual": "Virtual Interface",
}


def _html_is_redacted_id(value: str) -> bool:
    return bool(_HTML_REDACTED_ID_RE.fullmatch(value.strip()))


def _html_disambiguate_models(raw_names: list[str | None], fallbacks: list[str]) -> list[str]:
    """Assign hardware-first names with deterministic numbering for duplicate models."""
    counts: dict[str, int] = {}
    for name in raw_names:
        if name:
            counts[name] = counts.get(name, 0) + 1
    seen: dict[str, int] = {}
    resolved: list[str] = []
    for name, fallback in zip(raw_names, fallbacks):
        if name:
            if counts[name] > 1:
                seen[name] = seen.get(name, 0) + 1
                resolved.append(f"{name} (#{seen[name]})")
            else:
                resolved.append(name)
        else:
            resolved.append(fallback)
    return resolved


class _HtmlHardwareCatalog:
    """Read-only correlation catalog mapping sanitized snapshot IDs to safe hardware labels."""

    def __init__(self, sections: dict[str, Any]) -> None:
        self.gpu_labels: list[str] = []
        self.gpu_by_id: dict[str, str] = {}
        self.drive_labels: list[str] = []
        self.drive_by_id: dict[str, str] = {}
        self.partition_to_drive: dict[str, tuple[str, int | None]] = {}
        self.iface_labels: list[str] = []
        self.iface_by_id: dict[str, str] = {}
        self.mount_labels: list[str] = []
        self.mount_by_id: dict[str, str] = {}

        self._index_graphics(sections.get("graphics"))
        self._index_storage(sections.get("storage"))
        self._index_network(sections.get("network"))
        self._index_filesystems(sections.get("filesystems"))

    def _index_graphics(self, gpu_section: Any) -> None:
        if not isinstance(gpu_section, dict) or gpu_section.get("available") is False:
            return
        devices = gpu_section.get("devices")
        if not isinstance(devices, list):
            return
        dict_gpus = [g for g in devices if isinstance(g, dict)]
        raw_models: list[str | None] = []
        fallbacks: list[str] = []
        for idx, gpu in enumerate(dict_gpus, 1):
            model = _md_normalize_text(str(gpu.get("model") or ""))
            raw_models.append(model if (model and not _html_is_redacted_id(model)) else None)
            fallbacks.append(f"Graphics Device {idx}")
        self.gpu_labels = _html_disambiguate_models(raw_models, fallbacks)
        for gpu, label in zip(dict_gpus, self.gpu_labels):
            ident = _md_normalize_text(str(gpu.get("identity") or ""))
            if ident and ident not in self.gpu_by_id:
                self.gpu_by_id[ident] = label

    def _index_storage(self, storage_section: Any) -> None:
        if not isinstance(storage_section, dict) or storage_section.get("available") is False:
            return
        devices = storage_section.get("devices")
        if isinstance(devices, list):
            dict_devs = [d for d in devices if isinstance(d, dict)]
            raw_models: list[str | None] = []
            fallbacks: list[str] = []
            fallback_counts: dict[str, int] = {}
            for disk in dict_devs:
                model = _md_normalize_text(str(disk.get("model") or ""))
                raw_models.append(model if (model and not _html_is_redacted_id(model)) else None)
                kind = _md_normalize_text(str(disk.get("storage_type") or ""))
                base_fb = kind if (kind and not _html_is_redacted_id(kind)) else "Storage Device"
                fallback_counts[base_fb] = fallback_counts.get(base_fb, 0) + 1
                fallbacks.append(f"{base_fb} {fallback_counts[base_fb]}")
            self.drive_labels = _html_disambiguate_models(raw_models, fallbacks)
            for disk, label in zip(dict_devs, self.drive_labels):
                for key in ("device_name", "device_path"):
                    raw_id = _md_normalize_text(str(disk.get(key) or ""))
                    if raw_id:
                        self.drive_by_id.setdefault(raw_id, label)
                        if not raw_id.startswith("/") and not _html_is_redacted_id(raw_id):
                            self.drive_by_id.setdefault(f"/dev/{raw_id}", label)

        partitions = storage_section.get("partitions")
        if isinstance(partitions, list):
            for part in partitions:
                if not isinstance(part, dict):
                    continue
                part_path = _md_normalize_text(str(part.get("device_path") or ""))
                parent = _md_normalize_text(str(part.get("parent_device") or ""))
                part_num_raw = part.get("partition_number")
                part_num = (
                    part_num_raw
                    if isinstance(part_num_raw, int) and not isinstance(part_num_raw, bool)
                    else None
                )
                drive_label = self.drive_by_id.get(parent)
                if not drive_label and parent and not parent.startswith("/"):
                    drive_label = self.drive_by_id.get(f"/dev/{parent}")
                if part_path and drive_label:
                    self.partition_to_drive.setdefault(part_path, (drive_label, part_num))

    def _index_network(self, net_section: Any) -> None:
        if not isinstance(net_section, dict) or net_section.get("available") is False:
            return
        interfaces = net_section.get("interfaces")
        if not isinstance(interfaces, list):
            return
        dict_ifaces = [item for item in interfaces if isinstance(item, dict)]

        driver_pair_counts: dict[tuple[str, str], int] = {}
        prepared: list[tuple[str, str, str]] = []
        for iface in dict_ifaces:
            raw_name = _md_normalize_text(str(iface.get("interface") or ""))
            kind_raw = _md_normalize_text(str(iface.get("type") or ""))
            driver_raw = _md_normalize_text(str(iface.get("driver") or ""))
            kind_label = (
                _HTML_NIC_TYPE_LABELS.get(kind_raw.casefold(), f"{kind_raw} Interface")
                if (kind_raw and not _html_is_redacted_id(kind_raw))
                else "Network Interface"
            )
            driver = driver_raw if (driver_raw and not _html_is_redacted_id(driver_raw)) else ""
            prepared.append((raw_name, kind_label, driver))
            if (not raw_name or _html_is_redacted_id(raw_name)) and driver:
                pair = (kind_label, driver)
                driver_pair_counts[pair] = driver_pair_counts.get(pair, 0) + 1

        pair_seen: dict[tuple[str, str], int] = {}
        type_seen: dict[str, int] = {}
        for raw_name, kind_label, driver in prepared:
            if raw_name and not _html_is_redacted_id(raw_name):
                label = raw_name
            elif driver:
                pair = (kind_label, driver)
                if driver_pair_counts[pair] > 1:
                    pair_seen[pair] = pair_seen.get(pair, 0) + 1
                    label = f"{kind_label} {pair_seen[pair]} · {driver}"
                else:
                    label = f"{kind_label} · {driver}"
            else:
                type_seen[kind_label] = type_seen.get(kind_label, 0) + 1
                label = f"{kind_label} {type_seen[kind_label]}"
            self.iface_labels.append(label)
            if raw_name:
                self.iface_by_id.setdefault(raw_name, label)

    def _index_filesystems(self, fs_section: Any) -> None:
        if not isinstance(fs_section, dict) or fs_section.get("available") is False:
            return
        mounts = fs_section.get("mounts")
        if not isinstance(mounts, list):
            return
        dict_mounts = [m for m in mounts if isinstance(m, dict)]
        prefix_counts: dict[str, int] = {}
        non_virtual_ids: set[str] = set()
        for mount in dict_mounts:
            raw_mp = _md_normalize_text(str(mount.get("mountpoint") or ""))
            is_virtual = _html_is_virtual_fs(mount)
            if raw_mp and not _html_is_redacted_id(raw_mp):
                label = raw_mp
            elif is_virtual:
                prefix_counts["System Mount"] = prefix_counts.get("System Mount", 0) + 1
                label = f"System Mount {prefix_counts['System Mount']}"
            else:
                fstype = _md_normalize_text(str(mount.get("filesystem_type") or ""))
                prefix = _HTML_FS_FRIENDLY_LABELS.get(fstype.casefold())
                if not prefix:
                    prefix = (
                        f"{fstype} Volume"
                        if (fstype and not _html_is_redacted_id(fstype))
                        else "Storage Volume"
                    )
                prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1
                label = f"{prefix} {prefix_counts[prefix]}"
            self.mount_labels.append(label)
            if raw_mp:
                if not is_virtual:
                    self.mount_by_id[raw_mp] = label
                    non_virtual_ids.add(raw_mp)
                elif raw_mp not in non_virtual_ids:
                    self.mount_by_id.setdefault(raw_mp, label)

    def resolve_block_source(self, source: str) -> tuple[str | None, int | None]:
        """Resolve a mount/fstab source strictly via exact sanitized device/partition links."""
        cleaned = _md_normalize_text(source)
        if not cleaned:
            return None, None
        if cleaned in self.partition_to_drive:
            return self.partition_to_drive[cleaned]
        if cleaned in self.drive_by_id:
            return self.drive_by_id[cleaned], None
        match = _HTML_REDACTED_PARTITION_RE.fullmatch(cleaned)
        if match:
            base_dev, part_str = match.groups()
            drive = self.drive_by_id.get(base_dev)
            if drive:
                return drive, int(part_str)
        return None, None

    def resolve_parent_drive(self, parent: str) -> str | None:
        cleaned = _md_normalize_text(parent)
        if not cleaned:
            return None
        drive = self.drive_by_id.get(cleaned)
        if not drive and not cleaned.startswith("/"):
            drive = self.drive_by_id.get(f"/dev/{cleaned}")
        return drive

    def resolve_interface(self, raw_iface: str) -> tuple[str, bool]:
        cleaned = _md_normalize_text(raw_iface)
        if not cleaned:
            return "Not available", False
        if cleaned in self.iface_by_id:
            return self.iface_by_id[cleaned], _html_is_redacted_id(cleaned)
        if _html_is_redacted_id(cleaned):
            match = _HTML_REDACTED_KIND_NUM_RE.fullmatch(cleaned)
            if match:
                return f"Network Interface {match.group(2)}", True
            return "Network Interface", True
        return cleaned, False

    def resolve_sensor_device(self, raw_device: str) -> tuple[str, bool]:
        cleaned = _md_normalize_text(raw_device)
        if not cleaned:
            return "Not available", False
        if cleaned in self.gpu_by_id:
            return self.gpu_by_id[cleaned], _html_is_redacted_id(cleaned)
        if cleaned in self.drive_by_id:
            return self.drive_by_id[cleaned], _html_is_redacted_id(cleaned)
        drive, _ = self.resolve_block_source(cleaned)
        if drive:
            return drive, _html_is_redacted_id(cleaned)
        if _html_is_redacted_id(cleaned):
            match = _HTML_REDACTED_KIND_NUM_RE.fullmatch(cleaned)
            if match:
                kind, num = match.group(1).casefold(), match.group(2)
                if kind == "hardware":
                    return f"Hardware Device {num}", True
                if kind == "device":
                    return f"Storage Device {num}", True
            return "Hardware Device", True
        return cleaned, False

    def describe_fstab_target(self, raw_mountpoint: str, fstype: str) -> str:
        cleaned = _md_normalize_text(raw_mountpoint)
        if not cleaned:
            return "Not available"
        if not _html_is_redacted_id(cleaned):
            return cleaned
        if cleaned in self.mount_by_id:
            return self.mount_by_id[cleaned]
        low_fs = _md_normalize_text(fstype).casefold()
        if low_fs == "swap":
            return "Swap Target"
        if low_fs in {"proc", "sysfs", "tmpfs", "devpts", "devtmpfs"}:
            return "System Mount"
        if low_fs in {"cifs", "smb3", "nfs", "nfs4", "sshfs", "fuse.sshfs"}:
            return "Network Share Target"
        friendly = _HTML_FS_FRIENDLY_LABELS.get(low_fs)
        if friendly:
            return f"{friendly} Target"
        return "Configured Mount"

    def describe_fstab_source(self, raw_source: str) -> tuple[str, int | None, bool]:
        """Return (display_label, part_num, is_linked_hardware) for an fstab source."""
        cleaned = _md_normalize_text(raw_source)
        if not cleaned:
            return "Not available", None, False
        drive, part_num = self.resolve_block_source(cleaned)
        if drive:
            return drive, part_num, True
        if _html_is_redacted_id(cleaned):
            match = _HTML_REDACTED_KIND_NUM_RE.fullmatch(cleaned)
            if match:
                kind = match.group(1).casefold()
                if kind == "uuid":
                    return "Filesystem UUID", None, False
                if kind == "label":
                    return "Volume Label", None, False
                if kind == "source":
                    return "Network Share Source", None, False
                if kind == "device":
                    return "Storage Device", None, False
            part_match = _HTML_REDACTED_PARTITION_RE.fullmatch(cleaned)
            if part_match:
                return "Storage Device", int(part_match.group(2)), False
            return "Redacted Source", None, False
        return cleaned, None, False


def _html_os_distro_label(os_data: dict[str, Any]) -> str:
    distro = _md_normalize_text(str(os_data.get("distribution") or ""))
    version = _md_normalize_text(str(os_data.get("distribution_version") or ""))
    if distro and version and version not in distro:
        return f"{distro} {version}"
    return distro or version


def _html_build_summary_cards(sections: dict[str, Any], catalog: _HtmlHardwareCatalog) -> str:
    cards: list[str] = []

    os_data = sections.get("os")
    desktop_data = sections.get("desktop")
    if isinstance(os_data, dict) or isinstance(desktop_data, dict):
        os_avail = isinstance(os_data, dict) and os_data.get("available") is not False
        desk_avail = isinstance(desktop_data, dict) and desktop_data.get("available") is not False
        primary = ""
        sub_parts: list[str] = []
        if os_avail:
            assert isinstance(os_data, dict)
            primary = _html_os_distro_label(os_data)
            k_rel = _md_normalize_text(str(os_data.get("kernel_release") or ""))
            k_name = _md_normalize_text(str(os_data.get("kernel_name") or ""))
            if not primary:
                primary = " ".join(p for p in (k_name, k_rel) if p)
            elif k_rel:
                sub_parts.append(f"Kernel {k_rel}")
            uptime_text = _html_uptime_plain(os_data.get("uptime_seconds"))
            if uptime_text != "Not available":
                sub_parts.append(f"Uptime {uptime_text}")
        if desk_avail:
            assert isinstance(desktop_data, dict)
            de = _md_normalize_text(str(desktop_data.get("desktop_environment") or ""))
            stype = _md_normalize_text(str(desktop_data.get("session_type") or ""))
            desk_label = ""
            if de and stype:
                desk_label = f"{de} ({'X11' if stype.casefold() == 'x11' else stype})"
            elif de or stype:
                desk_label = de or ("X11" if stype.casefold() == "x11" else stype)
            if desk_label:
                if not primary:
                    primary = desk_label
                else:
                    sub_parts.insert(0, desk_label)
        if not primary:
            primary = "Unavailable"
            if isinstance(os_data, dict) and os_data.get("available") is False:
                sub_parts = ["Collection unavailable"]
        cards.append(
            '<div class="exec-card">'
            f'<div class="exec-card-header"><span class="exec-card-title">Operating System</span>{_HTML_ICONS["os"]}</div>'
            f'<div class="exec-card-value">{_html_esc(primary)}</div>'
            f'<div class="exec-card-sub">{_html_esc(" · ".join(sub_parts)) if sub_parts else _html_muted("No additional details")}</div>'
            "</div>"
        )

    cpu_data = sections.get("cpu")
    if isinstance(cpu_data, dict):
        if cpu_data.get("available") is False:
            val_html = _html_muted("Unavailable")
            sub_html = _html_muted("Collection unavailable")
        else:
            model = _md_normalize_text(str(cpu_data.get("model") or ""))
            val_html = _html_esc(model) if model else _html_muted("Not available")
            sub_parts = []
            phys = cpu_data.get("physical_cores")
            logi = cpu_data.get("logical_processors")
            if isinstance(phys, int) and not isinstance(phys, bool) and isinstance(logi, int) and not isinstance(logi, bool):
                sub_parts.append(f"{phys} Cores" if phys == logi else f"{phys} Cores / {logi} Threads")
            elif isinstance(phys, int) and not isinstance(phys, bool):
                sub_parts.append(f"{phys} Physical Cores")
            elif isinstance(logi, int) and not isinstance(logi, bool):
                sub_parts.append(f"{logi} Logical Processors")
            freq = _html_freq_plain(cpu_data.get("current_frequency_mhz"))
            if freq != "Not available":
                sub_parts.append(freq)
            temp = _html_temp_plain(cpu_data.get("temperature_c"))
            if temp != "Not available":
                sub_parts.append(temp)
            sub_html = _html_esc(" · ".join(sub_parts)) if sub_parts else _html_muted("Metrics unavailable")
        cards.append(
            '<div class="exec-card">'
            f'<div class="exec-card-header"><span class="exec-card-title">Processor</span>{_HTML_ICONS["cpu"]}</div>'
            f'<div class="exec-card-value">{val_html}</div>'
            f'<div class="exec-card-sub">{sub_html}</div>'
            "</div>"
        )

    mem_data = sections.get("memory")
    if isinstance(mem_data, dict):
        bar_html = ""
        if mem_data.get("available") is False:
            val_html = _html_muted("Unavailable")
            sub_html = _html_muted("Collection unavailable")
        else:
            ram = mem_data.get("ram")
            swap = mem_data.get("swap")
            if isinstance(ram, dict) and _is_number(ram.get("total_bytes")):
                val_html = _html_esc(f"{_html_bytes_plain(ram.get('total_bytes'))} RAM")
                sub_bits: list[str] = []
                if _is_number(ram.get("used_bytes")):
                    pct_s = _html_percent_plain(ram.get("percent_used"))
                    used_s = _html_bytes_plain(ram.get("used_bytes"))
                    sub_bits.append(f"{used_s} used ({pct_s})" if pct_s != "Not available" else f"{used_s} used")
                if _is_number(ram.get("available_bytes")):
                    sub_bits.append(f"{_html_bytes_plain(ram.get('available_bytes'))} available")
                sub_html = _html_esc(" · ".join(sub_bits)) if sub_bits else _html_muted("Usage unavailable")
                if _is_number(ram.get("percent_used")):
                    bar_html = _html_progress_bar(ram.get("percent_used"))
            elif isinstance(swap, dict):
                val_html = _html_muted("RAM not available")
                s_total = swap.get("total_bytes")
                if _html_numeric_valid(s_total) and s_total == 0:
                    sub_html = _html_esc("Swap: Not configured (0 B)")
                elif _is_number(s_total):
                    sub_html = _html_esc(f"Swap: {_html_bytes_plain(s_total)} total")
                else:
                    sub_html = _html_muted("Swap not available")
            else:
                val_html = _html_muted("Not available")
                sub_html = _html_muted("Memory metrics unavailable")
        cards.append(
            '<div class="exec-card">'
            f'<div class="exec-card-header"><span class="exec-card-title">System Memory</span>{_HTML_ICONS["memory"]}</div>'
            f'<div class="exec-card-value">{val_html}</div>'
            f'<div class="exec-card-sub">{sub_html}</div>'
            f"{bar_html}"
            "</div>"
        )

    gpu_data = sections.get("graphics")
    if isinstance(gpu_data, dict):
        if gpu_data.get("available") is False:
            val_html = _html_muted("Unavailable")
            sub_html = _html_muted("Collection unavailable")
        else:
            devices = gpu_data.get("devices")
            dict_gpus = [g for g in devices if isinstance(g, dict)] if isinstance(devices, list) else []
            if not dict_gpus:
                val_html = _html_muted("No GPUs reported")
                sub_html = _html_muted("No graphics adapters detected")
            else:
                first = dict_gpus[0]
                name = catalog.gpu_labels[0] if catalog.gpu_labels else "Graphics Device 1"
                val_html = _html_esc(name)
                sub_bits = []
                driver = _md_normalize_text(str(first.get("driver") or ""))
                if driver:
                    sub_bits.append(f"Driver: {driver}")
                pools = first.get("memory_pools")
                if isinstance(pools, dict):
                    vram = pools.get("driver_reported_vram")
                    if isinstance(vram, dict) and _is_number(vram.get("total_bytes")):
                        sub_bits.append(f"{_html_bytes_plain(vram.get('total_bytes'))} driver-reported VRAM")
                if len(dict_gpus) > 1:
                    sub_bits.append(f"+{len(dict_gpus) - 1} additional GPU" + ("s" if len(dict_gpus) > 2 else ""))
                sub_html = _html_esc(" · ".join(sub_bits)) if sub_bits else _html_muted("Details below")
        cards.append(
            '<div class="exec-card">'
            f'<div class="exec-card-header"><span class="exec-card-title">Graphics</span>{_HTML_ICONS["graphics"]}</div>'
            f'<div class="exec-card-value">{val_html}</div>'
            f'<div class="exec-card-sub">{sub_html}</div>'
            "</div>"
        )

    storage_data = sections.get("storage")
    fs_data = sections.get("filesystems")
    if isinstance(storage_data, dict):
        if storage_data.get("available") is False:
            val_html = _html_muted("Unavailable")
            sub_html = _html_muted("Collection unavailable")
        else:
            devices = storage_data.get("devices")
            dict_devs = [d for d in devices if isinstance(d, dict)] if isinstance(devices, list) else []
            if not dict_devs:
                val_html = _html_muted("No drives reported")
                sub_html = _html_muted("No physical storage devices")
            else:
                total_raw = sum(
                    float(d["capacity_bytes"])
                    for d in dict_devs
                    if _html_numeric_valid(d.get("capacity_bytes")) and d["capacity_bytes"] >= 0
                )
                has_cap = any(_is_number(d.get("capacity_bytes")) for d in dict_devs)
                if any(_is_number(d.get("capacity_bytes")) and not _html_numeric_valid(d["capacity_bytes"]) for d in dict_devs):
                    total_raw = float("inf")
                noun = "Drive" if len(dict_devs) == 1 else "Drives"
                if len(dict_devs) == 1:
                    single_name = catalog.drive_labels[0] if catalog.drive_labels else "Storage Device 1"
                    val_html = _html_esc(single_name)
                else:
                    val_html = _html_esc(
                        f"{len(dict_devs)} Physical {noun} ({_html_bytes_plain(total_raw)} raw)"
                        if has_cap else f"{len(dict_devs)} Physical {noun}"
                    )
                type_counts: dict[str, int] = {}
                for d in dict_devs:
                    kind = _md_normalize_text(str(d.get("storage_type") or "Storage"))
                    type_counts[kind] = type_counts.get(kind, 0) + 1
                sub_bits = [f"{cnt} {kind}" for kind, cnt in type_counts.items()]
                if isinstance(fs_data, dict) and isinstance(fs_data.get("mounts"), list):
                    vol_count = sum(
                        1 for m in fs_data["mounts"]
                        if isinstance(m, dict) and not _html_is_virtual_fs(m) and isinstance(m.get("capacity"), dict)
                    )
                    if vol_count:
                        sub_bits.append(f"{vol_count} mounted {'volume' if vol_count == 1 else 'volumes'}")
                sub_html = _html_esc(" · ".join(sub_bits))
        cards.append(
            '<div class="exec-card">'
            f'<div class="exec-card-header"><span class="exec-card-title">Storage</span>{_HTML_ICONS["storage"]}</div>'
            f'<div class="exec-card-value">{val_html}</div>'
            f'<div class="exec-card-sub">{sub_html}</div>'
            "</div>"
        )

    net_data = sections.get("network")
    if isinstance(net_data, dict):
        if net_data.get("available") is False:
            val_html = _html_muted("Unavailable")
            sub_html = _html_muted("Collection unavailable")
        else:
            ifaces = net_data.get("interfaces")
            dict_ifaces = [i for i in ifaces if isinstance(i, dict)] if isinstance(ifaces, list) else []
            if not dict_ifaces:
                val_html = _html_muted("No interfaces reported")
                sub_html = _html_muted("No network adapters detected")
            else:
                connected = [
                    (idx, i) for idx, i in enumerate(dict_ifaces)
                    if str(i.get("connection_state") or "").casefold() == "connected"
                ]
                val_html = _html_esc(f"{len(connected)} / {len(dict_ifaces)} Connected")
                sub_bits = []
                active_labels: list[str] = []
                for idx, item in connected:
                    kind = _md_normalize_text(str(item.get("type") or ""))
                    driver = _md_normalize_text(str(item.get("driver") or ""))
                    speed = _html_speed_mbps_plain(item.get("link_speed_mbps"))
                    if kind and driver and not _html_is_redacted_id(driver):
                        desc = f"{kind} · {driver}"
                    elif kind:
                        desc = kind
                    elif idx < len(catalog.iface_labels):
                        desc = catalog.iface_labels[idx]
                    else:
                        desc = ""
                    if desc and speed != "Not available":
                        desc = f"{desc} ({speed.split(' (', 1)[0]})"
                    if desc and desc not in active_labels:
                        active_labels.append(desc)
                if active_labels:
                    sub_bits.append(", ".join(active_labels[:3]))
                    if len(active_labels) > 3:
                        sub_bits.append(f"+{len(active_labels) - 3} more")
                else:
                    sub_bits.append("No active links")
                sub_html = _html_esc(" · ".join(sub_bits))
        cards.append(
            '<div class="exec-card">'
            f'<div class="exec-card-header"><span class="exec-card-title">Network</span>{_HTML_ICONS["network"]}</div>'
            f'<div class="exec-card-value">{val_html}</div>'
            f'<div class="exec-card-sub">{sub_html}</div>'
            "</div>"
        )

    if not cards:
        return ""
    cols_cls = " cols-1" if len(cards) == 1 else (" cols-2" if len(cards) == 2 else "")
    return f'<section class="exec-grid{cols_cls}" aria-label="System Overview">{"".join(cards)}</section>'


def _html_render_os(data: dict[str, Any]) -> tuple[str, list[str]]:
    if data.get("available") is False:
        return '<p class="note-text">Operating system information could not be collected.</p>', []

    handled = {
        "distribution", "distribution_version", "os_architecture", "kernel_name",
        "kernel_release", "kernel_version", "hostname", "uptime_seconds",
        "boot_mode", "identification", "kernel_command_line",
    }
    distro_text = _html_os_distro_label(data)
    kernel_name = _md_normalize_text(str(data.get("kernel_name") or ""))
    kernel_release = _md_normalize_text(str(data.get("kernel_release") or ""))
    kernel_text = " ".join(p for p in (kernel_name, kernel_release) if p)

    boot_raw = _md_normalize_text(str(data.get("boot_mode") or ""))
    if boot_raw:
        boot_html = _html_badge(boot_raw, "mint" if boot_raw.casefold() == "uefi" else "blue")
    else:
        boot_html = _html_muted("Not available")

    rows: list[tuple[str, str]] = [
        ("Distribution", f"<strong>{_html_esc(distro_text)}</strong>" if distro_text else _html_muted("Not available")),
        ("Architecture", _html_text_cell(data.get("os_architecture"), mono=True)),
        ("Kernel", _html_mono(kernel_text) if kernel_text else _html_muted("Not available")),
        ("Kernel Build", _html_text_cell(data.get("kernel_version"))),
        ("Hostname", _html_text_cell(data.get("hostname"), mono=True)),
        ("Uptime", _html_text_cell(_html_uptime_plain(data.get("uptime_seconds")))),
        ("Boot Mode", boot_html),
    ]
    for key, value in data.items():
        if key not in handled and not isinstance(value, (dict, list)):
            rows.append((_md_label(key), _html_value_cell(value, key)))

    parts: list[str] = [f'<div class="filter-block">{_html_kv_table(rows)}</div>']

    identification = data.get("identification")
    if isinstance(identification, dict) and identification:
        id_rows: list[tuple[str, str]] = []
        for key, val in identification.items():
            use_mono = key.casefold() in {"bios_version", "bios_date", "product_version"}
            id_rows.append((_md_label(key), _html_text_cell(val, mono=use_mono)))
        parts.append(
            '<div class="filter-block">'
            '<div class="section-label">Machine &amp; Firmware</div>'
            f"{_html_kv_table(id_rows)}"
            "</div>"
        )

    cmdline = data.get("kernel_command_line")
    if isinstance(cmdline, list):
        tokens: list[str] = []
        param_rows: list[list[str]] = []
        for item in cmdline:
            if isinstance(item, dict):
                param = _md_normalize_text(str(item.get("parameter") or ""))
                val = item.get("value")
                if not param:
                    continue
                if val == "present" or val is None:
                    tokens.append(param)
                    param_rows.append([_html_mono(param), _html_badge("present", "mint")])
                elif _is_option_list(val):
                    opt_str = _format_option_list(val)
                    tokens.append(f"{param}={opt_str.replace(', ', ',')}")
                    param_rows.append([_html_mono(param), _html_mono(opt_str)])
                else:
                    cleaned = _md_normalize_text(str(val))
                    tokens.append(f"{param}={cleaned}")
                    param_rows.append([_html_mono(param), _html_mono(cleaned)])
            elif isinstance(item, str):
                cleaned = _md_normalize_text(item)
                if cleaned:
                    tokens.append(cleaned)
                    param_rows.append([_html_mono(cleaned), _html_badge("flag")])
        if tokens:
            cmd_body = (
                f'<pre class="code-block filter-item">{_html_esc(" ".join(tokens))}</pre>'
                + _html_data_table(["Parameter", "Value"], param_rows, raw_cells=True)
            )
            parts.append(_html_details("Kernel Command Line", cmd_body, badge=f"{len(tokens)} params"))
        else:
            parts.append('<p class="note-text">No safe kernel command-line parameters were reported.</p>')

    for key, value in data.items():
        if key not in handled and isinstance(value, (dict, list)):
            parts.append(
                f'<div class="filter-block"><div class="section-label">{_html_esc(_md_label(key))}</div>'
                f"{_html_render_generic(value)}</div>"
            )

    badges: list[str] = []
    if boot_raw:
        badges.append(_html_badge(boot_raw, "mint" if boot_raw.casefold() == "uefi" else ""))
    return "".join(parts), badges


def _html_render_desktop(data: dict[str, Any]) -> tuple[str, list[str]]:
    if data.get("available") is False:
        return '<p class="note-text">Desktop environment information could not be collected.</p>', []

    handled = {
        "desktop_environment", "session", "session_type", "window_manager",
        "screens", "qt_version", "pyside_version",
    }
    stype_raw = _md_normalize_text(str(data.get("session_type") or ""))
    if stype_raw:
        stype_label = "X11" if stype_raw.casefold() == "x11" else stype_raw
        stype_html = _html_badge(stype_label, "blue")
    else:
        stype_label = ""
        stype_html = _html_muted("Not available")

    qt_ver = _md_normalize_text(str(data.get("qt_version") or ""))
    pyside_ver = _md_normalize_text(str(data.get("pyside_version") or ""))
    if qt_ver or pyside_ver:
        qt_html = f'{_html_mono(qt_ver or "Not available")} / {_html_mono(pyside_ver or "Not available")}'
    else:
        qt_html = _html_muted("Not available")

    rows: list[tuple[str, str]] = [
        ("Desktop Environment", _html_text_cell(data.get("desktop_environment"))),
        ("Session", _html_text_cell(data.get("session"), mono=True)),
        ("Session Type", stype_html),
        ("Window Manager", _html_text_cell(data.get("window_manager"))),
        ("Qt / PySide", qt_html),
    ]
    for key, value in data.items():
        if key not in handled and not isinstance(value, (dict, list)):
            rows.append((_md_label(key), _html_value_cell(value, key)))

    parts: list[str] = [f'<div class="filter-block">{_html_kv_table(rows)}</div>']
    badges: list[str] = []
    if stype_label:
        badges.append(_html_badge(stype_label, "blue"))

    screens = data.get("screens")
    if isinstance(screens, list):
        screen_rows: list[list[str]] = []
        for idx, screen in enumerate(screens, 1):
            if not isinstance(screen, dict):
                continue
            width = screen.get("width")
            height = screen.get("height")
            if _is_number(width) and _is_number(height):
                res_html = f"<strong>{_html_esc(f'{width} × {height}')}</strong>"
            else:
                res_html = _html_muted("Not available")
            scale = screen.get("scale")
            if _html_numeric_valid(scale):
                num_scale = float(scale)
                scale_str = f"{num_scale:.1f}x" if round(num_scale, 1) == round(num_scale, 2) else f"{num_scale:.2f}x"
                scale_html = _html_mono(scale_str)
            else:
                scale_html = _html_muted(_html_numeric_unavailable(scale))
            screen_rows.append([f"Display {idx}", res_html, scale_html])
        if screen_rows:
            badges.append(_html_badge(f"{len(screen_rows)} {'display' if len(screen_rows) == 1 else 'displays'}", "mono"))
            parts.append(
                '<div class="filter-block">'
                '<div class="section-label">Connected Displays</div>'
                f"{_html_data_table(['Display', 'Resolution', 'Scale'], screen_rows, raw_cells=True)}"
                "</div>"
            )
        else:
            parts.append('<p class="note-text">No display details were reported.</p>')

    for key, value in data.items():
        if key not in handled and isinstance(value, (dict, list)):
            parts.append(
                f'<div class="filter-block"><div class="section-label">{_html_esc(_md_label(key))}</div>'
                f"{_html_render_generic(value)}</div>"
            )

    return "".join(parts), badges


def _html_render_cpu(data: dict[str, Any]) -> tuple[str, list[str]]:
    if data.get("available") is False:
        return '<p class="note-text">CPU information could not be collected.</p>', []

    handled = {
        "model", "architecture", "physical_cores", "logical_processors",
        "current_frequency_mhz", "capabilities", "temperature_c",
    }
    model = _md_normalize_text(str(data.get("model") or ""))
    phys = data.get("physical_cores")
    logi = data.get("logical_processors")
    if isinstance(phys, int) and not isinstance(phys, bool) and isinstance(logi, int) and not isinstance(logi, bool):
        cores_html = f"<strong>{phys}</strong> Physical Cores / <strong>{logi}</strong> Logical Processors"
    elif phys is None and logi is None:
        cores_html = _html_muted("Not available")
    else:
        p_txt = str(phys) if phys is not None else "Not available"
        l_txt = str(logi) if logi is not None else "Not available"
        cores_html = _html_esc(f"{p_txt} / {l_txt}")

    freq_str = _html_freq_plain(data.get("current_frequency_mhz"))
    freq_html = _html_mono(freq_str) if freq_str != "Not available" else _html_muted(freq_str)

    rows: list[tuple[str, str]] = [
        ("Processor Model", f"<strong>{_html_esc(model)}</strong>" if model else _html_muted("Not available")),
        ("Architecture", _html_text_cell(data.get("architecture"), mono=True)),
        ("Cores / Threads", cores_html),
        ("Current Frequency", freq_html),
        ("Temperature", _html_temp_cell(data.get("temperature_c"))),
    ]
    for key, value in data.items():
        if key not in handled and not isinstance(value, (dict, list)):
            rows.append((_md_label(key), _html_value_cell(value, key)))

    parts: list[str] = [f'<div class="filter-block">{_html_kv_table(rows)}</div>']
    badges: list[str] = []
    if isinstance(phys, int) and not isinstance(phys, bool) and isinstance(logi, int) and not isinstance(logi, bool):
        badges.append(_html_badge(f"{phys}C / {logi}T", "mint mono"))

    capabilities = data.get("capabilities")
    if isinstance(capabilities, list):
        clean_flags = [_md_normalize_text(str(flag)) for flag in capabilities if _md_normalize_text(str(flag))]
        if clean_flags:
            chips = "".join(f'<span class="chip filter-item">{_html_esc(flag)}</span>' for flag in clean_flags)
            parts.append(
                _html_details(
                    "Advanced CPU Capabilities & Flags",
                    f'<div class="chip-list">{chips}</div>',
                    badge=f"{len(clean_flags)} flags",
                )
            )
        else:
            parts.append('<p class="note-text">No CPU capability flags were reported.</p>')

    for key, value in data.items():
        if key not in handled and isinstance(value, (dict, list)):
            parts.append(
                f'<div class="filter-block"><div class="section-label">{_html_esc(_md_label(key))}</div>'
                f"{_html_render_generic(value)}</div>"
            )

    return "".join(parts), badges


def _html_render_memory(data: dict[str, Any]) -> tuple[str, list[str]]:
    if data.get("available") is False:
        return '<p class="note-text">Memory information could not be collected.</p>', []

    handled = {"ram", "swap", "kernel_memory_details", "configuration"}
    pool_rows: list[list[str]] = []
    bars: list[str] = []
    badges: list[str] = []

    ram = data.get("ram")
    if isinstance(ram, dict):
        ram_total = _html_bytes_plain(ram.get("total_bytes"))
        ram_used = _html_bytes_plain(ram.get("used_bytes"))
        ram_avail = _html_bytes_plain(ram.get("available_bytes"))
        pool_rows.append([
            "<strong>Physical RAM</strong>",
            f"<strong>{_html_esc(ram_total)}</strong>" if ram_total != "Not available" else _html_muted(ram_total),
            _html_bytes_cell(ram.get("used_bytes")),
            _html_bytes_cell(ram.get("available_bytes")),
            _html_percent_badge(ram.get("percent_used")),
        ])
        if _is_number(ram.get("percent_used")):
            bars.append(_html_progress_bar(ram.get("percent_used"), label="RAM Load", detail=f"{ram_used} / {ram_total}"))
        if ram_total != "Not available":
            badges.append(_html_badge(f"{ram_total} RAM", "blue mono"))
    elif "ram" in data:
        pool_rows.append([
            "<strong>Physical RAM</strong>",
            _html_muted("Not available"),
            _html_muted("Not available"),
            _html_muted("Not available"),
            _html_muted("Not available"),
        ])

    swap = data.get("swap")
    if isinstance(swap, dict):
        s_total_raw = swap.get("total_bytes")
        swap_unconfigured = _html_numeric_valid(s_total_raw) and s_total_raw == 0
        s_total = _html_bytes_plain(s_total_raw)
        s_used = _html_bytes_plain(swap.get("used_bytes"))
        usage_cell = _html_badge("Not configured") if swap_unconfigured else _html_percent_badge(swap.get("percent_used"))
        pool_rows.append([
            "<strong>Swap Space</strong>",
            f"<strong>{_html_esc(s_total)}</strong>" if s_total != "Not available" else _html_muted(s_total),
            _html_bytes_cell(swap.get("used_bytes")),
            _html_bytes_cell(swap.get("available_bytes")),
            usage_cell,
        ])
        if not swap_unconfigured and _is_number(swap.get("percent_used")):
            bars.append(_html_progress_bar(swap.get("percent_used"), label="Swap Load", detail=f"{s_used} / {s_total}"))
    elif "swap" in data:
        pool_rows.append([
            "<strong>Swap Space</strong>",
            _html_muted("Not available"),
            _html_muted("Not available"),
            _html_muted("Not available"),
            _html_muted("Not available"),
        ])

    parts: list[str] = []
    if pool_rows:
        parts.append(
            '<div class="filter-block">'
            f"{_html_data_table(['Pool', 'Total', 'Used', 'Available', 'Usage'], pool_rows, raw_cells=True)}"
            "</div>"
        )
    if bars:
        parts.append(f'<div class="filter-block">{"".join(bars)}</div>')

    detail_rows: list[tuple[str, str]] = []
    if isinstance(ram, dict):
        if "cached_bytes" in ram:
            detail_rows.append(("RAM Cached", _html_bytes_cell(ram.get("cached_bytes"))))
        if "buffers_bytes" in ram:
            detail_rows.append(("RAM Buffers", _html_bytes_cell(ram.get("buffers_bytes"))))
        for key, value in ram.items():
            if key not in {"total_bytes", "available_bytes", "used_bytes", "percent_used", "cached_bytes", "buffers_bytes"}:
                detail_rows.append((f"RAM {_md_label(key)}", _html_value_cell(value, key)))
    if isinstance(swap, dict):
        for key, value in swap.items():
            if key not in {"total_bytes", "available_bytes", "used_bytes", "percent_used"}:
                detail_rows.append((f"Swap {_md_label(key)}", _html_value_cell(value, key)))

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
            if lowered == "hugepages_total":
                val_html = _html_mono(_md_int_count(value)) if _is_number(value) else _html_muted("Not available")
            else:
                val_html = _html_value_cell(value, key, "kernel_memory_details")
            detail_rows.append((label, val_html))

    if detail_rows:
        parts.append(
            '<div class="filter-block">'
            '<div class="section-label">Cache, Buffers &amp; Kernel Memory</div>'
            f"{_html_kv_table(detail_rows)}"
            "</div>"
        )

    config = data.get("configuration")
    if isinstance(config, dict) and config:
        pills = "".join(
            '<div class="stat-pill filter-item">'
            f'<div class="stat-pill-label">{_html_esc(_md_label(key))}</div>'
            f'<div class="stat-pill-val">{_html_esc(_html_value_plain(val, key))}</div>'
            "</div>"
            for key, val in config.items()
        )
        parts.append(
            '<div class="filter-block">'
            '<div class="section-label">Virtual Memory Configuration</div>'
            f'<div class="stat-grid">{pills}</div>'
            "</div>"
        )

    for key, value in data.items():
        if key not in handled:
            parts.append(
                f'<div class="filter-block"><div class="section-label">{_html_esc(_md_label(key))}</div>'
                f"{_html_render_generic(value)}</div>"
            )

    return "".join(parts) or '<p class="note-text">No memory details were available.</p>', badges


def _html_render_graphics(data: dict[str, Any], catalog: _HtmlHardwareCatalog) -> tuple[str, list[str]]:
    if data.get("available") is False:
        return '<p class="note-text">Graphics hardware information could not be collected.</p>', []

    parts: list[str] = []
    badges: list[str] = []
    devices = data.get("devices")

    if isinstance(devices, list):
        dict_gpus = [g for g in devices if isinstance(g, dict)]
        if not dict_gpus:
            parts.append('<p class="note-text">No graphics devices were reported.</p>')
        else:
            badges.append(_html_badge(f"{len(dict_gpus)} {'GPU' if len(dict_gpus) == 1 else 'GPUs'}", "purple mono"))
            gpu_cards: list[str] = []
            handled_gpu = {
                "identity", "model", "pci_vendor_id", "pci_device_id", "driver",
                "memory_pools", "utilization_percent", "telemetry_capabilities", "sensors",
            }
            for index, gpu in enumerate(dict_gpus, 1):
                title_name = catalog.gpu_labels[index - 1] if index - 1 < len(catalog.gpu_labels) else f"Graphics Device {index}"
                driver = _md_normalize_text(str(gpu.get("driver") or ""))
                identity = _md_normalize_text(str(gpu.get("identity") or ""))
                identity_redacted = bool(identity) and _html_is_redacted_id(identity)
                vendor = _md_normalize_text(str(gpu.get("pci_vendor_id") or ""))
                device_id = _md_normalize_text(str(gpu.get("pci_device_id") or ""))
                pci_text = f"{vendor} / {device_id}" if (vendor and device_id) else (vendor or device_id)

                sub_badges: list[str] = [_html_badge(f"GPU {index}", "blue mono")]
                if driver:
                    sub_badges.append(_html_badge(driver, "purple mono"))
                if identity and not identity_redacted:
                    sub_badges.append(_html_badge(identity, "mono"))

                card_bits: list[str] = []
                prop_rows: list[tuple[str, str]] = [
                    ("Driver", _html_text_cell(gpu.get("driver"), mono=True)),
                    ("PCI Vendor / Device", _html_mono(pci_text) if pci_text else _html_muted("Not available")),
                    ("Utilization", _html_percent_badge(gpu.get("utilization_percent"))),
                ]
                if identity and not identity_redacted:
                    prop_rows.insert(0, ("Device Identity", _html_mono(identity)))
                for key, value in gpu.items():
                    if key not in handled_gpu and not isinstance(value, (dict, list)):
                        prop_rows.append((_md_label(key), _html_value_cell(value, key)))
                card_bits.append(_html_kv_table(prop_rows))

                if _is_number(gpu.get("utilization_percent")):
                    card_bits.append(_html_progress_bar(gpu.get("utilization_percent"), label="GPU Utilization"))

                pools = gpu.get("memory_pools")
                if isinstance(pools, dict) and pools:
                    pool_rows: list[list[str]] = []
                    notes: list[str] = []
                    for pool_key, pool_data in pools.items():
                        if not isinstance(pool_data, dict):
                            continue
                        lowered_pool = pool_key.casefold()
                        if "vram" in lowered_pool:
                            pool_label = "VRAM (Driver-Reported)"
                        elif "gtt" in lowered_pool:
                            pool_label = "GTT (Driver-Reported)"
                        else:
                            pool_label = _md_label(pool_key)
                        used_b = pool_data.get("used_bytes")
                        total_b = pool_data.get("total_bytes")
                        if _html_numeric_valid(used_b) and _html_numeric_valid(total_b) and float(total_b) > 0:
                            pct_val = (float(used_b) / float(total_b)) * 100.0
                            usage_cell = _html_progress_bar(pct_val, inline=True)
                        else:
                            usage_cell = _html_muted("Out of range" if any(_is_number(v) and not _html_numeric_valid(v) for v in (used_b, total_b)) else "Not available")
                        pool_rows.append([
                            f"<strong>{_html_esc(pool_label)}</strong>",
                            _html_bytes_cell(used_b),
                            _html_bytes_cell(total_b),
                            usage_cell,
                        ])
                        classification = _md_normalize_text(str(pool_data.get("classification") or ""))
                        if classification and classification not in notes:
                            notes.append(classification)
                    if pool_rows:
                        caveats = "".join(f'<p class="caveat-text">Note: {_html_esc(n)}</p>' for n in notes)
                        card_bits.append(
                            '<div><div class="section-label">Memory Pools</div>'
                            f"{_html_data_table(['Pool', 'Used', 'Total', 'Usage'], pool_rows, raw_cells=True)}"
                            f"{caveats}</div>"
                        )

                sensors = gpu.get("sensors")
                if isinstance(sensors, dict):
                    if sensors:
                        sensor_rows = [
                            [_html_esc(_md_label(s_name)), _html_mono(_html_gpu_sensor_plain(s_name, s_val))]
                            for s_name, s_val in sensors.items()
                        ]
                        card_bits.append(
                            '<div><div class="section-label">GPU Sensors</div>'
                            f"{_html_data_table(['Sensor', 'Reading'], sensor_rows, raw_cells=True)}"
                            "</div>"
                        )
                    else:
                        card_bits.append('<p class="note-text">No GPU sensor readings were reported.</p>')

                caps = gpu.get("telemetry_capabilities")
                clean_caps = (
                    [_md_normalize_text(str(c)) for c in caps if _md_normalize_text(str(c))]
                    if isinstance(caps, list) else []
                )
                if clean_caps or identity_redacted:
                    detail_parts: list[str] = []
                    if identity_redacted:
                        detail_parts.append(_html_kv_table([("Diagnostic Reference ID", _html_mono(identity))]))
                    if clean_caps:
                        chips = "".join(f'<span class="chip filter-item">{_html_esc(c)}</span>' for c in clean_caps)
                        detail_parts.append(f'<div class="chip-list">{chips}</div>')
                    elif isinstance(caps, list):
                        detail_parts.append('<p class="note-text">No telemetry capabilities were reported.</p>')
                    panel_title = (
                        "Telemetry Capabilities & Technical Details"
                        if (clean_caps and identity_redacted)
                        else ("Telemetry Capabilities" if clean_caps else "Technical Details")
                    )
                    badge_txt = f"{len(clean_caps)} caps" if clean_caps else "ref ID"
                    card_bits.append(_html_details(panel_title, "".join(detail_parts), badge=badge_txt))
                elif isinstance(caps, list):
                    card_bits.append('<p class="note-text">No telemetry capabilities were reported.</p>')

                for key, value in gpu.items():
                    if key not in handled_gpu and isinstance(value, (dict, list)):
                        card_bits.append(
                            f'<div><div class="section-label">{_html_esc(_md_label(key))}</div>'
                            f"{_html_render_generic(value)}</div>"
                        )

                gpu_cards.append(
                    '<article class="sub-card filter-group">'
                    '<div class="sub-card-header">'
                    f"<h3>{_html_esc(title_name)}</h3>"
                    f'<div class="card-header-badges">{"".join(sub_badges)}</div>'
                    "</div>"
                    f'<div class="sub-card-body">{"".join(card_bits)}</div>'
                    "</article>"
                )
            parts.append(f'<div class="sub-grid">{"".join(gpu_cards)}</div>')

    for key, value in data.items():
        if key != "devices":
            parts.append(
                f'<div class="filter-block"><div class="section-label">{_html_esc(_md_label(key))}</div>'
                f"{_html_render_generic(value)}</div>"
            )

    return "".join(parts) or '<p class="note-text">No graphics hardware details were available.</p>', badges


def _html_storage_type_badge(storage_type: Any) -> str:
    cleaned = _md_normalize_text(str(storage_type or ""))
    if not cleaned:
        return _html_muted("Not available")
    low = cleaned.casefold()
    if "nvme" in low:
        return _html_badge(cleaned, "blue")
    if "ssd" in low:
        return _html_badge(cleaned, "mint")
    if "usb" in low or "optical" in low:
        return _html_badge(cleaned, "warn")
    return _html_badge(cleaned)


def _html_render_storage(data: dict[str, Any], catalog: _HtmlHardwareCatalog) -> tuple[str, list[str]]:
    if data.get("available") is False:
        return '<p class="note-text">Storage hardware information could not be collected.</p>', []

    parts: list[str] = []
    badges: list[str] = []
    tech_refs: list[list[str]] = []

    devices = data.get("devices")
    if isinstance(devices, list):
        dict_devs = [d for d in devices if isinstance(d, dict)]
        badges.append(_html_badge(f"{len(dict_devs)} {'device' if len(dict_devs) == 1 else 'devices'}", "blue mono"))
        any_unredacted_dev = any(
            (raw := _md_normalize_text(str(d.get("device_path") or d.get("device_name") or "")))
            and not _html_is_redacted_id(raw)
            for d in dict_devs
        )
        dev_rows: list[list[str]] = []
        for idx, disk in enumerate(dict_devs):
            drive_label = catalog.drive_labels[idx] if idx < len(catalog.drive_labels) else f"Storage Device {idx + 1}"
            dev_name = _md_normalize_text(str(disk.get("device_name") or ""))
            dev_path = _md_normalize_text(str(disk.get("device_path") or ""))
            if dev_name and dev_path and dev_path not in {dev_name, f"/dev/{dev_name}"}:
                raw_dev_id = f"{dev_name} ({dev_path})"
            else:
                raw_dev_id = dev_path or dev_name
            dev_is_redacted = bool(raw_dev_id) and _html_is_redacted_id(dev_path or dev_name)
            if dev_is_redacted:
                tech_refs.append([_html_badge("Drive", "blue"), _html_esc(drive_label), _html_mono(raw_dev_id)])

            cap_str = _html_bytes_plain(disk.get("capacity_bytes"))
            cap_html = f'<span class="num-cell"><strong>{_html_esc(cap_str)}</strong></span>' if cap_str != "Not available" else _html_muted(cap_str)
            temp_sup = disk.get("temperature_supported")
            row = [f"<strong>{_html_esc(drive_label)}</strong>"]
            if any_unredacted_dev:
                row.append(_html_mono(raw_dev_id) if (raw_dev_id and not dev_is_redacted) else _html_muted("Redacted"))
            row.extend([
                _html_storage_type_badge(disk.get("storage_type")),
                cap_html,
                _html_temp_cell(disk.get("temperature_c"), supported=temp_sup),
                _html_text_cell(temp_sup),
            ])
            dev_rows.append(row)
        if dev_rows:
            headers = ["Drive", "Device", "Type", "Raw Capacity", "Temperature", "Temp. Supported"] if any_unredacted_dev else ["Drive", "Type", "Raw Capacity", "Temperature", "Temp. Supported"]
            parts.append(
                '<div class="filter-block">'
                '<div class="section-label">Physical Storage Devices</div>'
                f"{_html_data_table(headers, dev_rows, raw_cells=True)}"
                '<p class="caveat-text">Raw block device capacities reflect physical hardware size and differ from mounted filesystem capacities.</p>'
                "</div>"
            )
        else:
            parts.append('<p class="note-text">No physical storage devices were reported.</p>')

    partitions = data.get("partitions")
    if isinstance(partitions, list):
        dict_parts = [p for p in partitions if isinstance(p, dict)]
        if dict_parts:
            badges.append(_html_badge(f"{len(dict_parts)} {'partition' if len(dict_parts) == 1 else 'partitions'}", "mono"))
            any_unredacted_part = any(
                (raw := _md_normalize_text(str(p.get("device_path") or "")))
                and not _html_is_redacted_id(raw)
                for p in dict_parts
            )
            part_rows: list[list[str]] = []
            for idx, part in enumerate(dict_parts, 1):
                raw_path = _md_normalize_text(str(part.get("device_path") or ""))
                raw_parent = _md_normalize_text(str(part.get("parent_device") or ""))
                part_num = part.get("partition_number")
                parent_label = catalog.resolve_parent_drive(raw_parent)
                if parent_label:
                    parent_html = f"<strong>{_html_esc(parent_label)}</strong>"
                elif raw_parent and not _html_is_redacted_id(raw_parent):
                    parent_html = _html_mono(raw_parent)
                else:
                    parent_html = _html_muted("Unlinked Drive")

                if isinstance(part_num, int) and not isinstance(part_num, bool):
                    part_desc = f"Partition {part_num}"
                else:
                    part_desc = f"Partition {idx}"

                if raw_path and _html_is_redacted_id(raw_path):
                    ref_target = f"{parent_label} · {part_desc}" if parent_label else part_desc
                    tech_refs.append([_html_badge("Partition", "mono"), _html_esc(ref_target), _html_mono(raw_path)])

                row = [parent_html]
                if any_unredacted_part:
                    row.append(_html_mono(raw_path) if (raw_path and not _html_is_redacted_id(raw_path)) else _html_muted("Redacted"))
                row.extend([
                    _html_badge(part_desc, "mono"),
                    f'<span class="num-cell">{_html_bytes_cell(part.get("capacity_bytes"))}</span>',
                ])
                part_rows.append(row)
            part_headers = ["Parent Drive", "Device Path", "Partition", "Partition Capacity"] if any_unredacted_part else ["Parent Drive", "Partition", "Partition Capacity"]
            parts.append(
                '<div class="filter-block">'
                '<div class="section-label">Partitions</div>'
                f"{_html_data_table(part_headers, part_rows, raw_cells=True)}"
                "</div>"
            )
        else:
            parts.append('<p class="note-text">No partitions were reported.</p>')

    if tech_refs:
        parts.append(
            _html_details(
                "Technical Storage Identifiers",
                _html_data_table(["Kind", "Hardware Description", "Reference ID"], tech_refs, raw_cells=True),
                badge=f"{len(tech_refs)} refs",
            )
        )

    for key, value in data.items():
        if key not in {"devices", "partitions"}:
            parts.append(
                f'<div class="filter-block"><div class="section-label">{_html_esc(_md_label(key))}</div>'
                f"{_html_render_generic(value)}</div>"
            )

    return "".join(parts) or '<p class="note-text">No storage details were available.</p>', badges


def _html_render_filesystems(data: dict[str, Any], catalog: _HtmlHardwareCatalog) -> tuple[str, list[str]]:
    if data.get("available") is False:
        return '<p class="note-text">Filesystem and mount information could not be collected.</p>', []

    parts: list[str] = []
    badges: list[str] = []

    mountinfo_avail = data.get("mountinfo_available")
    fstab = data.get("fstab")
    fstab_avail = fstab.get("available") if isinstance(fstab, dict) else None
    if mountinfo_avail is not None:
        badges.append(_html_badge(f"mountinfo: {'Yes' if mountinfo_avail else 'No'}", "mint" if mountinfo_avail else "warn"))
    if fstab_avail is not None:
        badges.append(_html_badge(f"fstab: {'Yes' if fstab_avail else 'No'}", "mint" if fstab_avail else "warn"))

    mounts = data.get("mounts")
    if isinstance(mounts, list):
        dict_mounts = [m for m in mounts if isinstance(m, dict)]
        volume_rows: list[list[str]] = []
        extra_storage_rows: list[list[str]] = []
        virtual_rows: list[list[str]] = []
        virtual_has_cap = False
        virtual_types: dict[str, int] = {}
        advanced_items: list[str] = []
        known_mount_keys = {
            "mountpoint", "filesystem_type", "source", "device_number",
            "root", "options", "super_options", "capacity",
        }

        for idx, mount in enumerate(dict_mounts):
            raw_mp = _md_normalize_text(str(mount.get("mountpoint") or ""))
            mp_redacted = bool(raw_mp) and _html_is_redacted_id(raw_mp)
            friendly_mp = catalog.mount_labels[idx] if idx < len(catalog.mount_labels) else (raw_mp or "Mount")
            mp_display_html = (
                f"<strong>{_html_esc(friendly_mp)}</strong>"
                if (mp_redacted or not raw_mp)
                else _html_mono(raw_mp)
            )
            fs_raw = _md_normalize_text(str(mount.get("filesystem_type") or ""))
            fs_html = _html_badge(fs_raw, "mono") if fs_raw else _html_muted("Not available")

            raw_src = _md_normalize_text(str(mount.get("source") or ""))
            raw_src_html = _html_text_cell(mount.get("source"), mono=True)
            linked_drive, linked_part = catalog.resolve_block_source(raw_src)
            if linked_drive:
                sub_parts_src: list[str] = []
                if linked_part is not None:
                    sub_parts_src.append(f"Partition {linked_part}")
                if raw_src and not _html_is_redacted_id(raw_src):
                    sub_parts_src.append(raw_src)
                sub_html = f'<span class="cell-sub">{_html_esc(" · ".join(sub_parts_src))}</span>' if sub_parts_src else ""
                src_display_html = f"<strong>{_html_esc(linked_drive)}</strong>{sub_html}"
            elif raw_src and _html_is_redacted_id(raw_src):
                part_match = _HTML_REDACTED_PARTITION_RE.fullmatch(raw_src)
                if part_match:
                    src_display_html = f'<span>Storage Device</span><span class="cell-sub">Partition {_html_esc(part_match.group(2))}</span>'
                elif raw_src.casefold().startswith("<source-"):
                    src_display_html = _html_muted("Redacted network share")
                else:
                    src_display_html = _html_muted("Redacted source")
            else:
                src_display_html = raw_src_html

            capacity = mount.get("capacity")
            is_virtual = _html_is_virtual_fs(mount)

            if is_virtual:
                fs_key = fs_raw or "unknown"
                virtual_types[fs_key] = virtual_types.get(fs_key, 0) + 1
                if isinstance(capacity, dict):
                    virtual_has_cap = True
                    used_s = _html_bytes_plain(capacity.get("used_bytes"))
                    total_s = _html_bytes_plain(capacity.get("total_bytes"))
                    cap_summary = f"{_html_esc(used_s)} / {_html_esc(total_s)}"
                    usage_html = _html_progress_bar(capacity.get("percent_used"), inline=True)
                else:
                    cap_summary = _html_muted("Virtual")
                    usage_html = _html_muted("—")
                virtual_rows.append([mp_display_html, fs_html, src_display_html, cap_summary, usage_html])
            elif isinstance(capacity, dict):
                volume_rows.append([
                    mp_display_html,
                    fs_html,
                    src_display_html,
                    f'<span class="num-cell"><strong>{_html_bytes_cell(capacity.get("total_bytes"))}</strong></span>',
                    f'<span class="num-cell">{_html_bytes_cell(capacity.get("used_bytes"))}</span>',
                    f'<span class="num-cell">{_html_bytes_cell(capacity.get("available_bytes"))}</span>',
                    _html_progress_bar(capacity.get("percent_used"), inline=True),
                ])
            else:
                extra_storage_rows.append([mp_display_html, fs_html, src_display_html, _html_muted("Capacity not reported")])

            extra_bits: list[str] = []
            for extra_key, extra_val in mount.items():
                if extra_key not in known_mount_keys:
                    extra_bits.append(f"{_md_label(extra_key)}: {_html_value_plain(extra_val, extra_key)}")
            opts_text = _html_format_options(mount.get("options"))
            super_text = _html_format_options(mount.get("super_options"))
            extra_html = (
                f'<span><strong>Extra:</strong> {_html_esc("; ".join(extra_bits))}</span>'
                if extra_bits else ""
            )
            adv_head_parts = [f"<strong>{_html_esc(friendly_mp)}</strong>", fs_html]
            if mp_redacted:
                adv_head_parts.append(f'<span class="mount-detail-meta">Mount ID: {_html_mono(raw_mp)}</span>')
            if linked_drive:
                drive_note = f"{linked_drive} (Partition {linked_part})" if linked_part is not None else linked_drive
                adv_head_parts.append(f'<span class="mount-detail-meta">Drive: {_html_esc(drive_note)}</span>')
            adv_head_parts.extend([
                f'<span class="mount-detail-meta">Source: {raw_src_html}</span>',
                f'<span class="mount-detail-meta">Device: {_html_text_cell(mount.get("device_number"), mono=True)}</span>',
                f'<span class="mount-detail-meta">Root: {_html_text_cell(mount.get("root"), mono=True)}</span>',
            ])
            advanced_items.append(
                '<div class="mount-detail-item filter-item">'
                f'<div class="mount-detail-head">{"".join(adv_head_parts)}</div>'
                '<div class="mount-detail-opts">'
                f'<span><strong>Mount options:</strong> {_html_mono(opts_text)}</span>'
                f'<span><strong>Superblock options:</strong> {_html_mono(super_text)}</span>'
                f"{extra_html}"
                "</div>"
                "</div>"
            )

        if volume_rows:
            badges.append(_html_badge(f"{len(volume_rows)} {'volume' if len(volume_rows) == 1 else 'volumes'}", "mint mono"))
            parts.append(
                '<div class="filter-block">'
                '<div class="section-label">Mounted Storage Volumes</div>'
                f"{_html_data_table(['Volume', 'Filesystem', 'Backing Drive', 'Total', 'Used', 'Available', 'Usage'], volume_rows, raw_cells=True)}"
                "</div>"
            )
        if extra_storage_rows:
            parts.append(
                '<div class="filter-block">'
                '<div class="section-label">Additional Storage &amp; Network Mounts</div>'
                f"{_html_data_table(['Volume', 'Filesystem', 'Source', 'Capacity'], extra_storage_rows, raw_cells=True)}"
                "</div>"
            )
        if virtual_rows:
            badges.append(_html_badge(f"{len(virtual_rows)} virtual", "mono"))
            top_types = sorted(virtual_types.items(), key=lambda pair: (-pair[1], pair[0]))[:6]
            type_summary = ", ".join(f"{name} ({count})" for name, count in top_types)
            if len(virtual_types) > 6:
                type_summary += f", +{len(virtual_types) - 6} other types"
            if virtual_has_cap:
                virt_table = _html_data_table(
                    ["Mount", "Filesystem", "Source", "Used / Total", "Usage"],
                    virtual_rows,
                    raw_cells=True,
                )
            else:
                virt_table = _html_data_table(
                    ["Mount", "Filesystem", "Source"],
                    [row[:3] for row in virtual_rows],
                    raw_cells=True,
                )
            virt_body = f'<p class="note-text">Filesystem types: {_html_esc(type_summary)}</p>{virt_table}'
            parts.append(
                _html_details(
                    "System & Virtual Mounts",
                    virt_body,
                    badge=f"{len(virtual_rows)} mounts",
                    open_default=len(virtual_rows) <= 6,
                )
            )
        if not volume_rows and not extra_storage_rows and not virtual_rows:
            parts.append('<p class="note-text">No mounted filesystems were reported.</p>')
        if advanced_items:
            parts.append(
                _html_details(
                    "Advanced Mount Details & Options",
                    f'<div class="mount-detail-list">{"".join(advanced_items)}</div>',
                    badge=f"{len(advanced_items)} mounts",
                )
            )

    if isinstance(fstab, dict):
        entries = fstab.get("entries")
        if isinstance(entries, list):
            comment_lines: list[str] = []
            blank_lines: list[str] = []
            entry_rows: list[list[str]] = []
            invalid_rows: list[list[str]] = []
            fstab_tech_refs: list[list[str]] = []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                rtype = entry.get("record_type")
                line_text = _md_text(entry.get("line"), missing="?")
                if rtype == "comment":
                    comment_lines.append(line_text)
                elif rtype == "blank":
                    blank_lines.append(line_text)
                elif rtype == "invalid":
                    invalid_rows.append([
                        _html_mono(line_text),
                        _html_badge("Invalid", "warn"),
                        _html_esc(f"{_md_text(entry.get('field_count'), missing='?')} fields"),
                    ])
                else:
                    dump_val = entry.get("dump")
                    pass_val = entry.get("pass")
                    if dump_val is not None or pass_val is not None:
                        dump_pass = _html_mono(f"{dump_val} / {pass_val}")
                    else:
                        dump_pass = _html_muted("Not available")

                    raw_src = _md_normalize_text(str(entry.get("source") or ""))
                    raw_mp = _md_normalize_text(str(entry.get("mountpoint") or ""))
                    raw_fs = _md_normalize_text(str(entry.get("filesystem_type") or ""))

                    src_label, src_part, is_linked_hw = catalog.describe_fstab_source(raw_src)
                    if is_linked_hw:
                        part_sub = f'<span class="cell-sub">Partition {src_part}</span>' if src_part is not None else ""
                        src_html = f"<strong>{_html_esc(src_label)}</strong>{part_sub}"
                    elif raw_src and _html_is_redacted_id(raw_src):
                        part_sub = f'<span class="cell-sub">Partition {src_part}</span>' if src_part is not None else ""
                        src_html = f'{_html_esc(src_label)}{part_sub}'
                    elif raw_src:
                        src_html = _html_mono(raw_src)
                    else:
                        src_html = _html_muted("Not available")

                    mp_label = catalog.describe_fstab_target(raw_mp, raw_fs)
                    if raw_mp and _html_is_redacted_id(raw_mp):
                        mp_html = f"<strong>{_html_esc(mp_label)}</strong>"
                    elif raw_mp:
                        mp_html = _html_mono(raw_mp)
                    else:
                        mp_html = _html_muted("Not available")

                    if (raw_src and _html_is_redacted_id(raw_src)) or (raw_mp and _html_is_redacted_id(raw_mp)):
                        fstab_tech_refs.append([
                            _html_mono(line_text),
                            _html_esc(mp_label),
                            _html_mono(raw_src) if raw_src else _html_muted("Not available"),
                            _html_mono(raw_mp) if raw_mp else _html_muted("Not available"),
                        ])

                    entry_rows.append([
                        _html_mono(line_text),
                        mp_html,
                        _html_text_cell(entry.get("filesystem_type"), mono=True),
                        src_html,
                        _html_mono(_html_format_options(entry.get("options"))),
                        dump_pass,
                    ])

            fstab_parts: list[str] = ['<div class="section-label">Configured /etc/fstab Entries</div>']
            summary_badges: list[str] = [
                _html_badge(f"{len(entry_rows)} active", "mint mono"),
            ]
            if comment_lines:
                summary_badges.append(_html_badge(f"{len(comment_lines)} comments", "mono"))
            if blank_lines:
                summary_badges.append(_html_badge(f"{len(blank_lines)} blank", "mono"))
            if invalid_rows:
                summary_badges.append(_html_badge(f"{len(invalid_rows)} invalid", "warn mono"))
            fstab_parts.append(f'<div class="fstab-badges">{"".join(summary_badges)}</div>')

            if entry_rows:
                fstab_parts.append(
                    _html_data_table(
                        ["Line", "Target", "Type", "Source", "Options", "Dump / Pass"],
                        entry_rows,
                        raw_cells=True,
                        wrap_class="table-wrap fstab-table",
                    )
                )
            elif not invalid_rows:
                fstab_parts.append('<p class="note-text">No active fstab configuration entries were reported.</p>')

            if invalid_rows:
                fstab_parts.append(
                    '<div class="fstab-subblock">'
                    '<div class="section-label">Invalid /etc/fstab Records</div>'
                    f"{_html_data_table(['Line', 'Record Type', 'Details'], invalid_rows, raw_cells=True)}"
                    "</div>"
                )

            if fstab_tech_refs:
                fstab_parts.append(
                    '<div class="fstab-subblock">'
                    + _html_details(
                        "Technical /etc/fstab Identifiers",
                        _html_data_table(["Line", "Target Label", "Source ID", "Mount ID"], fstab_tech_refs, raw_cells=True),
                        badge=f"{len(fstab_tech_refs)} refs",
                    )
                    + "</div>"
                )

            if comment_lines or blank_lines:
                omitted_rows: list[tuple[str, str]] = []
                if comment_lines:
                    omitted_rows.append((f"Comment lines ({len(comment_lines)})", _html_mono(", ".join(comment_lines))))
                if blank_lines:
                    omitted_rows.append((f"Blank lines ({len(blank_lines)})", _html_mono(", ".join(blank_lines))))
                fstab_parts.append(
                    '<div class="fstab-subblock">'
                    + _html_details(
                        "Non-Entry /etc/fstab Records (Comments & Blank Lines)",
                        _html_kv_table(omitted_rows),
                        badge=f"{len(comment_lines) + len(blank_lines)} lines",
                    )
                    + "</div>"
                )
            parts.append(f'<div class="filter-block">{"".join(fstab_parts)}</div>')

    for key, value in data.items():
        if key not in {"mounts", "mountinfo_available", "fstab"}:
            parts.append(
                f'<div class="filter-block"><div class="section-label">{_html_esc(_md_label(key))}</div>'
                f"{_html_render_generic(value)}</div>"
            )

    return "".join(parts) or '<p class="note-text">No filesystem details were available.</p>', badges


def _html_render_network(data: dict[str, Any], catalog: _HtmlHardwareCatalog) -> tuple[str, list[str]]:
    if data.get("available") is False:
        return '<p class="note-text">Network configuration could not be collected.</p>', []

    parts: list[str] = []
    badges: list[str] = []
    iface_tech_refs: list[list[str]] = []

    for key, label in (
        ("addresses_available", "Addresses"),
        ("interface_stats_available", "Stats"),
        ("counters_available", "Counters"),
    ):
        if key in data:
            val = data.get(key)
            badges.append(_html_badge(f"{label}: {'Yes' if val else 'No'}", "mint" if val else "warn"))

    dns = data.get("dns")
    if isinstance(dns, dict):
        ns = [_md_normalize_text(str(item)) for item in (dns.get("nameservers") or []) if _md_normalize_text(str(item))]
        sd = [_md_normalize_text(str(item)) for item in (dns.get("search_domains") or []) if _md_normalize_text(str(item))]
        ns_html = " ".join(_html_mono(item) for item in ns) if ns else _html_muted("None")
        sd_html = " ".join(_html_mono(item) for item in sd) if sd else _html_muted("None")
        parts.append(
            '<div class="filter-block">'
            '<div class="section-label">DNS Resolver</div>'
            f"{_html_kv_table([('Nameservers', ns_html), ('Search Domains', sd_html)])}"
            "</div>"
        )
    elif "dns" in data:
        parts.append(
            '<div class="filter-block">'
            '<div class="section-label">DNS Resolver</div>'
            f"{_html_kv_table([('DNS Configuration', _html_muted('Not available'))])}"
            "</div>"
        )

    interfaces = data.get("interfaces")
    if isinstance(interfaces, list):
        dict_ifaces = [item for item in interfaces if isinstance(item, dict)]
        if not dict_ifaces:
            parts.append('<p class="note-text">No network interfaces were reported.</p>')
        else:
            handled_iface = {
                "interface", "type", "auxiliary", "connection_state", "driver",
                "link_speed_mbps", "addresses", "counters", "rates",
            }
            iface_cards: list[str] = []
            for index, iface in enumerate(dict_ifaces, 1):
                raw_name = _md_normalize_text(str(iface.get("interface") or ""))
                name_redacted = bool(raw_name) and _html_is_redacted_id(raw_name)
                display_name = catalog.iface_labels[index - 1] if index - 1 < len(catalog.iface_labels) else f"Network Interface {index}"
                if name_redacted:
                    iface_tech_refs.append([_html_esc(display_name), _html_mono(raw_name)])

                kind = _md_normalize_text(str(iface.get("type") or ""))
                state = _md_normalize_text(str(iface.get("connection_state") or ""))
                state_low = state.casefold()
                if state_low == "connected":
                    state_badge = _html_badge(state, "status-up")
                elif state_low == "disconnected":
                    state_badge = _html_badge(state, "status-down")
                elif state:
                    state_badge = _html_badge(state)
                else:
                    state_badge = _html_badge("Unknown")

                head_badges = [state_badge]
                if kind:
                    head_badges.insert(0, _html_badge(kind, "blue"))
                if iface.get("auxiliary") is True:
                    head_badges.append(_html_badge("Auxiliary"))

                speed_plain = _html_speed_mbps_plain(iface.get("link_speed_mbps"))
                meta_rows: list[tuple[str, str]] = [
                    ("Driver", _html_text_cell(iface.get("driver"), mono=True)),
                    ("Link Speed", _html_text_cell(speed_plain, mono=True) if speed_plain != "Not available" else _html_muted("Not available")),
                    ("Auxiliary", _html_text_cell(iface.get("auxiliary"))),
                ]
                sub_parts: list[str] = [_html_kv_table(meta_rows)]

                addresses = iface.get("addresses")
                if isinstance(addresses, list):
                    addr_rows = [
                        [
                            _html_badge(_md_text(addr.get("family")), "mono"),
                            _html_text_cell(addr.get("address"), mono=True),
                            _html_text_cell(addr.get("netmask"), mono=True),
                            _html_text_cell(addr.get("broadcast"), mono=True),
                        ]
                        for addr in addresses
                        if isinstance(addr, dict)
                    ]
                    if addr_rows:
                        sub_parts.append(
                            '<div><div class="section-label">Addresses</div>'
                            f"{_html_data_table(['Family', 'Address', 'Netmask', 'Broadcast'], addr_rows, raw_cells=True)}"
                            "</div>"
                        )
                    else:
                        sub_parts.append('<p class="note-text">No addresses reported.</p>')

                counters = iface.get("counters") if isinstance(iface.get("counters"), dict) else None
                rates = iface.get("rates") if isinstance(iface.get("rates"), dict) else None
                if counters is not None or rates is not None:
                    traffic_rows = [
                        [
                            "<strong>Received</strong>",
                            f'<span class="num-cell">{_html_bytes_cell(counters.get("bytes_received") if counters else None)}</span>',
                            f'<span class="num-cell">{_html_rate_cell(rates.get("receive_bytes_per_second") if rates else None)}</span>',
                            f'<span class="num-cell">{_html_esc(_md_int_count(counters.get("packets_received"))) if counters and _is_number(counters.get("packets_received")) else _html_muted("Not available")}</span>',
                            f'<span class="num-cell">{_html_esc(_md_int_count(counters.get("errors_in"))) if counters and _is_number(counters.get("errors_in")) else _html_muted("Not available")}</span>',
                            f'<span class="num-cell">{_html_esc(_md_int_count(counters.get("dropped_in"))) if counters and _is_number(counters.get("dropped_in")) else _html_muted("Not available")}</span>',
                        ],
                        [
                            "<strong>Transmitted</strong>",
                            f'<span class="num-cell">{_html_bytes_cell(counters.get("bytes_transmitted") if counters else None)}</span>',
                            f'<span class="num-cell">{_html_rate_cell(rates.get("transmit_bytes_per_second") if rates else None)}</span>',
                            f'<span class="num-cell">{_html_esc(_md_int_count(counters.get("packets_transmitted"))) if counters and _is_number(counters.get("packets_transmitted")) else _html_muted("Not available")}</span>',
                            f'<span class="num-cell">{_html_esc(_md_int_count(counters.get("errors_out"))) if counters and _is_number(counters.get("errors_out")) else _html_muted("Not available")}</span>',
                            f'<span class="num-cell">{_html_esc(_md_int_count(counters.get("dropped_out"))) if counters and _is_number(counters.get("dropped_out")) else _html_muted("Not available")}</span>',
                        ],
                    ]
                    sub_parts.append(
                        '<div><div class="section-label">Traffic Counters &amp; Rates</div>'
                        f"{_html_data_table(['Direction', 'Total', 'Rate', 'Packets', 'Errors', 'Dropped'], traffic_rows, raw_cells=True)}"
                        "</div>"
                    )

                for key, value in iface.items():
                    if key not in handled_iface:
                        sub_parts.append(
                            f'<div><div class="section-label">{_html_esc(_md_label(key))}</div>'
                            f"{_html_render_generic(value)}</div>"
                        )

                heading_html = (
                    _html_esc(display_name)
                    if (name_redacted or not raw_name)
                    else f'<span class="mono-span">{_html_esc(display_name)}</span>'
                )
                iface_cards.append(
                    '<article class="sub-card filter-group">'
                    '<div class="sub-card-header">'
                    f"<h3>{heading_html}</h3>"
                    f'<div class="card-header-badges">{"".join(head_badges)}</div>'
                    "</div>"
                    f'<div class="sub-card-body">{"".join(sub_parts)}</div>'
                    "</article>"
                )
            parts.append(
                '<div><div class="section-label">Network Interfaces</div>'
                f'<div class="sub-grid">{"".join(iface_cards)}</div></div>'
            )

    def _route_iface_cell(raw_val: Any) -> str:
        raw_str = _md_normalize_text(str(raw_val or ""))
        if not raw_str:
            return _html_muted("Not available")
        label, was_redacted = catalog.resolve_interface(raw_str)
        if was_redacted:
            return f"<strong>{_html_esc(label)}</strong>"
        return _html_mono(label)

    ipv4_routes = data.get("ipv4_routes")
    if "ipv4_routes" in data:
        if ipv4_routes is None:
            v4_body = '<p class="note-text">IPv4 route information is not available.</p>'
        elif isinstance(ipv4_routes, list) and ipv4_routes:
            v4_rows = [
                [
                    _route_iface_cell(r.get("interface")),
                    _html_text_cell(r.get("destination"), mono=True),
                    _html_text_cell(r.get("gateway"), mono=True),
                    _html_text_cell(r.get("netmask"), mono=True),
                    _html_text_cell(r.get("metric"), mono=True),
                ]
                for r in ipv4_routes
                if isinstance(r, dict)
            ]
            v4_body = _html_data_table(
                ["Interface", "Destination", "Gateway", "Netmask", "Metric"],
                v4_rows,
                raw_cells=True,
                wrap_class="table-wrap routes-scroll",
            )
        else:
            v4_body = '<p class="note-text">No IPv4 routes were reported.</p>'
        parts.append(f'<div class="filter-block"><div class="section-label">IPv4 Routes</div>{v4_body}</div>')

    ipv6_routes = data.get("ipv6_routes")
    if "ipv6_routes" in data:
        if ipv6_routes is None:
            v6_body = '<p class="note-text">IPv6 route information is not available.</p>'
        elif isinstance(ipv6_routes, list) and ipv6_routes:
            v6_rows = [
                [
                    _route_iface_cell(r.get("interface")),
                    _html_text_cell(r.get("destination"), mono=True),
                    _html_text_cell(r.get("gateway"), mono=True),
                    _html_text_cell(r.get("metric"), mono=True),
                ]
                for r in ipv6_routes
                if isinstance(r, dict)
            ]
            v6_body = _html_data_table(
                ["Interface", "Destination", "Gateway", "Metric"],
                v6_rows,
                raw_cells=True,
                wrap_class="table-wrap routes-scroll",
            )
        else:
            v6_body = '<p class="note-text">No IPv6 routes were reported.</p>'
        parts.append(f'<div class="filter-block"><div class="section-label">IPv6 Routes</div>{v6_body}</div>')

    if iface_tech_refs:
        parts.append(
            _html_details(
                "Technical Interface Identifiers",
                _html_data_table(["Interface Description", "Reference ID"], iface_tech_refs, raw_cells=True),
                badge=f"{len(iface_tech_refs)} refs",
            )
        )

    handled_net = {
        "interfaces", "addresses_available", "interface_stats_available",
        "counters_available", "ipv4_routes", "ipv6_routes", "dns",
    }
    for key, value in data.items():
        if key not in handled_net:
            parts.append(
                f'<div class="filter-block"><div class="section-label">{_html_esc(_md_label(key))}</div>'
                f"{_html_render_generic(value)}</div>"
            )

    return "".join(parts) or '<p class="note-text">No network details were available.</p>', badges


def _html_render_sensors(data: dict[str, Any], catalog: _HtmlHardwareCatalog) -> tuple[str, list[str]]:
    if data.get("available") is False:
        return '<p class="note-text">Hardware sensor information could not be collected.</p>', []

    badges: list[str] = []
    if "temperatures_available" in data:
        t_avail = data.get("temperatures_available")
        badges.append(_html_badge(f"Temps: {'Available' if t_avail else 'Unavailable'}", "mint" if t_avail else "warn"))
    if "fan_speeds_available" in data:
        f_avail = data.get("fan_speeds_available")
        badges.append(_html_badge(f"Fans: {'Available' if f_avail else 'Unavailable'}", "mint" if f_avail else "warn"))

    groups = (
        ("temperatures", "Temperatures", "Temperature", "value_c", lambda v: _html_temp_cell(v)),
        ("drive_temperatures", "Drive Temperatures", "Temperature", "value_c", lambda v: _html_temp_cell(v)),
        ("fan_speeds", "Fan Speeds", "Speed", "value_rpm", lambda v: _html_mono(_html_rpm_plain(v)) if _is_number(v) else _html_muted("Not available")),
        ("power_readings", "Power Readings", "Power", "value_w", lambda v: _html_mono(_html_watts_plain(v)) if _is_number(v) else _html_muted("Not available")),
        ("clock_readings", "Clock Readings", "Frequency", "value_mhz", lambda v: _html_mono(_html_freq_plain(v)) if _is_number(v) else _html_muted("Not available")),
    )

    sensor_tech_refs: dict[str, str] = {}

    def _sensor_device_cell(raw_val: Any) -> str:
        raw_str = _md_normalize_text(str(raw_val or ""))
        if not raw_str:
            return _html_muted("Not available")
        label, was_redacted = catalog.resolve_sensor_device(raw_str)
        if was_redacted:
            sensor_tech_refs.setdefault(raw_str, label)
            return f"<strong>{_html_esc(label)}</strong>"
        return _html_mono(label)

    group_cards: list[str] = []
    empty_groups: list[str] = []
    for key, heading, metric_col, value_key, cell_formatter in groups:
        entries = data.get(key)
        if not isinstance(entries, list):
            continue
        rows = [
            [
                _sensor_device_cell(item.get("device")),
                _html_text_cell(item.get("name")),
                cell_formatter(item.get(value_key)),
            ]
            for item in entries
            if isinstance(item, dict)
        ]
        if rows:
            group_cards.append(
                '<article class="sub-card filter-group">'
                '<div class="sub-card-header">'
                f"<h3>{_html_esc(heading)}</h3>"
                f'{_html_badge(str(len(rows)), "mono")}'
                "</div>"
                '<div class="sub-card-body">'
                f"{_html_data_table(['Device', 'Sensor', metric_col], rows, raw_cells=True)}"
                "</div>"
                "</article>"
            )
        else:
            empty_groups.append(heading.casefold())

    parts: list[str] = []
    if group_cards:
        parts.append(f'<div class="sensor-grid">{"".join(group_cards)}</div>')
    if empty_groups:
        parts.append(f'<p class="note-text">No readings were reported for: {_html_esc(", ".join(empty_groups))}.</p>')
    if sensor_tech_refs:
        ref_rows = [[_html_esc(label), _html_mono(raw_id)] for raw_id, label in sensor_tech_refs.items()]
        parts.append(
            _html_details(
                "Technical Sensor Device Identifiers",
                _html_data_table(["Hardware Description", "Reference ID"], ref_rows, raw_cells=True),
                badge=f"{len(ref_rows)} refs",
            )
        )

    handled = {
        "temperatures_available", "fan_speeds_available",
        "temperatures", "drive_temperatures", "fan_speeds", "power_readings", "clock_readings",
    }
    for key, value in data.items():
        if key not in handled:
            parts.append(
                f'<div class="filter-block"><div class="section-label">{_html_esc(_md_label(key))}</div>'
                f"{_html_render_generic(value)}</div>"
            )

    return "".join(parts) or '<p class="note-text">No hardware sensor details were available.</p>', badges


def _html_render_section(name: str, data: Any, catalog: _HtmlHardwareCatalog) -> tuple[str, list[str], str]:
    key = name.casefold()
    icon = _HTML_ICONS.get(key, _HTML_ICONS["generic"])
    if isinstance(data, dict):
        if key == "os":
            body, badges = _html_render_os(data)
            return body, badges, icon
        if key == "desktop":
            body, badges = _html_render_desktop(data)
            return body, badges, icon
        if key == "cpu":
            body, badges = _html_render_cpu(data)
            return body, badges, icon
        if key == "memory":
            body, badges = _html_render_memory(data)
            return body, badges, icon
        if key == "graphics":
            body, badges = _html_render_graphics(data, catalog)
            return body, badges, icon
        if key == "storage":
            body, badges = _html_render_storage(data, catalog)
            return body, badges, icon
        if key == "filesystems":
            body, badges = _html_render_filesystems(data, catalog)
            return body, badges, icon
        if key == "network":
            body, badges = _html_render_network(data, catalog)
            return body, badges, icon
        if key == "sensors":
            body, badges = _html_render_sensors(data, catalog)
            return body, badges, icon
    return _html_render_generic(data), [], icon


def _html_render_errors_card(errors: list[Any]) -> str:
    if not errors:
        return (
            '<section class="card spec-card full-width">'
            '<div class="card-header">'
            f'<div class="card-header-title">{_HTML_ICONS["errors_ok"]}<h2>Collection Errors</h2></div>'
            f'<div class="card-header-badges">{_html_badge("0 errors", "mint mono")}</div>'
            "</div>"
            '<div class="card-body"><p class="note-text">No collection errors were reported.</p></div>'
            "</section>"
        )

    count_label = f"{len(errors)} {'error' if len(errors) == 1 else 'errors'}"
    if all(isinstance(item, dict) and set(item.keys()) <= {"section", "message"} for item in errors):
        rows = [
            [
                _html_badge(
                    _html_section_title(item["section"])
                    if isinstance(item.get("section"), str) and item["section"].strip()
                    else "General",
                    "crit",
                ),
                _html_text_cell(item.get("message")),
            ]
            for item in errors
        ]
        body_html = _html_data_table(["Section", "Message"], rows, raw_cells=True)
    else:
        body_html = _html_render_generic(errors)

    return (
        '<section class="card spec-card full-width card-error">'
        '<div class="card-header">'
        f'<div class="card-header-title">{_HTML_ICONS["errors_warn"]}<h2>Collection Errors</h2></div>'
        f'<div class="card-header-badges">{_html_badge(count_label, "crit mono")}</div>'
        "</div>"
        f'<div class="card-body">{body_html}</div>'
        "</section>"
    )


def render_html(snapshot: dict[str, Any]) -> str:
    """Render a standalone offline HTML diagnostic dashboard with safely escaped snapshot data."""
    _validate_snapshot(snapshot)

    sections = snapshot["sections"]
    selected = ", ".join(_html_section_title(item) for item in snapshot["selected_sections"]) or "None"
    privacy_enabled = bool(snapshot["privacy"])
    privacy_status = "Enabled" if privacy_enabled else "Disabled"
    privacy_badge = _html_badge(f"Privacy: {privacy_status}", "mint" if privacy_enabled else "warn")
    privacy_cls = "privacy-on" if privacy_enabled else "privacy-off"

    header_badges: list[str] = []
    redaction_token = re.compile(r"<[a-z]+(?:-[a-z0-9]+)*>", re.IGNORECASE)
    os_section = sections.get("os")
    if isinstance(os_section, dict) and os_section.get("available") is not False:
        distro = _html_os_distro_label(os_section)
        if not distro:
            distro = " ".join(
                p for p in (
                    _md_normalize_text(str(os_section.get("kernel_name") or "")),
                    _md_normalize_text(str(os_section.get("kernel_release") or "")),
                )
                if p
            )
        if distro and not redaction_token.search(distro):
            header_badges.append(_html_badge(distro, "mint"))
    desktop_section = sections.get("desktop")
    if isinstance(desktop_section, dict) and desktop_section.get("available") is not False:
        de = _md_normalize_text(str(desktop_section.get("desktop_environment") or ""))
        if de and not redaction_token.search(de):
            header_badges.append(_html_badge(de, "blue"))
    header_badges.append(privacy_badge)
    header_badges.append(_html_badge(f"TaskPup v{snapshot['app_version']}", "purple mono"))
    header_badges.append(_html_badge(snapshot["timestamp"], "mono"))

    catalog = _HtmlHardwareCatalog(sections)
    summary_html = _html_build_summary_cards(sections, catalog)

    section_entries: list[tuple[str, str, list[str], str, bool]] = []
    for name, data in sections.items():
        body_html, card_badges, icon = _html_render_section(name, data, catalog)
        is_half = name.casefold() in _HTML_HALF_WIDTH_SECTIONS and isinstance(data, dict)
        section_entries.append((_html_section_title(name), body_html, card_badges, icon, is_half))

    # Avoid leaving a lone half-width card next to an empty column.
    section_cards: list[str] = []
    idx = 0
    while idx < len(section_entries):
        title, body_html, card_badges, icon, is_half = section_entries[idx]
        if is_half:
            run_end = idx
            while run_end < len(section_entries) and section_entries[run_end][4]:
                run_end += 1
            run_len = run_end - idx
            for pos in range(idx, run_end):
                r_title, r_body, r_badges, r_icon, _ = section_entries[pos]
                full_cls = " full-width" if (pos == run_end - 1 and run_len % 2 == 1) else ""
                badges_html = f'<div class="card-header-badges">{"".join(r_badges)}</div>' if r_badges else ""
                section_cards.append(
                    f'<section class="card spec-card{full_cls}">'
                    '<div class="card-header">'
                    f'<div class="card-header-title">{r_icon}<h2>{_html_esc(r_title)}</h2></div>'
                    f"{badges_html}"
                    "</div>"
                    f'<div class="card-body">{r_body}</div>'
                    "</section>"
                )
            idx = run_end
        else:
            badges_html = f'<div class="card-header-badges">{"".join(card_badges)}</div>' if card_badges else ""
            section_cards.append(
                '<section class="card spec-card full-width">'
                '<div class="card-header">'
                f'<div class="card-header-title">{icon}<h2>{_html_esc(title)}</h2></div>'
                f"{badges_html}"
                "</div>"
                f'<div class="card-body">{body_html}</div>'
                "</section>"
            )
            idx += 1

    if not section_cards:
        section_cards.append(
            '<section class="card spec-card full-width">'
            '<div class="card-header">'
            f'<div class="card-header-title">{_HTML_ICONS["generic"]}<h2>Diagnostic Sections</h2></div>'
            "</div>"
            '<div class="card-body"><p class="note-text">No diagnostic sections were available.</p></div>'
            "</section>"
        )

    errors_card = _html_render_errors_card(snapshot["errors"])

    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '  <meta charset="utf-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "  <title>TaskPup System Diagnostic Report</title>\n"
        f"  <style>\n{_HTML_STYLESHEET}  </style>\n"
        "</head>\n"
        "<body>\n"
        '<div class="container">\n'
        '  <header class="report-header">\n'
        '    <div class="header-top">\n'
        '      <div class="header-left">\n'
        f'        <div class="header-logo">{_HTML_ICONS["logo"]}</div>\n'
        '        <div class="header-title">\n'
        '          <h1>TaskPup <span class="mint-accent">System Diagnostic Report</span></h1>\n'
        '          <p class="header-subtitle">Hardware &amp; System Diagnostics</p>\n'
        "        </div>\n"
        "      </div>\n"
        f'      <div class="header-badges">{"".join(header_badges)}</div>\n'
        "    </div>\n"
        '    <div class="header-meta-strip">\n'
        f'      <div class="privacy-notice {privacy_cls}">\n'
        f'        {_HTML_ICONS["shield"]}\n'
        f'        <div><strong>Privacy protection: {privacy_status}.</strong> '
        "Automated redaction may not catch every sensitive value. Review this report before sharing it. "
        "Disable browser headers and footers when printing a PDF if they expose local paths.</div>\n"
        "      </div>\n"
        '      <div class="header-meta-line">\n'
        f'        <span><strong>Generated (UTC):</strong> {_html_esc(snapshot["timestamp"])}</span>\n'
        f'        <span><strong>TaskPup version:</strong> {_html_esc(snapshot["app_version"])}</span>\n'
        f'        <span><strong>Schema version:</strong> {_html_esc(snapshot["schema_version"])}</span>\n'
        f'        <span><strong>Selected sections:</strong> {_html_esc(selected)}</span>\n'
        "      </div>\n"
        "    </div>\n"
        "  </header>\n"
        '  <div class="toolbar no-print" role="region" aria-label="Report controls">\n'
        '    <div class="toolbar-left">\n'
        '      <div class="search-box">\n'
        f'        <span class="search-icon">{_HTML_ICONS["search"]}</span>\n'
        '        <input type="search" id="filterInput" class="search-input" '
        'placeholder="Quick filter sections, devices, mounts, sensors..." '
        'aria-label="Filter diagnostic report" autocomplete="off">\n'
        "      </div>\n"
        '      <button type="button" id="clearFilterBtn" class="btn btn-subtle" hidden>Clear</button>\n'
        '      <span id="filterStatus" class="filter-status" aria-live="polite"></span>\n'
        "    </div>\n"
        '    <div class="toolbar-right">\n'
        '      <button type="button" id="toggleDetailsBtn" class="btn">Expand All Details</button>\n'
        f'      <button type="button" id="printBtn" class="btn">{_HTML_ICONS["print"]} Print / Save as PDF</button>\n'
        "    </div>\n"
        "  </div>\n"
        f"  {summary_html}\n"
        '  <div id="filterEmptyState" class="empty-state" hidden>'
        "No diagnostic sections or entries matched your filter.</div>\n"
        '  <main class="main-grid">\n'
        f"    {''.join(section_cards)}\n"
        f"    {errors_card}\n"
        "  </main>\n"
        '  <footer class="report-footer">\n'
        f'    Generated by <strong>TaskPup</strong> v{_html_esc(snapshot["app_version"])} &bull; '
        f'Schema v{_html_esc(snapshot["schema_version"])} &bull; '
        f'{_html_esc(snapshot["timestamp"])} &bull; Sit. Stay. SIGKILL.\n'
        "  </footer>\n"
        "</div>\n"
        f"<script>\n{_HTML_SCRIPT}</script>\n"
        "</body>\n"
        "</html>\n"
    )


def _make_zip(snapshot: dict[str, Any]) -> bytes:
    reports = (
        ("report.md", render_markdown(snapshot)),
        ("report.json", render_json(snapshot)),
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

    ``format`` is one of ``md``, ``json``, ``jsonl``, ``html`` or ``zip``. By default an
    existing destination is preserved. Callers should set ``overwrite=True``
    only after the user has explicitly approved replacement in the UI.
    """
    _validate_snapshot(snapshot)
    if not isinstance(overwrite, bool):
        raise TypeError("overwrite must be a bool")
    if format == "md":
        payload = render_markdown(snapshot).encode("utf-8")
    elif format == "json":
        payload = render_json(snapshot).encode("utf-8")
    elif format == "jsonl":
        payload = render_jsonl(snapshot).encode("utf-8")
    elif format == "html":
        payload = render_html(snapshot).encode("utf-8")
    elif format == "zip":
        payload = _make_zip(snapshot)
    else:
        raise ValueError("format must be one of: md, json, jsonl, html, zip")
    _atomic_write(Path(destination), payload, overwrite=overwrite)

