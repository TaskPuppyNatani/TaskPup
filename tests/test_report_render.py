import json
import stat
import zipfile

import pytest

from taskpup import report_render
from taskpup.report_render import write_report


def snapshot() -> dict[str, object]:
    return {
        "schema_version": "1",
        "timestamp": "2026-11-21T22:15:00Z",
        "app_version": "0.1.0",
        "selected_sections": ["Operating System", "Mounts"],
        "privacy": True,
        "sections": {
            "Operating System": {
                "distribution": "Test Linux",
                "untrusted": "<script>alert('x')</script> ~~strike~~ `code` | [link](javascript:bad)",
                "details": {"kernel": "6.1", "flags": ["a", "b"]},
            },
            "Mounts": [{"mountpoint": "/mnt/data", "options": "rw,nosuid"}],
        },
        "errors": [{"section": "Graphics", "message": "telemetry unavailable"}],
    }


def test_markdown_export_escapes_untrusted_text_and_writes_private_file(tmp_path) -> None:
    destination = tmp_path / "diagnostic.md"

    write_report(snapshot(), destination, "md")

    rendered = destination.read_text(encoding="utf-8")
    assert "# TaskPup System Diagnostic Report" in rendered
    assert "## Operating System" in rendered
    assert "&lt;script&gt;" in rendered
    assert "\\~\\~strike\\~\\~" in rendered
    assert "\\`code\\`" in rendered
    assert "\\|" in rendered
    assert "| Field | Value |" in rendered
    assert "| # | Mountpoint | Options |" in rendered
    assert "telemetry unavailable" in rendered
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert {path.name for path in tmp_path.iterdir()} == {"diagnostic.md"}


def test_jsonl_export_has_independently_parseable_schema_versioned_records(tmp_path) -> None:
    destination = tmp_path / "diagnostic.jsonl"

    write_report(snapshot(), destination, "jsonl")

    records = [json.loads(line) for line in destination.read_text(encoding="utf-8").splitlines()]
    assert [record["record_type"] for record in records] == ["metadata", "section", "section", "error"]
    assert all(record["schema_version"] == "1" for record in records)
    assert all(record["timestamp"] == "2026-11-21T22:15:00Z" for record in records)
    assert records[0]["data"] == {
        "app_version": "0.1.0",
        "selected_sections": ["Operating System", "Mounts"],
        "privacy": True,
    }
    assert records[1]["data"]["distribution"] == "Test Linux"
    assert records[-1]["section"] == "Graphics"


def test_byte_formatting_uses_binary_units_and_handles_boundaries() -> None:
    assert report_render.format_bytes(0) == "0 B"
    assert report_render.format_bytes(1023) == "1,023 B"
    assert report_render.format_bytes(1024) == "1.00 KiB"
    assert report_render.format_bytes(7_733_346_304) == "7.20 GiB"
    assert report_render.format_bytes(128_035_676_160) == "119.24 GiB"
    assert report_render.format_bytes(2**50) == "1.00 PiB"


def test_html_export_is_standalone_and_escapes_system_text(tmp_path) -> None:
    destination = tmp_path / "diagnostic.html"

    write_report(snapshot(), destination, "html")

    rendered = destination.read_text(encoding="utf-8")
    assert rendered.startswith("<!doctype html>")
    assert "<style>" in rendered
    assert "<table>" in rendered
    assert '<th scope="col">Mountpoint</th>' in rendered
    assert "</script>alert" not in rendered
    assert "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;" in rendered
    assert "https://" not in rendered
    assert "Automated redaction may not catch every sensitive value" in rendered


def test_nested_capacity_and_network_bytes_are_readable_but_jsonl_stays_exact() -> None:
    data = snapshot()
    data["sections"] = {
        "memory": {"ram": {"total_bytes": 7_733_346_304},
                   "swap": {"total_bytes": 8_589_930_496},
                   "kernel_memory_details": {"Cached": 512_000}},
        "graphics": {"devices": [{"memory_pools": {
            "driver_reported_vram": {"used_bytes": 20_100_000_000, "total_bytes": 25_769_803_776},
            "driver_reported_gtt": {"used_bytes": 1024, "total_bytes": 2048},
        }}]},
        "storage": {"devices": [{"capacity_bytes": 128_035_676_160}],
                    "filesystems": [{"capacity": {"total_bytes": 128_035_676_160,
                                                      "used_bytes": 64 * 1024**3,
                                                      "available_bytes": 55 * 1024**3,
                                                      "percent_used": 50}}]},
        "network": {"interfaces": [{"counters": {"bytes_received": 7_733_346_304,
                                                     "bytes_transmitted": 1024,
                                                     "packets_received": 1500},
                                      "rates": {"receive_bytes_per_second": 2048}}]},
    }
    markdown = report_render.render_markdown(data)
    html = report_render.render_html(data)
    assert "7.20 GiB" in markdown and "119.24 GiB" in markdown
    assert "8.00 GiB" in markdown
    assert "| VRAM | 18.72 GiB | 24.00 GiB |" in markdown
    assert "| GTT | 1.00 KiB | 2.00 KiB |" in markdown
    assert "| Received | 7.20 GiB | 2.00 KiB/s | 1,500 | Not available | Not available |" in markdown
    assert "Used Bytes" not in markdown and "Total Bytes" not in markdown
    assert "Bytes Received" not in markdown and "Receive Bytes Per Second" not in markdown
    assert "7.20 GiB" in html and "119.24 GiB" in html
    assert "Driver Reported VRAM: Used Bytes: 18.72 GiB" in html
    assert "Bytes Received: 7.20 GiB" in html and "Receive Bytes Per Second: 2.00 KiB/s" in html
    assert "Packets Received: 1500" in html
    assert '"used_bytes": 20100000000' not in markdown + html
    records = [json.loads(line) for line in report_render.render_jsonl(data).splitlines()]
    graphics = next(record["data"] for record in records if record.get("section") == "graphics")
    assert graphics["devices"][0]["memory_pools"]["driver_reported_vram"]["used_bytes"] == 20_100_000_000


def test_internal_section_names_are_displayed_as_readable_labels() -> None:
    internal_labels = snapshot()
    internal_labels["selected_sections"] = ["cpu_info"]  # type: ignore[assignment]
    internal_labels["sections"] = {"cpu_info": {"model_name": "Example CPU"}}  # type: ignore[assignment]

    markdown = report_render.render_markdown(internal_labels)
    html = report_render.render_html(internal_labels)

    assert "## CPU Info" in markdown
    assert "| Model Name | Example CPU |" in markdown
    assert "<h2>CPU Info</h2>" in html
    assert "<td>Model Name</td><td>Example CPU</td>" in html


def test_zip_contains_exactly_three_reports_rendered_from_same_snapshot(tmp_path) -> None:
    destination = tmp_path / "diagnostic.zip"

    write_report(snapshot(), destination, "zip")

    with zipfile.ZipFile(destination) as archive:
        assert archive.namelist() == ["report.md", "report.jsonl", "report.html"]
        assert archive.testzip() is None
        markdown = archive.read("report.md").decode("utf-8")
        records = [
            json.loads(line)
            for line in archive.read("report.jsonl").decode("utf-8").splitlines()
        ]
        html = archive.read("report.html").decode("utf-8")
    assert "2026-11-21T22:15:00Z" in markdown
    assert all(record["timestamp"] == "2026-11-21T22:15:00Z" for record in records)
    assert "2026-11-21T22:15:00Z" in html
    assert "Test Linux" in markdown and "Test Linux" in html
    assert any(record["data"].get("distribution") == "Test Linux" for record in records if isinstance(record["data"], dict))
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_existing_destination_is_preserved_unless_overwrite_is_requested(tmp_path) -> None:
    destination = tmp_path / "diagnostic.md"
    destination.write_text("existing", encoding="utf-8")

    with pytest.raises(FileExistsError):
        write_report(snapshot(), destination, "md")
    assert destination.read_text(encoding="utf-8") == "existing"

    write_report(snapshot(), destination, "md", overwrite=True)
    assert "TaskPup System Diagnostic Report" in destination.read_text(encoding="utf-8")
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_symbolic_link_destination_is_refused_without_touching_target(tmp_path) -> None:
    target = tmp_path / "important.txt"
    target.write_text("keep this", encoding="utf-8")
    destination = tmp_path / "diagnostic.md"
    destination.symlink_to(target)

    with pytest.raises(OSError, match="symbolic-link"):
        write_report(snapshot(), destination, "md", overwrite=True)

    assert destination.is_symlink()
    assert target.read_text(encoding="utf-8") == "keep this"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["diagnostic.md", "important.txt"]


def test_failed_temporary_write_is_cleaned_up(tmp_path, monkeypatch) -> None:
    destination = tmp_path / "diagnostic.md"

    def fail_fsync(_: int) -> None:
        raise OSError("simulated disk error")

    monkeypatch.setattr(report_render.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="simulated disk error"):
        write_report(snapshot(), destination, "md")

    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


def test_invalid_snapshot_and_format_fail_before_creating_files(tmp_path) -> None:
    destination = tmp_path / "diagnostic.jsonl"
    invalid = snapshot()
    invalid["sections"] = {"bad": float("nan")}  # type: ignore[assignment]

    with pytest.raises(ValueError, match="non-finite"):
        write_report(invalid, destination, "jsonl")
    with pytest.raises(ValueError, match="format"):
        write_report(snapshot(), destination, "pdf")
    assert list(tmp_path.iterdir()) == []


def rich_diagnostic_snapshot() -> dict[str, object]:
    return {
        "schema_version": "1",
        "timestamp": "2026-11-21T21:47:25Z",
        "app_version": "0.1.0",
        "selected_sections": [
            "os", "desktop", "cpu", "memory", "graphics", "storage", "filesystems", "network", "sensors",
        ],
        "privacy": True,
        "sections": {
            "os": {
                "distribution": "Linux Mint",
                "distribution_version": "22.3",
                "os_architecture": "x86_64",
                "kernel_name": "Linux",
                "kernel_release": "7.0.0-43-generic",
                "kernel_version": "#43~24.04.1-Ubuntu SMP\r\n",
                "hostname": "<host-1>",
                "uptime_seconds": 52920.4,
                "boot_mode": "UEFI",
                "identification": {
                    "system_vendor": "HP\n",
                    "product_name": "HP Pavilion 17-ar0xx  \r\n",
                    "product_version": "   \n",
                    "bios_vendor": "AMI\n",
                    "bios_version": "F.29\n",
                    "bios_date": "07/01/2020\n",
                },
                "kernel_command_line": [
                    {"parameter": "BOOT_IMAGE", "value": "/boot/vmlinuz-7.0.0-43-generic"},
                    {"parameter": "root", "value": "UUID=<uuid-1>"},
                    {"parameter": "rootflags", "value": [{"name": "subvol", "value": "@"}, {"name": "compress", "value": "zstd"}]},
                    {"parameter": "ro", "value": "present"},
                    {"parameter": "quiet", "value": "present"},
                ],
            },
            "desktop": {
                "desktop_environment": "XFCE",
                "session": "xfce",
                "session_type": "x11",
                "window_manager": None,
                "screens": [{"width": 1920, "height": 1080, "scale": 1.0}, {"width": 2560, "height": 1440, "scale": 1.25}],
                "qt_version": "6.12.0",
                "pyside_version": "6.12.0",
            },
            "cpu": {
                "model": "AMD Ryzen 7 9800X3D  \r\n",
                "architecture": "x86_64",
                "physical_cores": 8,
                "logical_processors": 16,
                "current_frequency_mhz": 4725.456,
                "temperature_c": 62.345,
                "capabilities": [f"flag_{i}" for i in range(12)],
            },
            "memory": {
                "ram": {
                    "total_bytes": 7_733_346_304,
                    "available_bytes": 2_355_000_000,
                    "used_bytes": 5_378_346_304,
                    "percent_used": 69.53545082054042,
                    "cached_bytes": 2_018_634_629,
                    "buffers_bytes": 47_311_872,
                },
                "swap": {
                    "total_bytes": 8_589_934_592,
                    "available_bytes": 7_743_400_000,
                    "used_bytes": 846_534_592,
                    "percent_used": 9.85496,
                },
                "kernel_memory_details": {
                    "Buffers": 47_311_872,
                    "Cached": 1_621_352_448,
                    "SwapCached": 157_967_360,
                    "HugePages_Total": 0,
                    "Hugepagesize": 2_097_152,
                },
                "configuration": {"swappiness": 60, "overcommit_memory": 0, "overcommit_ratio": 50},
            },
            "graphics": {
                "devices": [
                    {
                        "identity": "<hardware-1>",
                        "model": "AMD Radeon RX 7900 XTX",
                        "pci_vendor_id": "0x1002\n",
                        "pci_device_id": "0x744c\n",
                        "driver": "amdgpu",
                        "utilization_percent": 12.345,
                        "memory_pools": {
                            "driver_reported_vram": {
                                "used_bytes": 4 * 1024**3,
                                "total_bytes": 24 * 1024**3,
                                "classification": "driver-reported; dedicated/shared semantics are not assumed",
                            },
                            "driver_reported_gtt": {
                                "used_bytes": 512 * 1024**2,
                                "total_bytes": 16 * 1024**3,
                                "classification": "driver-reported; dedicated/shared semantics are not assumed",
                            },
                        },
                        "sensors": {"GPU temperature": 54.67, "Core clock": 2450.25, "Power": 85.44, "Fan": 1200.4},
                        "telemetry_capabilities": ["Core clock", "GPU temperature", "utilization"],
                    },
                    {
                        "identity": "<hardware-2>",
                        "model": "Wani [Radeon R5/R6/R7 Graphics]",
                        "pci_vendor_id": "0x1002\r\n",
                        "pci_device_id": "0x9874\r\n",
                        "driver": "amdgpu",
                        "utilization_percent": None,
                        "memory_pools": {
                            "driver_reported_vram": {
                                "used_bytes": 393_486_336,
                                "total_bytes": 536_870_912,
                                "classification": "driver-reported; dedicated/shared semantics are not assumed",
                            },
                        },
                        "sensors": {},
                        "telemetry_capabilities": [],
                    },
                ],
            },
            "storage": {
                "devices": [
                    {
                        "device_path": "<device-1>",
                        "device_name": "<device-1>",
                        "model": "Samsung 990 PRO\n",
                        "storage_type": "NVMe SSD",
                        "capacity_bytes": 2 * 1024**4,
                        "temperature_c": 41.25,
                        "temperature_supported": True,
                    },
                    {
                        "device_path": "<device-2>",
                        "device_name": "<device-2>",
                        "model": "ATA SanDisk SDSSDP12",
                        "storage_type": "SATA SSD",
                        "capacity_bytes": 128_035_676_160,
                        "temperature_c": None,
                        "temperature_supported": False,
                    },
                    {
                        "device_path": "<device-3>-partition-0",
                        "device_name": "<device-3>-partition-0",
                        "model": "hp DVDRW DA8AESH",
                        "storage_type": "Optical drive",
                        "capacity_bytes": 1024**3,
                        "temperature_c": None,
                        "temperature_supported": False,
                    },
                ],
                "partitions": [
                    {"device_path": "<device-1>-partition-1", "parent_device": "<device-1>", "partition_number": 1, "capacity_bytes": 512 * 1024**2},
                    {"device_path": "<device-1>-partition-2", "parent_device": "<device-1>", "partition_number": 2, "capacity_bytes": 1024**4},
                ],
            },
            "filesystems": {
                "mountinfo_available": True,
                "mounts": [
                    {
                        "device_number": "8:3",
                        "root": "<mountroot-1>",
                        "mountpoint": "<mount-1>",
                        "filesystem_type": "ext4",
                        "source": "<device-1>-partition-2",
                        "options": [{"name": "rw"}, {"name": "relatime"}],
                        "super_options": [{"name": "rw"}, {"name": "errors", "value": "remount-ro"}],
                        "capacity": {
                            "total_bytes": 47_233_900_544,
                            "used_bytes": 23_450_517_504,
                            "available_bytes": 21_356_724_224,
                            "percent_used": 49.6476,
                        },
                    },
                    {
                        "device_number": "0:25",
                        "root": "<mountroot-1>",
                        "mountpoint": "<mount-2>",
                        "filesystem_type": "tmpfs",
                        "source": "tmpfs",
                        "options": [{"name": "rw"}, {"name": "nosuid"}],
                        "super_options": [{"name": "rw"}, {"name": "gid", "value": "<user>"}],
                        "capacity": None,
                    },
                ],
                "fstab": {
                    "available": True,
                    "entries": [
                        {"line": 1, "record_type": "comment"},
                        {"line": 2, "record_type": "comment"},
                        {"line": 3, "record_type": "blank"},
                        {
                            "line": 9,
                            "record_type": "entry",
                            "source": "<uuid-1>",
                            "mountpoint": "<mount-1>",
                            "filesystem_type": "ext4",
                            "options": [{"name": "errors", "value": "remount-ro"}],
                            "dump": 0,
                            "pass": 1,
                        },
                        {"line": 12, "record_type": "invalid", "field_count": 3},
                    ],
                },
            },
            "network": {
                "addresses_available": True,
                "interface_stats_available": True,
                "counters_available": True,
                "dns": {"nameservers": ["<ip-32>"], "search_domains": ["<host-2>"]},
                "interfaces": [
                    {
                        "interface": "<interface-1>",
                        "type": "Ethernet",
                        "auxiliary": False,
                        "connection_state": "Connected",
                        "driver": "r8169",
                        "link_speed_mbps": 1000,
                        "addresses": [
                            {"family": "IPv4", "address": "<ip-1>", "netmask": "<ip-2>", "broadcast": "<ip-3>"},
                            {"family": "MAC", "address": "<mac-1>", "netmask": None, "broadcast": "ff:ff:ff:ff:ff:ff"},
                        ],
                        "counters": {
                            "bytes_received": 1_352_914_698,
                            "bytes_transmitted": 256_618_659,
                            "packets_received": 1211417,
                            "packets_transmitted": 398399,
                            "errors_in": 0,
                            "errors_out": 0,
                            "dropped_in": 50008,
                            "dropped_out": 0,
                        },
                        "rates": {"receive_bytes_per_second": 4096, "transmit_bytes_per_second": 1024},
                    },
                    {
                        "interface": "<interface-2>",
                        "type": "Loopback",
                        "auxiliary": True,
                        "connection_state": "Disconnected",
                        "driver": None,
                        "link_speed_mbps": 0,
                        "addresses": [],
                        "counters": None,
                        "rates": None,
                    },
                ],
                "ipv4_routes": [{"interface": "<interface-1>", "destination": "<ip-4>", "gateway": "<ip-5>", "netmask": "<ip-2>", "metric": 100}],
                "ipv6_routes": [{"interface": "<interface-1>", "destination": "<ip-6>", "gateway": "<ip-7>", "metric": 256}],
            },
            "sensors": {
                "temperatures_available": True,
                "fan_speeds_available": True,
                "temperatures": [{"device": "k10temp", "name": "Tctl", "value_c": 62.345}],
                "drive_temperatures": [{"device": "<device-1>", "name": "Drive temperature", "value_c": 41.25}],
                "fan_speeds": [{"device": "<hardware-1>", "name": "Fan", "value_rpm": 1200.4}],
                "power_readings": [{"device": "<hardware-1>", "name": "Power", "value_w": 85.44}],
                "clock_readings": [{"device": "<hardware-1>", "name": "Core clock", "value_mhz": 2450.25}],
            },
        },
        "errors": [],
    }


def test_markdown_overview_structured_sections_numeric_precision_and_no_data_loss() -> None:
    data = rich_diagnostic_snapshot()
    md = report_render.render_markdown(data)

    # Header metadata and privacy warning preserved
    assert "# TaskPup System Diagnostic Report" in md
    assert "> **Privacy protection: Enabled.**" in md
    assert "- **Generated (UTC):** 2026-11-21T21:47:25Z" in md
    assert "- **TaskPup version:** 0.1.0" in md
    assert "- **Schema version:** 1" in md
    assert "- **Selected sections:** Operating System, Desktop Environment, CPU," in md

    # At a glance overview
    assert "## At a glance" in md
    assert "| Operating system | Linux Mint 22.3 (XFCE, X11) |" in md
    assert "| CPU | AMD Ryzen 7 9800X3D · 8 cores / 16 threads |" in md
    assert "| RAM | 5.01 GiB used / 7.20 GiB total (69.5%) |" in md
    assert "| Swap | 807.32 MiB used / 8.00 GiB total (9.9%) |" in md
    assert "| Graphics | AMD Radeon RX 7900 XTX; Wani \\[Radeon R5/R6/R7 Graphics\\] |" in md
    assert "| Primary storage | Samsung 990 PRO · 2.00 TiB; ATA SanDisk SDSSDP12 · 119.24 GiB |" in md
    assert "| Network | 2 interfaces (1 connected) |" in md

    # Readable precision and no stray carriage-return markers or "Bytes" headers
    assert "69.53545082054042" not in md
    assert "⏎" not in md
    assert "Used Bytes" not in md and "Total Bytes" not in md and "Cached Bytes" not in md
    assert "| Product Version | Not reported |" in md
    assert "| BIOS Vendor | AMI |" in md
    assert "BOOT_IMAGE=/boot/vmlinuz-7.0.0-43-generic root=UUID=<uuid-1> rootflags=subvol=@,compress=zstd ro quiet" in md

    # Displays and CPU capabilities preserved
    assert "| 1 | 1920 × 1080 | 1.0x |" in md
    assert "| 2 | 2560 × 1440 | 1.25x |" in md
    assert "| Current frequency | 4,725.5 MHz |" in md
    assert "| Temperature | 62.3 °C |" in md
    assert "### CPU Capabilities" in md
    assert "`flag_0`" in md and "`flag_11`" in md

    # Memory summary + details + vm config
    assert "## Memory and Swap" in md
    assert "| RAM | 5.01 GiB | 2.19 GiB | 7.20 GiB | 69.5% |" in md
    assert "| Swap | 807.32 MiB | 7.21 GiB | 8.00 GiB | 9.9% |" in md
    assert "| RAM Cached | 1.88 GiB |" in md
    assert "| Kernel Cached | 1.51 GiB |" in md
    assert "| Huge Page Size | 2.00 MiB |" in md
    assert "### Virtual Memory Configuration" in md and "| Swappiness | 60 |" in md

    # Multiple GPUs separated cleanly with pools, sensors with units, and capabilities
    assert "### GPU 1: AMD Radeon RX 7900 XTX" in md
    assert "### GPU 2: Wani \\[Radeon R5/R6/R7 Graphics\\]" in md
    assert "| PCI Vendor / Device | 0x1002 / 0x744c |" in md
    assert "| VRAM | 4.00 GiB | 24.00 GiB |" in md
    assert "| GPU Temperature | 54.7 °C |" in md
    assert "| Core Clock | 2,450.2 MHz |" in md or "| Core Clock | 2,450.3 MHz |" in md
    assert "| Power | 85.4 W |" in md
    assert "| Fan | 1,200 RPM |" in md

    # Storage separated from partitions
    assert "### Physical Storage Devices" in md
    assert "| &lt;device-1&gt; | Samsung 990 PRO | NVMe SSD | 2.00 TiB | 41.2 °C | Yes |" in md or "| &lt;device-1&gt; | Samsung 990 PRO | NVMe SSD | 2.00 TiB | 41.3 °C | Yes |" in md
    assert "### Partitions" in md
    assert "| &lt;device-1&gt;-partition-2 | &lt;device-1&gt; | 2 | 1.00 TiB |" in md

    # Filesystems: capacity separated from virtual mounts and options without Name:/Value: repetition
    assert "### Mounted Volumes" in md
    assert "| &lt;mount-1&gt; | ext4 | &lt;device-1&gt;-partition-2 | 21.84 GiB / 43.99 GiB | 19.89 GiB | 49.6% |" in md
    assert "### System and Virtual Mounts" in md
    assert "| &lt;mount-2&gt; | tmpfs | tmpfs |" in md
    assert "### Mount Options and Identifiers" in md
    assert "Name:" not in md and "Value:" not in md
    assert "root `<mountroot-1>`" in md
    assert "options `rw, relatime`; super options `rw, errors=remount-ro`" in md
    assert "super options `rw, gid=<user>`" in md
    assert "*2 comment lines, 1 blank line omitted.*" in md
    assert "| 9 | &lt;uuid-1&gt; | &lt;mount-1&gt; | ext4 | errors=remount-ro | 0 / 1 |" in md
    assert "Line 12: invalid entry (3 fields)" in md

    # Network summary + per-interface H4 subsections + compact 2-row traffic table + routes
    assert "### Interface Summary" in md
    assert "#### &lt;interface-1&gt; (Ethernet)" in md
    assert "#### &lt;interface-2&gt; (Loopback)" in md
    assert "- **Link speed:** 1,000 Mbps" in md
    assert "| Received | 1.26 GiB | 4.00 KiB/s | 1,211,417 | 0 | 50,008 |" in md
    assert "| Transmitted | 244.73 MiB | 1.00 KiB/s | 398,399 | 0 | 0 |" in md
    assert "### IPv4 Routes" in md and "### IPv6 Routes" in md

    # Sensors subsections
    assert "### Temperatures" in md and "### Drive Temperatures" in md
    assert "### Fan Speeds" in md and "### Power Readings" in md and "### Clock Readings" in md

    # Collected snapshot numeric values remain untouched
    assert data["sections"]["memory"]["ram"]["percent_used"] == 69.53545082054042  # type: ignore[index]


def test_markdown_handles_missing_values_partial_sections_and_unconfigured_swap() -> None:
    partial: dict[str, object] = {
        "schema_version": "1",
        "timestamp": "2026-11-21T22:00:00Z",
        "app_version": "0.1.0",
        "selected_sections": ["memory", "cpu"],
        "privacy": False,
        "sections": {
            "memory": {
                "ram": None,
                "swap": {"total_bytes": 0, "available_bytes": 0, "used_bytes": 0, "percent_used": 0.0},
                "kernel_memory_details": {},
                "configuration": {},
            },
            "cpu": {"available": False},
        },
        "errors": [{"section": "cpu", "message": "Collection failed (OSError)."}],
    }
    md = report_render.render_markdown(partial)
    assert "> **Privacy protection: Disabled.**" in md
    assert "## At a glance" in md
    assert "| Swap | Not configured (0 B) |" in md
    # Missing sections are not fabricated in At a glance
    assert "| Operating system |" not in md
    assert "| Graphics |" not in md
    assert "| Primary storage |" not in md
    assert "| Network |" not in md
    assert "| RAM | Not available | Not available | Not available | Not available |" in md
    assert "| Swap | 0 B | 0 B | 0 B | Not configured |" in md
    assert "CPU information could not be collected." in md
    assert "| CPU | Collection failed (OSError). |" in md


def test_markdown_escapes_multiline_table_injections_and_preserves_zip_consistency(tmp_path) -> None:
    data = rich_diagnostic_snapshot()
    data["sections"]["os"]["hostname"] = "line1 | col\r\n| injected | cell |\n```fence```"  # type: ignore[index]
    data["sections"]["os"]["kernel_command_line"] = [  # type: ignore[index]
        {"parameter": "BOOT_IMAGE", "value": "/boot/vmlinuz```trick"},
    ]

    md_path = tmp_path / "standalone.md"
    zip_path = tmp_path / "bundle.zip"
    write_report(data, md_path, "md")
    write_report(data, zip_path, "zip")

    standalone_md = md_path.read_text(encoding="utf-8")
    with zipfile.ZipFile(zip_path) as archive:
        zipped_md = archive.read("report.md").decode("utf-8")
        zipped_jsonl = archive.read("report.jsonl").decode("utf-8")
        zipped_html = archive.read("report.html").decode("utf-8")

    assert standalone_md == zipped_md
    assert zipped_jsonl == report_render.render_jsonl(data)
    assert zipped_html == report_render.render_html(data)

    # Multiline injection stays inside a single escaped table row
    hostname_lines = [line for line in standalone_md.splitlines() if line.startswith("| Hostname |")]
    assert len(hostname_lines) == 1
    assert "\\| injected \\| cell \\|" in hostname_lines[0]
    assert "⏎" not in standalone_md
    # Code block with backticks uses a longer fence so it cannot break out
    assert "````text" in standalone_md
