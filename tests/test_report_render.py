import copy
from html.parser import HTMLParser
import json
import os
import re
import stat
import zipfile

import pytest

from taskpup import report_collect, report_render
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


def test_formatted_json_preserves_snapshot_types_and_unicode(tmp_path) -> None:
    data = snapshot()
    data["sections"] = {"example": {"model": "Disque é", "size": 1000, "missing": None}}
    destination = tmp_path / "diagnostic.json"
    write_report(data, destination, "json")
    raw = destination.read_text(encoding="utf-8")
    assert "\n  \"schema_version\"" in raw and "Disque é" in raw
    assert json.loads(raw) == data


@pytest.mark.parametrize("protected", [True, False])
def test_privacy_modes_are_consistent_across_all_exports(tmp_path, protected: bool) -> None:
    privacy = report_collect._Privacy(protected)
    raw = {
        "devices": [{"device_path": "/dev/nvme2n1", "model": "Synthetic SSD", "capacity_bytes": 1024}],
        "partitions": [{"device_path": "/dev/nvme2n1p2", "parent_device": "nvme2n1", "partition_number": 2}],
        "mounts": [{"source": "/dev/nvme2n1p2", "mountpoint": "/media/private-name", "filesystem_type": "ext4"}],
        "fstab": {"entries": report_collect._parse_fstab(
            "/dev/nvme2n1p2 /media/private-name ext4 subvol=/private/team,credentials=/tmp/secret-file,password=fixture-secret 0 2", privacy)},
    }
    data = snapshot()
    data["privacy"] = protected
    data["sections"] = {"storage": report_collect._sanitize(raw, privacy)}
    destination = tmp_path / "reports.zip"
    write_report(data, destination, "zip")
    with zipfile.ZipFile(destination) as archive:
        texts = [archive.read(name).decode("utf-8") for name in archive.namelist()]
        assert json.loads(archive.read("report.json")) == data
        assert all(json.loads(line) for line in archive.read("report.jsonl").decode().splitlines())
    for text in texts:
        assert "fixture-secret" not in text and "/tmp/secret-file" not in text
        if protected:
            assert "/dev/nvme2n1" not in text and "/media/private-name" not in text and "/private/team" not in text
        else:
            assert "/dev/nvme2n1" in text and "/media/private-name" in text
    if protected:
        assert "Device 1, Partition 2" in texts[0] and "Synthetic SSD" in texts[0]


@pytest.mark.parametrize("format_name", ["html", "md", "json", "jsonl", "zip"])
@pytest.mark.parametrize("protected", [True, False])
def test_mount_user_and_broadcast_privacy_across_every_export(
    tmp_path, format_name: str, protected: bool,
) -> None:
    privacy = report_collect._Privacy(protected)
    raw = {
        "fstab": report_collect._parse_fstab(
            "/dev/sda1 /mnt/share cifs user=synthetic-remote-account,user,ro 0 0", privacy,
        ),
        "network": {
            "addresses": [
                {"family": "MAC", "address": "02:de:ad:be:ef:01", "broadcast": "02:de:ad:be:ef:02"},
                {"family": "IPv4", "address": "192.0.2.4", "broadcast": "198.51.100.255"},
                {"family": "IPv6", "address": "2001:db8::4", "broadcast": "2001:db8::ffff"},
            ],
        },
    }
    sanitized = report_collect._sanitize(raw, privacy)
    mount_options = sanitized["fstab"][0]["options"]
    assert {"name": "user"} in mount_options
    if protected:
        assert any(
            option["name"] == "user" and option.get("value", "").startswith("<user-")
            for option in mount_options
        )
    else:
        assert {"name": "user", "value": "synthetic-remote-account"} in mount_options
    data = snapshot()
    data["privacy"] = protected
    data["sections"] = {"storage and network": sanitized}
    suffix = {"html": "html", "md": "md", "json": "json", "jsonl": "jsonl", "zip": "zip"}[format_name]
    destination = tmp_path / f"diagnostic.{suffix}"

    write_report(data, destination, format_name)

    if format_name == "zip":
        with zipfile.ZipFile(destination) as archive:
            assert archive.testzip() is None
            outputs = [archive.read(name).decode("utf-8") for name in archive.namelist()]
            assert set(archive.namelist()) == {"report.md", "report.json", "report.jsonl", "report.html"}
    else:
        outputs = [destination.read_text(encoding="utf-8")]
    combined = "\n".join(outputs)
    if protected:
        for private_value in (
            "synthetic-remote-account", "02:de:ad:be:ef:01", "02:de:ad:be:ef:02",
            "198.51.100.255", "2001:db8::ffff",
        ):
            assert private_value not in combined
    else:
        for full_value in (
            "synthetic-remote-account", "02:de:ad:be:ef:01", "02:de:ad:be:ef:02",
            "198.51.100.255", "2001:db8::ffff",
        ):
            assert full_value in combined


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
    assert "8.00 GiB" in html
    assert "VRAM (Driver-Reported)" in html and "18.72 GiB" in html and "24.00 GiB" in html
    assert "GTT (Driver-Reported)" in html and "1.00 KiB" in html and "2.00 KiB" in html
    assert "2.00 KiB/s" in html and "1,500" in html
    assert "Used Bytes" not in html and "Total Bytes" not in html
    assert "Bytes Received" not in html and "Receive Bytes Per Second" not in html
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


def test_zip_contains_all_reports_rendered_from_same_snapshot(tmp_path) -> None:
    destination = tmp_path / "diagnostic.zip"

    write_report(snapshot(), destination, "zip")

    with zipfile.ZipFile(destination) as archive:
        assert archive.namelist() == ["report.md", "report.json", "report.jsonl", "report.html"]
        assert json.loads(archive.read("report.json")) == snapshot()
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


def test_cleanup_failure_still_closes_directory_descriptor(tmp_path, monkeypatch) -> None:
    real_open, real_close = os.open, os.close
    directory_fds: list[int] = []
    closed: list[int] = []

    def track_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if path == tmp_path:
            directory_fds.append(fd)
        return fd

    def track_close(fd):
        if fd in directory_fds:
            closed.append(fd)
        real_close(fd)

    def fail(*args, **kwargs):
        raise OSError("simulated failure")

    monkeypatch.setattr(report_render.os, "open", track_open)
    monkeypatch.setattr(report_render.os, "close", track_close)
    monkeypatch.setattr(report_render.os, "fsync", fail)
    monkeypatch.setattr(report_render.os, "unlink", fail)
    with pytest.raises(OSError, match="simulated failure"):
        report_render._atomic_write(tmp_path / "report.md", b"report", overwrite=False)
    assert len(directory_fds) == 1
    assert closed == directory_fds
    assert not (tmp_path / "report.md").exists()


def test_network_address_family_disambiguates_broadcasts() -> None:
    privacy = report_collect._Privacy(True)
    value = "20:10:aa:bb:cc:dd:ee:ff"
    addresses = [
        {"family": "IPv6", "address": value, "broadcast": value},
        {"family": "MAC", "address": value, "broadcast": value},
        {"family": "IPv4", "broadcast": "192.0.2.255"},
    ]
    result = report_collect._sanitize(addresses, privacy)
    assert result[0]["address"] == result[0]["broadcast"] == "<ip-1>"
    assert result[1]["address"] == result[1]["broadcast"] == "<mac-1>"
    assert result[2]["broadcast"] == "<ip-2>"


def test_fdopen_failure_closes_raw_descriptor_and_removes_temporary_file(tmp_path, monkeypatch) -> None:
    destination = tmp_path / "diagnostic.md"
    raw_descriptors: list[int] = []
    close_attempts: list[int] = []
    real_fdopen = os.fdopen
    real_close = os.close

    def fail_fdopen(fd: int, *_args, **_kwargs):
        raw_descriptors.append(fd)
        # Simulate fdopen constructing and then abandoning a wrapper before
        # raising. closefd=False must leave the raw descriptor with its caller.
        abandoned_stream = real_fdopen(fd, *_args, **_kwargs)
        abandoned_stream.close()
        os.fstat(fd)
        raise OSError("simulated fdopen error")

    def track_close(fd: int) -> None:
        if raw_descriptors and fd == raw_descriptors[0]:
            close_attempts.append(fd)
        real_close(fd)

    monkeypatch.setattr(report_render.os, "fdopen", fail_fdopen)
    monkeypatch.setattr(report_render.os, "close", track_close)
    with pytest.raises(OSError, match="simulated fdopen error"):
        report_render._atomic_write(destination, b"report", overwrite=False)

    assert len(raw_descriptors) == 1
    assert close_attempts == raw_descriptors
    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("failure", ["write", "flush", "fsync"])
def test_stream_failure_closes_stream_then_owned_raw_descriptor_once_and_removes_temporary_file(
    tmp_path, monkeypatch, failure: str,
) -> None:
    destination = tmp_path / "diagnostic.md"
    raw_descriptors: list[int] = []
    direct_close_attempts: list[int] = []
    stream_closes: list[int] = []
    real_fdopen = os.fdopen
    real_close = os.close

    class FailingStream:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            stream_closes.append(self.fd)
            self.stream.close()

        def write(self, payload: bytes) -> int:
            if failure == "write":
                raise OSError("simulated write error")
            return self.stream.write(payload)

        def flush(self) -> None:
            if failure == "flush":
                raise OSError("simulated flush error")
            self.stream.flush()

        def fileno(self) -> int:
            return self.stream.fileno()

    def tracked_fdopen(fd: int, *args, **kwargs):
        raw_descriptors.append(fd)
        return FailingStream(real_fdopen(fd, *args, **kwargs))

    def track_close(fd: int) -> None:
        if raw_descriptors and fd == raw_descriptors[0]:
            direct_close_attempts.append(fd)
        real_close(fd)

    def fail_fsync(_fd: int) -> None:
        raise OSError("simulated fsync error")

    monkeypatch.setattr(report_render.os, "fdopen", tracked_fdopen)
    monkeypatch.setattr(report_render.os, "close", track_close)
    if failure == "fsync":
        monkeypatch.setattr(report_render.os, "fsync", fail_fsync)

    with pytest.raises(OSError, match=f"simulated {failure} error"):
        report_render._atomic_write(destination, b"report", overwrite=False)

    assert len(raw_descriptors) == 1
    assert stream_closes == raw_descriptors
    assert direct_close_attempts == raw_descriptors
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
    assert "| Device 1 | Samsung 990 PRO | NVMe SSD | 2.00 TiB | 41.2 °C | Yes |" in md or "| Device 1 | Samsung 990 PRO | NVMe SSD | 2.00 TiB | 41.3 °C | Yes |" in md
    assert "### Partitions" in md
    assert "| Device 1, Partition 2 | Device 1 | 2 | 1.00 TiB |" in md

    # Filesystems: capacity separated from virtual mounts and options without Name:/Value: repetition
    assert "### Mounted Volumes" in md
    assert "| &lt;mount-1&gt; | ext4 | Device 1, Partition 2 | 21.84 GiB / 43.99 GiB | 19.89 GiB | 49.6% |" in md
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


def test_html_dashboard_header_summary_cards_formatting_and_full_data_preservation() -> None:
    data = rich_diagnostic_snapshot()
    # Add representative high-precision values and milliwatt idle GPU reading
    data["sections"]["cpu"]["current_frequency_mhz"] = 5050.211187500001  # type: ignore[index]
    data["sections"]["cpu"]["temperature_c"] = 39.125  # type: ignore[index]
    data["sections"]["filesystems"]["mounts"][0]["capacity"]["percent_used"] = 57.971210721172866  # type: ignore[index]
    data["sections"]["graphics"]["devices"][0]["memory_pools"]["driver_reported_vram"]["used_bytes"] = 1_067_902_238  # type: ignore[index]
    data["sections"]["graphics"]["devices"][1]["sensors"] = {"GPU temperature": 35.0, "Core clock": 600.0, "Power": 0.005}  # type: ignore[index]
    data["sections"]["graphics"]["devices"][1]["utilization_percent"] = 0.0  # type: ignore[index]
    data["sections"]["sensors"]["power_readings"].append({"device": "<hardware-2>", "name": "Power", "value_w": 0.005})  # type: ignore[index]
    data["sections"]["sensors"]["fan_speeds"].append({"device": "<hardware-2>", "name": "Fan", "value_rpm": 0.0})  # type: ignore[index]

    before = copy.deepcopy(data)
    html = report_render.render_html(data)

    # Snapshot immutability
    assert data == before

    # TaskPup header branding, metadata, privacy notice, and no redacted IDs in header
    header_match = re.search(r"<header\b[^>]*>(.*?)</header>", html, re.DOTALL)
    assert header_match is not None
    header_html = header_match.group(1)
    assert "TaskPup" in header_html
    assert "System Diagnostic Report" in header_html
    assert "Hardware &amp; System Diagnostics" in header_html
    assert "Linux Mint 22.3" in header_html
    assert "Privacy: Enabled" in header_html
    assert "TaskPup v0.1.0" in header_html
    assert "2026-11-21T21:47:25Z" in header_html
    assert "Automated redaction may not catch every sensitive value" in header_html
    assert "&lt;host-1&gt;" not in header_html
    assert "Linux Mint System Profile" not in html

    # All 6 executive summary cards rendered from snapshot
    summary_match = re.search(r'<section class="exec-grid[^"]*"[^>]*>(.*?)</section>', html, re.DOTALL)
    assert summary_match is not None
    summary_html = summary_match.group(1)
    for title in ("Operating System", "Processor", "System Memory", "Graphics", "Storage", "Network"):
        assert f'<span class="exec-card-title">{title}</span>' in summary_html
    assert "AMD Ryzen 7 9800X3D" in summary_html
    assert "5.05 GHz" in summary_html
    assert "39.1 °C" in summary_html
    assert "7.20 GiB RAM" in summary_html
    assert "1 / 2 Connected" in summary_html

    # Human-readable numeric precision and zero/unavailable/unsupported distinctions
    assert "58.0%" in html
    assert "57.971210721172866" not in html
    assert "5050.211187500001" not in html
    assert "5.05 GHz" in html
    assert "600.0 MHz" in html
    assert "39.1 °C" in html
    assert "39.125" not in html
    assert "1,018.43 MiB" in html
    assert "0.005 W" in html
    assert "0 RPM" in html
    assert "1,200 RPM" in html
    assert "1 Gbps (1,000 Mbps)" in html
    assert "Not reported" in html  # blank product_version
    assert "Unsupported" in html  # drive with temperature_supported=False

    # OS firmware + kernel command line preserved inside details
    assert "Machine &amp; Firmware" in html
    assert "Kernel Command Line" in html
    assert "BOOT_IMAGE=/boot/vmlinuz-7.0.0-43-generic root=UUID=&lt;uuid-1&gt; rootflags=subvol=@,compress=zstd ro quiet" in html

    # Desktop displays preserved
    assert "Connected Displays" in html
    assert "1920 × 1080" in html and "2560 × 1440" in html and "1.25x" in html

    # CPU capabilities preserved in expandable details
    assert "Advanced CPU Capabilities &amp; Flags" in html
    for i in range(12):
        assert f"flag_{i}" in html

    # Memory bars, cache/buffers, kernel memory, VM config
    assert "Physical RAM" in html and "Swap Space" in html
    assert "RAM Load" in html and "Swap Load" in html
    assert "Cache, Buffers &amp; Kernel Memory" in html
    assert "Huge Page Size" in html and "2.00 MiB" in html
    assert "Virtual Memory Configuration" in html and "Swappiness" in html

    # Multi-GPU separated into individual sub-cards with hardware-first headings, VRAM/GTT & caveat
    assert "<h3>AMD Radeon RX 7900 XTX</h3>" in html
    assert "<h3>Wani [Radeon R5/R6/R7 Graphics]</h3>" in html
    assert "VRAM (Driver-Reported)" in html
    assert "GTT (Driver-Reported)" in html
    assert "driver-reported; dedicated/shared semantics are not assumed" in html
    assert "0x1002 / 0x744c" in html
    assert "Telemetry Capabilities" in html
    assert "Diagnostic Reference ID" in html and "&lt;hardware-1&gt;" in html

    # Storage separates physical devices & partitions with drive models first and technical refs preserved
    assert "Physical Storage Devices" in html
    assert "Partitions" in html
    assert "Raw block device capacities reflect physical hardware size and differ from mounted filesystem capacities." in html
    assert "Technical Storage Identifiers" in html
    assert "&lt;device-1&gt;-partition-2" in html

    # Filesystems: readable volume/mount labels + backing drive + virtual mounts + advanced details + fstab
    assert "Mounted Storage Volumes" in html
    assert "ext4 Volume 1" in html
    assert "System &amp; Virtual Mounts" in html
    assert "System Mount 1" in html
    assert "Advanced Mount Details &amp; Options" in html
    assert "Name: rw" not in html and "Value: remount-ro" not in html
    assert "rw, relatime" in html
    assert "rw, errors=remount-ro" in html
    assert "rw, gid=&lt;user&gt;" in html
    assert "&lt;mountroot-1&gt;" in html
    assert "8:3" in html
    assert "Configured /etc/fstab Entries" in html
    assert "Technical /etc/fstab Identifiers" in html
    assert "Non-Entry /etc/fstab Records (Comments &amp; Blank Lines)" in html
    assert "1, 2" in html  # exact comment line numbers preserved
    assert "Invalid /etc/fstab Records" in html and "3 fields" in html

    # Network interfaces use hardware-first descriptions + routes + technical refs
    assert "DNS Resolver" in html and "&lt;ip-32&gt;" in html and "&lt;host-2&gt;" in html
    assert "Network Interfaces" in html
    assert "<h3>Ethernet Adapter · r8169</h3>" in html
    assert "<h3>Loopback Interface 1</h3>" in html
    assert "Technical Interface Identifiers" in html
    assert "&lt;interface-1&gt;" in html and "&lt;interface-2&gt;" in html
    assert "status-up" in html and "status-down" in html
    assert "Traffic Counters &amp; Rates" in html
    assert "1.26 GiB" in html and "4.00 KiB/s" in html and "1,211,417" in html and "50,008" in html
    assert "IPv4 Routes" in html and "IPv6 Routes" in html
    assert "routes-scroll" in html

    # Sensors grouped cleanly with hardware-first device resolution & technical refs preserved
    for heading in ("Temperatures", "Drive Temperatures", "Fan Speeds", "Power Readings", "Clock Readings"):
        assert f"<h3>{heading}</h3>" in html
    assert "Technical Sensor Device Identifiers" in html

    # Empty errors state
    assert "Collection Errors" in html and "0 errors" in html
    assert "No collection errors were reported." in html


def test_html_virtual_filesystem_classification_and_large_mount_list() -> None:
    data = rich_diagnostic_snapshot()
    mounts: list[dict[str, object]] = [
        {
            "device_number": "0:28",
            "root": "<mountroot-2>",
            "mountpoint": "<mount-root>",
            "filesystem_type": "btrfs",
            "source": "<device-4>-partition-3",
            "options": [{"name": "rw"}, {"name": "relatime"}],
            "super_options": [{"name": "rw"}, {"name": "subvol", "value": "/@"}],
            "capacity": {"total_bytes": 316 * 1024**3, "used_bytes": 183 * 1024**3, "available_bytes": 131 * 1024**3, "percent_used": 57.9},
        },
        {
            "device_number": "259:11",
            "root": "<mountroot-1>",
            "mountpoint": "<mount-ntfs>",
            "filesystem_type": "fuseblk",
            "source": "<device-2>-partition-1",
            "options": [{"name": "rw"}],
            "super_options": [{"name": "rw"}],
            "capacity": {"total_bytes": 953 * 1024**3, "used_bytes": 820 * 1024**3, "available_bytes": 133 * 1024**3, "percent_used": 86.0},
        },
        {
            "device_number": "0:81",
            "root": "<mountroot-1>",
            "mountpoint": "<mount-cifs>",
            "filesystem_type": "cifs",
            "source": "<source-1>",
            "options": [{"name": "rw"}],
            "super_options": [{"name": "rw"}, {"name": "vers", "value": "3.0"}],
            "capacity": None,
            "custom_tag": "smb-share",
        },
    ]
    virtual_types = [
        "proc", "sysfs", "tmpfs", "cgroup", "cgroup2", "securityfs",
        "devtmpfs", "devpts", "efivarfs", "bpf", "pstore", "autofs",
        "debugfs", "tracefs", "fuse.gvfsd-fuse", "fuse.portal", "overlay", "nsfs",
    ]
    for idx in range(40):
        fstype = virtual_types[idx % len(virtual_types)]
        mounts.append({
            "device_number": f"0:{100 + idx}",
            "root": "<mountroot-1>",
            "mountpoint": f"<mount-virt-{idx}>",
            "filesystem_type": fstype,
            "source": fstype,
            "options": [{"name": "rw"}, {"name": "nosuid"}, {"name": "nodev"}],
            "super_options": [{"name": "rw"}],
            "capacity": None,
        })
    data["sections"]["filesystems"]["mounts"] = mounts  # type: ignore[index]

    html = report_render.render_html(data)

    # Non-virtual mounts with capacity go into Mounted Storage Volumes (including fuseblk!)
    vol_section = html.split("Mounted Storage Volumes", 1)[1].split("Additional Storage &amp; Network Mounts", 1)[0]
    assert "&lt;mount-root&gt;" in vol_section
    assert "&lt;mount-ntfs&gt;" in vol_section
    assert "bar-crit" in vol_section  # 86.0% triggers critical bar styling
    assert "&lt;mount-virt-0&gt;" not in vol_section

    # Non-virtual mount without capacity (cifs) stays separated from virtual mounts
    extra_section = html.split("Additional Storage &amp; Network Mounts", 1)[1].split("System &amp; Virtual Mounts", 1)[0]
    assert "&lt;mount-cifs&gt;" in extra_section
    assert "cifs" in extra_section

    # Large virtual mount list (>6) is collapsed by default inside <details>
    assert '<details class="details-panel filter-block"><summary><span class="summary-title">System &amp; Virtual Mounts</span><span class="badge mono">40 mounts</span></summary>' in html
    # Advanced mount details preserve all 43 mounts including extra custom metadata
    assert '<span class="summary-title">Advanced Mount Details &amp; Options</span><span class="badge mono">43 mounts</span>' in html
    assert "Custom Tag: smb-share" in html
    assert "&lt;mount-virt-39&gt;" in html


def test_html_missing_data_partial_sections_and_error_visibility() -> None:
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
    html = report_render.render_html(partial)

    assert "Privacy: Disabled" in html
    assert "privacy-off" in html
    # Unselected sections do not fabricate summary cards
    assert '<span class="exec-card-title">Graphics</span>' not in html
    assert '<span class="exec-card-title">Storage</span>' not in html
    assert '<span class="exec-card-title">Network</span>' not in html
    # Present sections show honest unavailable / unconfigured states
    assert "RAM not available" in html
    assert "Not configured" in html
    assert "0 B" in html
    assert "CPU information could not be collected." in html
    # Actual errors are prominently displayed and never hidden behind a success banner
    assert "card-error" in html
    assert "1 error" in html
    assert "Collection failed (OSError)." in html
    assert "No collection errors were reported." not in html

    # Empty sections map produces a clear fallback card
    empty_snap = {**partial, "sections": {}, "selected_sections": [], "errors": []}
    empty_html = report_render.render_html(empty_snap)
    assert "No diagnostic sections were available." in empty_html


def test_html_progress_bar_bounds_and_safe_inline_styles() -> None:
    data = rich_diagnostic_snapshot()
    data["sections"]["memory"]["ram"]["percent_used"] = -25.4  # type: ignore[index]
    data["sections"]["memory"]["swap"]["percent_used"] = 187.6  # type: ignore[index]
    data["sections"]["graphics"]["devices"][0]["utilization_percent"] = 74.2  # type: ignore[index]
    data["sections"]["filesystems"]["mounts"][0]["capacity"]["percent_used"] = 999.9  # type: ignore[index]

    html = report_render.render_html(data)

    # All inline style attributes must ONLY be strictly bounded numeric widths (0.0% to 100.0%)
    styles = re.findall(r'style="([^"]*)"', html)
    assert styles, "expected bounded progress-bar width styles"
    for style in styles:
        match = re.fullmatch(r"width: (\d+(?:\.\d+)?)%;", style)
        assert match is not None, f"unexpected inline style: {style!r}"
        width_val = float(match.group(1))
        assert 0.0 <= width_val <= 100.0
    assert "width: 0.0%;" in html
    assert "width: 100.0%;" in html
    assert "width: 74.2%;" in html
    assert "bar-warn" in html


@pytest.mark.parametrize("huge", [10**400, -(10**400)])
def test_html_oversized_numeric_values_are_safe(huge: int) -> None:
    data = rich_diagnostic_snapshot()
    sections = data["sections"]
    sections["memory"]["ram"]["percent_used"] = huge  # type: ignore[index]
    sections["memory"]["swap"]["percent_used"] = huge  # type: ignore[index]
    gpu = sections["graphics"]["devices"][0]  # type: ignore[index]
    gpu["utilization_percent"] = huge
    gpu["memory_pools"]["driver_reported_vram"]["used_bytes"] = huge
    gpu["memory_pools"]["driver_reported_vram"]["total_bytes"] = huge
    gpu["sensors"] = {"Power": huge, "Core clock": huge, "Fan": huge}
    sections["storage"]["devices"][0]["capacity_bytes"] = huge  # type: ignore[index]
    sections["filesystems"]["mounts"][0]["capacity"]["percent_used"] = huge  # type: ignore[index]
    sections["cpu"]["temperature_c"] = huge  # type: ignore[index]
    sections["cpu"]["current_frequency_mhz"] = huge  # type: ignore[index]
    sections["os"]["uptime_seconds"] = huge  # type: ignore[index]
    sections["network"]["interfaces"][0]["link_speed_mbps"] = huge  # type: ignore[index]
    html = report_render.render_html(data)
    assert "Out of range" in html
    assert "NaN%" not in html and "Infinity%" not in html
    for width in re.findall(r'style="width: ([\d.]+)%;"', html):
        assert 0 <= float(width) <= 100
    assert "0 RPM" in report_render._html_rpm_plain(0)
    assert report_render._html_percent_plain(None) == "Not available"
    assert report_render._html_percent_plain(42.5) == "42.5%"


def test_html_gpu_pool_ratio_handles_extreme_finite_values() -> None:
    data = rich_diagnostic_snapshot()
    pool = data["sections"]["graphics"]["devices"][0]["memory_pools"]["driver_reported_vram"]  # type: ignore[index]
    pool["used_bytes"] = 1e100
    pool["total_bytes"] = 5e-324
    html = report_render.render_html(data)
    assert "Infinity%" not in html


@pytest.mark.parametrize("huge", [10**400, -(10**400)])
def test_zip_export_handles_oversized_percent_without_mutating_snapshot(tmp_path, huge: int) -> None:
    data = rich_diagnostic_snapshot()
    data["sections"]["memory"]["ram"]["percent_used"] = huge  # type: ignore[index]
    before = copy.deepcopy(data)
    markdown = report_render.render_markdown(data)
    html = report_render.render_html(data)
    assert "Out of range" in markdown and "Out of range" in html
    destination = tmp_path / "report.zip"
    write_report(data, destination, "zip")
    with zipfile.ZipFile(destination) as archive:
        assert archive.read("report.md").decode() == markdown
        assert archive.read("report.html").decode() == html
        jsonl = archive.read("report.jsonl").decode()
        assert jsonl == report_render.render_jsonl(data)
        records = [json.loads(line) for line in jsonl.splitlines()]
        memory = next(r["data"] for r in records if r.get("section") == "memory")
        assert memory["ram"]["percent_used"] == huge
    assert data == before
    assert report_render._md_percent(42.5) == "42.5%"


@pytest.mark.parametrize("formatter", [report_render._md_bytes, report_render._md_rate,
    report_render._md_percent, report_render._md_temp, report_render._md_freq_mhz,
    report_render._md_rpm, report_render._md_watts, report_render._md_speed_mbps,
    report_render._md_uptime])
def test_markdown_numeric_formatters_handle_unrepresentable_values(formatter) -> None:
    for value in (10**400, -(10**400), float("inf"), float("nan")):
        assert formatter(value) == "Out of range"


def test_zip_export_handles_extreme_values_across_numeric_sections(tmp_path) -> None:
    data = rich_diagnostic_snapshot()
    sections = data["sections"]
    sections["memory"]["swap"]["total_bytes"] = 10**400  # type: ignore[index]
    gpu = sections["graphics"]["devices"][0]  # type: ignore[index]
    gpu["utilization_percent"] = -(10**400)
    gpu["memory_pools"]["driver_reported_vram"]["used_bytes"] = 10**400
    sections["storage"]["devices"][0]["capacity_bytes"] = 10**400  # type: ignore[index]
    sections["filesystems"]["mounts"][0]["capacity"]["percent_used"] = 10**400  # type: ignore[index]
    destination = tmp_path / "extreme.zip"
    write_report(data, destination, "zip")
    with zipfile.ZipFile(destination) as archive:
        assert b"Out of range" in archive.read("report.md")
        assert b"Out of range" in archive.read("report.html")


def test_html_escapes_hostile_inputs_and_handles_long_identifiers() -> None:
    xss = '"><script>alert("xss")</script><img src=x onerror=alert(1)><svg onload=bad>'
    long_id = "dev-" + ("a" * 400) + "-end"
    data = rich_diagnostic_snapshot()
    data["timestamp"] = f"2026-11-22T00:00:00Z {xss}"
    data["app_version"] = f"0.1.0{xss}"
    data["sections"]["os"]["distribution"] = f"Mint {xss}"  # type: ignore[index]
    data["sections"]["os"]["hostname"] = xss  # type: ignore[index]
    data["sections"]["cpu"]["model"] = f"CPU {long_id} {xss}"  # type: ignore[index]
    data["sections"]["cpu"]["capabilities"] = [xss, long_id]  # type: ignore[index]
    data["sections"]["filesystems"]["mounts"][0]["mountpoint"] = xss  # type: ignore[index]
    data["sections"]["filesystems"]["mounts"][0]["options"] = [{"name": xss, "value": xss}]  # type: ignore[index]
    data["sections"]["network"]["interfaces"][0]["interface"] = long_id  # type: ignore[index]
    data["errors"] = [{"section": xss, "message": xss}]

    html = report_render.render_html(data)

    # Parse DOM tags/attributes to verify zero injected executable elements or event handlers
    parsed_tags: list[tuple[str, list[tuple[str, str | None]]]] = []

    class SecurityAuditParser(HTMLParser):
        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            parsed_tags.append((tag.lower(), [(k.lower(), v) for k, v in attrs]))

    SecurityAuditParser().feed(html)
    script_tags = [tag for tag, _ in parsed_tags if tag == "script"]
    assert len(script_tags) == 1, "only the static inline script tag may exist"
    assert not any(tag == "img" for tag, _ in parsed_tags)
    for tag, attrs in parsed_tags:
        for attr_name, _ in attrs:
            assert not attr_name.startswith("on"), f"unexpected inline event handler {attr_name} on <{tag}>"

    # Static script never embeds snapshot values
    script_match = re.search(r"<script>\n(.*?)</script>", html, re.DOTALL)
    assert script_match is not None
    assert "alert(" not in script_match.group(1)
    assert long_id not in script_match.group(1)
    # Escaped hostile payload and very long identifier remain present and readable
    without_static_script = re.sub(r"<script>\n.*?</script>", "", html, count=1, flags=re.DOTALL)
    assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in without_static_script
    assert long_id in without_static_script


def test_html_offline_self_contained_interactivity_responsive_css_and_zip_invariance(tmp_path) -> None:
    data = rich_diagnostic_snapshot()
    before = copy.deepcopy(data)

    md_standalone = report_render.render_markdown(data)
    jsonl_standalone = report_render.render_jsonl(data)
    html_standalone = report_render.render_html(data)

    html_path = tmp_path / "standalone.html"
    zip_path = tmp_path / "bundle.zip"
    write_report(data, html_path, "html")
    write_report(data, zip_path, "zip")

    assert html_path.read_text(encoding="utf-8") == html_standalone
    with zipfile.ZipFile(zip_path) as archive:
        assert archive.read("report.html").decode("utf-8") == html_standalone
        assert archive.read("report.md").decode("utf-8") == md_standalone
        assert archive.read("report.jsonl").decode("utf-8") == jsonl_standalone

    # Offline self-contained guarantees
    assert "http://" not in html_standalone
    assert "https://" not in html_standalone
    assert "<link " not in html_standalone
    assert "<script src=" not in html_standalone
    assert "@import" not in html_standalone

    # Interactive search, details toggle, print controls, and print stylesheet
    assert 'id="filterInput"' in html_standalone
    assert 'id="clearFilterBtn"' in html_standalone
    assert 'id="filterStatus"' in html_standalone
    assert 'id="filterEmptyState"' in html_standalone
    assert 'id="toggleDetailsBtn"' in html_standalone
    assert 'id="printBtn"' in html_standalone
    assert "Print / Save as PDF" in html_standalone
    assert "@media print" in html_standalone
    assert "beforeprint" in html_standalone and "afterprint" in html_standalone
    # Print is triggered only via button click listener, never automatically on page load
    script_body = re.search(r"<script>\n(.*?)</script>", html_standalone, re.DOTALL)
    assert script_body is not None
    assert script_body.group(1).count("window.print()") == 1

    # Responsive CSS avoids fixed wide min-width overflow traps and handles narrow viewports
    assert "minmax(620px" not in html_standalone
    assert "repeat(2, minmax(0, 1fr))" in html_standalone
    assert "@media (max-width: 1080px)" in html_standalone
    assert "@media (max-width: 1020px)" in html_standalone
    assert "@media (max-width: 640px)" in html_standalone
    assert "overflow-x: auto" in html_standalone
    assert "overflow-wrap: anywhere" in html_standalone

    # Snapshot remained untouched across all render formats
    assert data == before


def test_html_hardware_first_labels_disambiguation_fallbacks_and_safe_correlations() -> None:
    snap: dict[str, object] = {
        "schema_version": "1",
        "timestamp": "2026-11-22T12:00:00Z",
        "app_version": "0.1.0",
        "selected_sections": ["graphics", "storage", "filesystems", "network", "sensors"],
        "privacy": True,
        "sections": {
            "graphics": {
                "devices": [
                    {
                        "identity": "<hardware-1>",
                        "model": "Navi 31 [Radeon RX 7900 XT/7900 XTX/7900 GRE/7900M]",
                        "pci_vendor_id": "0x1002",
                        "pci_device_id": "0x744c",
                        "driver": "amdgpu",
                        "utilization_percent": 10.0,
                        "memory_pools": {},
                        "sensors": {},
                        "telemetry_capabilities": ["utilization"],
                    },
                    {
                        "identity": "<hardware-2>",
                        "model": "Synthetic Accelerator X",
                        "pci_vendor_id": "0x10de",
                        "pci_device_id": "0x1234",
                        "driver": "nouveau",
                        "utilization_percent": 0.0,
                        "memory_pools": {},
                        "sensors": {},
                        "telemetry_capabilities": [],
                    },
                    {
                        "identity": "<hardware-3>",
                        "model": "Synthetic Accelerator X",
                        "pci_vendor_id": "0x10de",
                        "pci_device_id": "0x1234",
                        "driver": "nouveau",
                        "utilization_percent": None,
                        "memory_pools": {},
                        "sensors": {},
                        "telemetry_capabilities": [],
                    },
                    {
                        "identity": "<hardware-4>",
                        "model": None,
                        "pci_vendor_id": None,
                        "pci_device_id": None,
                        "driver": None,
                        "utilization_percent": None,
                        "memory_pools": {},
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
                        "model": "Samsung SSD 990 PRO 1TB",
                        "storage_type": "NVMe SSD",
                        "capacity_bytes": 1000 * 1024**3,
                        "temperature_c": 34.0,
                        "temperature_supported": True,
                    },
                    {
                        "device_path": "<device-2>",
                        "device_name": "<device-2>",
                        "model": "Samsung SSD 990 PRO 1TB",
                        "storage_type": "NVMe SSD",
                        "capacity_bytes": 1000 * 1024**3,
                        "temperature_c": 36.0,
                        "temperature_supported": True,
                    },
                    {
                        "device_path": "<device-3>",
                        "device_name": "<device-3>",
                        "model": None,
                        "storage_type": "SATA SSD",
                        "capacity_bytes": 500 * 1024**3,
                        "temperature_c": None,
                        "temperature_supported": False,
                    },
                ],
                "partitions": [
                    {"device_path": "<device-1>-partition-1", "parent_device": "<device-1>", "partition_number": 1, "capacity_bytes": 500 * 1024**3},
                    {"device_path": "<device-2>-partition-1", "parent_device": "<device-2>", "partition_number": 1, "capacity_bytes": 500 * 1024**3},
                    {"device_path": "<device-9>-partition-1", "parent_device": "<device-9>", "partition_number": 1, "capacity_bytes": 500 * 1024**3},
                ],
            },
            "filesystems": {
                "mountinfo_available": True,
                "mounts": [
                    {
                        "device_number": "0:28",
                        "root": "<mountroot-1>",
                        "mountpoint": "<mount-1>",
                        "filesystem_type": "btrfs",
                        "source": "<device-1>-partition-1",
                        "options": [{"name": "rw"}],
                        "super_options": [{"name": "rw"}],
                        "capacity": {"total_bytes": 500 * 1024**3, "used_bytes": 100 * 1024**3, "available_bytes": 400 * 1024**3, "percent_used": 20.0},
                    },
                    {
                        "device_number": "8:1",
                        "root": "<mountroot-1>",
                        "mountpoint": "<mount-2>",
                        "filesystem_type": "ntfs3",
                        "source": "<device-2>-partition-1",
                        "options": [{"name": "rw"}],
                        "super_options": [{"name": "rw"}],
                        "capacity": {"total_bytes": 500 * 1024**3, "used_bytes": 250 * 1024**3, "available_bytes": 250 * 1024**3, "percent_used": 50.0},
                    },
                    {
                        "device_number": "8:2",
                        "root": "<mountroot-1>",
                        "mountpoint": "<mount-3>",
                        "filesystem_type": "ntfs3",
                        # Same 500 GiB capacity as <device-3>, but unlinked device ID <device-9> must NOT be guessed!
                        "source": "<device-9>-partition-1",
                        "options": [{"name": "rw"}],
                        "super_options": [{"name": "rw"}],
                        "capacity": {"total_bytes": 500 * 1024**3, "used_bytes": 50 * 1024**3, "available_bytes": 450 * 1024**3, "percent_used": 10.0},
                    },
                    {
                        "device_number": "0:81",
                        "root": "<mountroot-1>",
                        "mountpoint": "<mount-4>",
                        "filesystem_type": "cifs",
                        "source": "<source-1>",
                        "options": [{"name": "rw"}],
                        "super_options": [{"name": "rw"}],
                        "capacity": None,
                    },
                    {
                        "device_number": "0:22",
                        "root": "<mountroot-1>",
                        "mountpoint": "<mount-5>",
                        "filesystem_type": "proc",
                        "source": "proc",
                        "options": [{"name": "rw"}],
                        "super_options": [{"name": "rw"}],
                        "capacity": None,
                    },
                ],
                "fstab": {
                    "available": True,
                    "entries": [
                        {
                            "line": 1,
                            "record_type": "entry",
                            "source": "<uuid-1>",
                            "mountpoint": "<mount-1>",
                            "filesystem_type": "btrfs",
                            "options": [{"name": "defaults"}],
                            "dump": 0,
                            "pass": 0,
                        },
                    ],
                },
            },
            "network": {
                "addresses_available": True,
                "interface_stats_available": True,
                "counters_available": True,
                "dns": {"nameservers": ["<ip-9>"], "search_domains": []},
                "interfaces": [
                    {
                        "interface": "<interface-1>",
                        "type": "Ethernet",
                        "auxiliary": False,
                        "connection_state": "Connected",
                        "driver": "r8169",
                        "link_speed_mbps": 1000,
                        "addresses": [{"family": "IPv4", "address": "<ip-1>", "netmask": "<ip-2>", "broadcast": None}],
                        "counters": None,
                        "rates": None,
                    },
                    {
                        "interface": "<interface-2>",
                        "type": "Ethernet",
                        "auxiliary": False,
                        "connection_state": "Disconnected",
                        "driver": "r8169",
                        "link_speed_mbps": None,
                        "addresses": [{"family": "MAC", "address": "<mac-1>", "netmask": None, "broadcast": None}],
                        "counters": None,
                        "rates": None,
                    },
                    {
                        "interface": "<interface-3>",
                        "type": "Wi-Fi",
                        "auxiliary": False,
                        "connection_state": "Connected",
                        "driver": "mt7921e",
                        "link_speed_mbps": None,
                        "addresses": [],
                        "counters": None,
                        "rates": None,
                    },
                    {
                        "interface": "<interface-4>",
                        "type": "Wi-Fi",
                        "auxiliary": False,
                        "connection_state": "Disconnected",
                        "driver": None,
                        "link_speed_mbps": None,
                        "addresses": [],
                        "counters": None,
                        "rates": None,
                    },
                ],
                "ipv4_routes": [
                    {"interface": "<interface-1>", "destination": "<ip-3>", "gateway": "<ip-4>", "netmask": "<ip-2>", "metric": 100},
                ],
                "ipv6_routes": [
                    {"interface": "<interface-3>", "destination": "<ip-5>", "gateway": "<ip-6>", "metric": 256},
                ],
            },
            "sensors": {
                "temperatures_available": True,
                "fan_speeds_available": False,
                "temperatures": [{"device": "<hardware-1>", "name": "GPU temperature", "value_c": 42.0}],
                "drive_temperatures": [
                    {"device": "<device-1>", "name": "Drive temperature", "value_c": 34.0},
                    {"device": "<device-2>", "name": "Drive temperature", "value_c": 36.0},
                ],
                "fan_speeds": [],
                "power_readings": [{"device": "<hardware-2>", "name": "Power", "value_w": 55.0}],
                "clock_readings": [{"device": "<hardware-4>", "name": "Core clock", "value_mhz": 1200.0}],
            },
        },
        "errors": [],
    }

    before = copy.deepcopy(snap)
    md_before = report_render.render_markdown(snap)
    jsonl_before = report_render.render_jsonl(snap)
    html = report_render.render_html(snap)

    # Immutability + Markdown/JSONL invariance
    assert snap == before
    assert report_render.render_markdown(snap) == md_before
    assert report_render.render_jsonl(snap) == jsonl_before

    # 1. GPU model preferred over <hardware-1>, exact family preserved (no guessed retail SKU), duplicates numbered, missing fallback
    assert "<h3>Navi 31 [Radeon RX 7900 XT/7900 XTX/7900 GRE/7900M]</h3>" in html
    assert "<h3>Synthetic Accelerator X (#1)</h3>" in html
    assert "<h3>Synthetic Accelerator X (#2)</h3>" in html
    assert "<h3>Graphics Device 4</h3>" in html
    gpu_section = html.split("<h2>Graphics Hardware (GPU)</h2>", 1)[1].split("<h2>Storage Hardware</h2>", 1)[0]
    gpu_headers = re.findall(r"<h3>(.*?)</h3>", gpu_section)
    assert all("&lt;hardware-" not in heading for heading in gpu_headers)

    # 2 & 3. Drive models preferred over <device-N>, duplicate drives numbered, missing model gets neutral fallback (not guessed)
    storage_section = html.split("<h2>Storage Hardware</h2>", 1)[1].split("<h2>Filesystems &amp; Mounts</h2>", 1)[0]
    primary_storage = storage_section.split("Technical Storage Identifiers", 1)[0]
    assert "Samsung SSD 990 PRO 1TB (#1)" in primary_storage
    assert "Samsung SSD 990 PRO 1TB (#2)" in primary_storage
    assert "SATA SSD 1" in primary_storage
    assert "Unlinked Drive" in primary_storage
    assert "&lt;device-" not in primary_storage
    # Technical identifiers still preserved inside collapsible details
    assert "&lt;device-1&gt;" in storage_section and "&lt;device-2&gt;-partition-1" in storage_section

    # 4. Network interface descriptions use safe type + driver, duplicates disambiguated, routes resolved, IPs/MACs still redacted
    net_section = html.split("<h2>Network Configuration</h2>", 1)[1].split("<h2>Hardware Sensors</h2>", 1)[0]
    primary_net = net_section.split("Technical Interface Identifiers", 1)[0]
    assert "<h3>Ethernet Adapter 1 · r8169</h3>" in primary_net
    assert "<h3>Ethernet Adapter 2 · r8169</h3>" in primary_net
    assert "<h3>Wi-Fi Adapter · mt7921e</h3>" in primary_net
    assert "<h3>Wi-Fi Adapter 1</h3>" in primary_net
    assert "&lt;interface-" not in primary_net
    assert "&lt;ip-1&gt;" in primary_net and "&lt;mac-1&gt;" in primary_net
    assert "&lt;interface-1&gt;" in net_section and "&lt;interface-3&gt;" in net_section

    # 5 & 7. Filesystem readable headings + unambiguous backing drive linkage + NO guessed association for <device-9>
    fs_section = html.split("<h2>Filesystems &amp; Mounts</h2>", 1)[1].split("<h2>Network Configuration</h2>", 1)[0]
    vol_table = fs_section.split("Mounted Storage Volumes", 1)[1].split("Additional Storage &amp; Network Mounts", 1)[0]
    assert "Btrfs Volume 1" in vol_table
    assert "NTFS Volume 1" in vol_table
    assert "NTFS Volume 2" in vol_table
    assert "Samsung SSD 990 PRO 1TB (#1)" in vol_table
    assert "Samsung SSD 990 PRO 1TB (#2)" in vol_table
    # Unlinked <device-9>-partition-1 (same 500 GiB as SATA SSD 1) must NOT be guessed as SATA SSD 1!
    ntfs2_row = vol_table.split("NTFS Volume 2", 1)[1].split("</tr>", 1)[0]
    assert "SATA SSD 1" not in ntfs2_row
    assert "Storage Device" in ntfs2_row and "Partition 1" in ntfs2_row
    assert "&lt;mount-" not in vol_table and "&lt;device-" not in vol_table
    assert "Network Share 1" in fs_section and "Redacted network share" in fs_section
    assert "System Mount 1" in fs_section
    # Advanced Mount Details & fstab Technical References preserve redacted correlation IDs
    assert "Mount ID: <span class=\"mono-span\">&lt;mount-1&gt;</span>" in fs_section
    assert "&lt;source-1&gt;" in fs_section and "&lt;uuid-1&gt;" in fs_section

    # Sensors resolve hardware-first labels consistently across GPUs and drives
    sensors_section = html.split("<h2>Hardware Sensors</h2>", 1)[1].split("<h2>Collection Errors</h2>", 1)[0]
    primary_sensors = sensors_section.split("Technical Sensor Device Identifiers", 1)[0]
    assert "Navi 31 [Radeon RX 7900 XT/7900 XTX/7900 GRE/7900M]" in primary_sensors
    assert "Synthetic Accelerator X (#1)" in primary_sensors
    assert "Graphics Device 4" in primary_sensors
    assert "Samsung SSD 990 PRO 1TB (#1)" in primary_sensors
    assert "Samsung SSD 990 PRO 1TB (#2)" in primary_sensors
    assert "&lt;hardware-" not in primary_sensors and "&lt;device-" not in primary_sensors
    assert "&lt;hardware-1&gt;" in sensors_section and "&lt;device-1&gt;" in sensors_section


def test_html_unredacted_names_permitted_when_privacy_disabled_and_hostile_models_escaped() -> None:
    hostile_gpu = '"><script>alert("gpu")</script>'
    hostile_drive = '<img src=x onerror=alert("drive")> SSD'
    hostile_driver = '<svg onload=bad>drv'
    snap: dict[str, object] = {
        "schema_version": "1",
        "timestamp": "2026-11-22T12:05:00Z",
        "app_version": "0.1.0",
        "selected_sections": ["graphics", "storage", "filesystems", "network"],
        "privacy": False,
        "sections": {
            "graphics": {
                "devices": [
                    {
                        "identity": "0000:03:00.0",
                        "model": hostile_gpu,
                        "pci_vendor_id": "0x1002",
                        "pci_device_id": "0x744c",
                        "driver": hostile_driver,
                        "utilization_percent": 5.0,
                        "memory_pools": {},
                        "sensors": {},
                        "telemetry_capabilities": [],
                    },
                ],
            },
            "storage": {
                "devices": [
                    {
                        "device_path": "/dev/nvme0n1",
                        "device_name": "nvme0n1",
                        "model": hostile_drive,
                        "storage_type": "NVMe SSD",
                        "capacity_bytes": 512 * 1024**3,
                        "temperature_c": 35.0,
                        "temperature_supported": True,
                    },
                ],
                "partitions": [
                    {"device_path": "/dev/nvme0n1p1", "parent_device": "nvme0n1", "partition_number": 1, "capacity_bytes": 512 * 1024**3},
                ],
            },
            "filesystems": {
                "mountinfo_available": True,
                "mounts": [
                    {
                        "device_number": "259:1",
                        "root": "/",
                        "mountpoint": "/data",
                        "filesystem_type": "ext4",
                        "source": "/dev/nvme0n1p1",
                        "options": [{"name": "rw"}],
                        "super_options": [{"name": "rw"}],
                        "capacity": {"total_bytes": 512 * 1024**3, "used_bytes": 128 * 1024**3, "available_bytes": 384 * 1024**3, "percent_used": 25.0},
                    },
                ],
                "fstab": {"available": False, "entries": []},
            },
            "network": {
                "addresses_available": True,
                "interface_stats_available": True,
                "counters_available": True,
                "dns": None,
                "interfaces": [
                    {
                        "interface": "enp14s0",
                        "type": "Ethernet",
                        "auxiliary": False,
                        "connection_state": "Connected",
                        "driver": hostile_driver,
                        "link_speed_mbps": 1000,
                        "addresses": [],
                        "counters": None,
                        "rates": None,
                    },
                ],
                "ipv4_routes": [{"interface": "enp14s0", "destination": "0.0.0.0", "gateway": "192.0.2.1", "netmask": "0.0.0.0", "metric": 100}],
                "ipv6_routes": [],
            },
        },
        "errors": [],
    }

    html = report_render.render_html(snap)

    # Permitted unredacted identifiers stay visible when privacy is disabled
    assert "0000:03:00.0" in html
    assert "/dev/nvme0n1" in html and "/dev/nvme0n1p1" in html
    assert "/data" in html
    assert "enp14s0" in html

    # Hostile model/driver strings are safely escaped with zero injected executable markup
    tags: list[tuple[str, list[tuple[str, str | None]]]] = []

    class AuditParser(HTMLParser):
        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            tags.append((tag.lower(), [(k.lower(), v) for k, v in attrs]))

    AuditParser().feed(html)
    assert sum(1 for tag, _ in tags if tag == "script") == 1
    assert not any(tag == "img" for tag, _ in tags)
    for tag, attrs in tags:
        for attr_name, _ in attrs:
            assert not attr_name.startswith("on"), f"unexpected handler {attr_name} on <{tag}>"
    assert "&lt;script&gt;alert(&quot;gpu&quot;)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(&quot;drive&quot;)&gt; SSD" in html
    assert "&lt;svg onload=bad&gt;drv" in html
