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
    assert "Driver Reported VRAM: Used Bytes: 18.72 GiB" in markdown
    assert "Bytes Received: 7.20 GiB" in markdown and "Receive Bytes Per Second: 2.00 KiB/s" in markdown
    assert "Packets Received: 1500" in markdown
    assert "7.20 GiB" in html and "119.24 GiB" in html
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
