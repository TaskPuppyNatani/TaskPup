from types import SimpleNamespace

from taskpup import report_collect as reports


def test_app_version_uses_project_version_fallback_when_uninstalled(monkeypatch) -> None:
    def missing_distribution(_name: str) -> str:
        raise reports.importlib.metadata.PackageNotFoundError("taskpup")

    monkeypatch.setattr(reports.importlib.metadata, "version", missing_distribution)

    assert reports._app_version() == "0.1.1"


def test_fstab_structures_entries_and_redacts_credentials_and_private_identifiers() -> None:
    privacy = reports._Privacy(True)
    raw = (
        "# fstab sample\n"
        "\n"
        "/dev/nvme2n1p1 /media/Photo\\040Archive ext4 defaults,subvol=/home/alex/Work 0 2\n"
        "nas.example.test:/export /mnt/share nfs4 rw,credentials=/etc/smb.creds,password=hunter2 0 0\n"
        "broken entry\n"
    )

    entries = reports._parse_fstab(raw, privacy)

    assert entries[0] == {"line": 1, "record_type": "comment"}
    assert entries[1] == {"line": 2, "record_type": "blank"}
    local = entries[2]
    assert local["record_type"] == "entry"
    assert local["source"] == "<device-1>-partition-1"
    assert local["mountpoint"] == "<mount-1>"
    assert {"name": "subvol", "value": "<mountroot-1>"} in local["options"]
    remote = entries[3]
    assert remote["source"] == "<source-1>"
    assert {"name": "credentials", "value": "<redacted>"} in remote["options"]
    assert {"name": "password", "value": "<redacted>"} in remote["options"]
    assert entries[4]["record_type"] == "invalid"
    assert "hunter2" not in repr(entries)
    assert "smb.creds" not in repr(entries)
    assert "nas.example.test" not in repr(entries)


def test_device_and_filesystem_source_pseudonyms_are_stable_and_partition_aware() -> None:
    privacy = reports._Privacy(True)

    whole_disk = reports._sanitize({"name": "nvme2n1", "device_path": "/dev/nvme2n1"}, privacy)
    partition = reports._sanitize({"name": "nvme2n1p1", "source": "/dev/nvme2n1p1"}, privacy)

    assert whole_disk["name"] == whole_disk["device_path"] == "<device-1>"
    assert partition["name"] == partition["source"] == "<device-1>-partition-1"


def test_bind_sources_and_unknown_systemd_options_are_protected() -> None:
    line = "/srv/customer-alice/private-share /mnt/archive none bind,x-systemd.custom=PRIVATE_MARKER 0 0"
    protected = reports._parse_fstab(line, reports._Privacy(True))[0]
    full = reports._parse_fstab(line, reports._Privacy(False))[0]
    assert "/srv/customer-alice" not in repr(protected)
    assert full["source"] == "/srv/customer-alice/private-share"
    assert "PRIVATE_MARKER" not in repr(protected) and "PRIVATE_MARKER" not in repr(full)


def test_generic_network_and_hardware_identifiers_are_redacted_consistently() -> None:
    privacy = reports._Privacy(True)
    data = {
        "addresses": [
            {"family": "MAC", "address": "02:11:22:33:44:55"},
            {"family": "MAC", "address": "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:22"},
            {"family": "IPv6", "address": "2001:db8::2"},
        ],
        "routes": [{"destination": "2001:db8::/64", "gateway": "10.20.30.1", "interface": "enp0s31f6"}],
        "dns": {"nameservers": ["192.0.2.53"], "search_domains": ["corp.example.test"]},
        "mount": {"root": "/subvol/home/alex", "source": "nas.example.test:/export/alex"},
        "gpu": {"identity": "/sys/devices/pci0000:00/0000:00:02.0"},
        "storage": {"source": "[2001:db8::42]:/export", "model": "nvme2n1"},
    }

    sanitized = reports._sanitize(data, privacy)
    rendered = repr(sanitized)

    for raw in (
        "02:11:22:33:44:55", "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:22",
        "2001:db8::2", "2001:db8::/64", "10.20.30.1",
        "enp0s31f6", "192.0.2.53", "corp.example.test", "nas.example.test",
        "/subvol/home/alex", "/sys/devices/pci0000:00/0000:00:02.0", "[2001:db8::42]:/export",
    ):
        assert raw not in rendered
    assert sanitized["addresses"][0]["address"] == "<mac-1>"
    assert sanitized["addresses"][1]["address"] == "<mac-2>"
    assert sanitized["gpu"]["identity"].startswith("<hardware-")
    assert sanitized["storage"]["model"] == "<device-1>"


def test_kernel_command_line_omits_unknown_arguments_and_sanitizes_boot_paths() -> None:
    privacy = reports._Privacy(True)

    parsed = reports._parse_kernel_cmdline(
        "quiet root=UUID=12345678-1234-1234-1234-123456789abc "
        "BOOT_IMAGE=/home/alex/vmlinuz-1 root=PARTUUID=deadbeef-1234 loglevel=3 password=hunter2 token=abc123",
        privacy,
    )

    assert {"parameter": "quiet", "value": "present"} in parsed
    assert {"parameter": "root", "value": "UUID=<uuid-1>"} in parsed
    assert {"parameter": "BOOT_IMAGE", "value": "<path-1>"} in parsed
    assert {"parameter": "root", "value": "PARTUUID=<uuid-2>"} in parsed
    assert {"parameter": "loglevel", "value": "3"} in parsed
    assert "password" not in repr(parsed)
    assert "hunter2" not in repr(parsed)
    assert "abc123" not in repr(parsed)


def test_full_kernel_command_line_preserves_device_path() -> None:
    parsed = reports._parse_kernel_cmdline("root=/dev/nvme2n1p2", reports._Privacy(False))
    assert parsed == [{"parameter": "root", "value": "/dev/nvme2n1p2"}]


def test_credentials_are_removed_even_when_privacy_is_disabled() -> None:
    privacy = reports._Privacy(False)

    cleaned = reports._sanitize(
        {
            "source": "//testuser:SYNTHETIC-PASSWORD@nas.example.test/share",
            "mount_options": [{"name": "password", "value": "SYNTHETIC-PASSWORD"}],
        },
        privacy,
    )

    assert cleaned["source"] == "//<redacted>@nas.example.test/share"
    assert cleaned["mount_options"][0]["value"] == "<redacted>"
    assert "testuser" not in repr(cleaned)
    assert "SYNTHETIC-PASSWORD" not in repr(cleaned)


def test_report_collects_only_selected_sections_and_uses_passed_screen_snapshot() -> None:
    report = reports.collect_report(
        {"desktop", "unknown"},
        screen_info=[{"name": "private-monitor-name", "width": 1920, "height": 1080, "scale": 1.25}],
    )

    assert report["schema_version"] == "1"
    assert report["timestamp"].endswith("Z")
    assert report["selected_sections"] == ["desktop"]
    assert report["privacy"] is True
    assert list(report["sections"]) == ["desktop"]
    assert report["sections"]["desktop"]["screens"] == [{"width": 1920, "height": 1080, "scale": 1.25}]
    assert "private-monitor-name" not in repr(report)
    assert report["errors"] == [{"section": "unknown", "message": "Unknown report section; skipped."}]


def test_memory_uses_taskpup_total_minus_available_semantics(monkeypatch) -> None:
    monkeypatch.setattr(
        reports.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(total=1000, available=250, used=123, percent=12.3, cached=40, buffers=10),
    )
    monkeypatch.setattr(
        reports.psutil,
        "swap_memory",
        lambda: SimpleNamespace(total=500, free=350, used=150, percent=30),
    )
    monkeypatch.setattr(reports, "_read_text", lambda *_args, **_kwargs: None)

    memory = reports.collect_report({"memory"})["sections"]["memory"]["ram"]

    assert memory["total_bytes"] == 1000
    assert memory["available_bytes"] == 250
    assert memory["used_bytes"] == 750
    assert memory["percent_used"] == 75.0


def test_collection_failure_is_reported_without_exposing_exception(monkeypatch) -> None:
    def failed():
        raise OSError("synthetic-private-path")

    monkeypatch.setattr(reports, "_collect_memory", failed)
    report = reports.collect_report({"memory"})
    assert report["sections"]["memory"] == {"available": False}
    assert report["errors"] == [{"section": "memory", "message": "Collection failed (OSError)."}]
    assert "synthetic-private-path" not in repr(report)


def test_unavailable_mount_routes_and_dns_are_distinguished_from_empty(monkeypatch) -> None:
    monkeypatch.setattr(reports, "_read_text", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(reports.psutil, "net_if_addrs", lambda: {})
    monkeypatch.setattr(reports.psutil, "net_if_stats", lambda: {})
    monkeypatch.setattr(reports.psutil, "net_io_counters", lambda **_kwargs: {})
    monkeypatch.setattr(reports.NetworkSampler, "sample", lambda *_args: {})
    network = reports._collect_network()
    assert network["ipv4_routes"] is None and network["ipv6_routes"] is None and network["dns"] is None
    sample = reports.StorageSample(1.0, {}, (), filesystems_available=False)
    filesystem = reports._collect_filesystems(sample, reports._Privacy(True))
    assert filesystem["mountinfo_available"] is False
    assert filesystem["fstab"]["available"] is False
