from pathlib import Path
from types import SimpleNamespace

import pytest

from taskpup import storage
from taskpup.storage import StorageSampler


def configure_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    proc = tmp_path / "proc"
    sysfs = tmp_path / "sys"
    block = sysfs / "class" / "block"
    block.mkdir(parents=True)
    (sysfs / "fs" / "btrfs").mkdir(parents=True)
    (proc / "self").mkdir(parents=True)
    (proc / "diskstats").write_text("")
    (proc / "self" / "mountinfo").write_text("")
    monkeypatch.setattr(storage, "PROC_DISKSTATS", proc / "diskstats")
    monkeypatch.setattr(storage, "PROC_MOUNTINFO", proc / "self" / "mountinfo")
    monkeypatch.setattr(storage, "SYS_BLOCK", block)
    monkeypatch.setattr(storage, "SYS_BTRFS", sysfs / "fs" / "btrfs")
    monkeypatch.setattr(storage, "DEV_ROOT", tmp_path / "dev")
    return proc, sysfs, block


def add_block(
    sysfs: Path,
    block: Path,
    name: str,
    major: int,
    minor: int,
    *,
    sectors: int = 4096,
    model: str = "Example SSD",
    vendor: str = "Example",
    layout: tuple[str, ...] = ("pci0000:00", "ata1", "host0", "block"),
    diskseq: str | None = "1",
    rotational: int | None = 0,
    temperature: str | None = None,
    temperature_label: str | None = None,
) -> Path:
    target = sysfs / "devices" / Path(*layout) / name
    target.mkdir(parents=True)
    (target / "dev").write_text(f"{major}:{minor}\n")
    (target / "size").write_text(f"{sectors}\n")
    if diskseq is not None:
        (target / "diskseq").write_text(f"{diskseq}\n")
    queue = target / "queue"
    queue.mkdir()
    if rotational is not None:
        (queue / "rotational").write_text(f"{rotational}\n")
    device = target / "device"
    device.mkdir()
    (device / "model").write_text(f"{model}\n")
    (device / "vendor").write_text(f"{vendor}\n")
    (device / "transport").write_text("sata\n")
    link = block / name
    link.symlink_to(target, target_is_directory=True)
    if temperature is not None:
        hwmon = device / "hwmon2"
        hwmon.mkdir()
        (hwmon / "temp1_input").write_text(f"{temperature}\n")
        if temperature_label is not None:
            (hwmon / "temp1_label").write_text(f"{temperature_label}\n")
    return target


def add_partition(
    block: Path,
    parent: Path,
    name: str,
    major: int,
    minor: int,
    *,
    number: int,
    sectors: int = 1024,
) -> Path:
    target = parent / name
    target.mkdir()
    (target / "dev").write_text(f"{major}:{minor}\n")
    (target / "size").write_text(f"{sectors}\n")
    (target / "partition").write_text(f"{number}\n")
    (block / name).symlink_to(target, target_is_directory=True)
    return target


def add_dm(block: Path, sysfs: Path, name: str, major: int, minor: int, slave: Path) -> Path:
    target = sysfs / "devices" / "virtual" / "block" / name
    target.mkdir(parents=True)
    (target / "dev").write_text(f"{major}:{minor}\n")
    (target / "size").write_text("2048\n")
    (target / "diskseq").write_text("8\n")
    (target / "dm").mkdir()
    (target / "dm" / "name").write_text("vg-root\n")
    slaves = target / "slaves"
    slaves.mkdir()
    (slaves / slave.name).symlink_to(slave, target_is_directory=True)
    (block / name).symlink_to(target, target_is_directory=True)
    return target


def disk_line(
    major: int,
    minor: int,
    name: str,
    *,
    read_sectors: int = 0,
    write_sectors: int = 0,
    io_ms: int = 0,
) -> str:
    counters = [1, 0, read_sectors, 0, 1, 0, write_sectors, 0, 0, io_ms, io_ms]
    return f"{major} {minor} {name} " + " ".join(map(str, counters))


def set_diskstats(proc: Path, *lines: str) -> None:
    (proc / "diskstats").write_text("\n".join(lines) + "\n")


def mount_line(
    mount_id: int,
    major: int,
    minor: int,
    mountpoint: str,
    fstype: str,
    source: str,
    *,
    root: str = "/",
) -> str:
    def escaped(value: str) -> str:
        return value.replace(" ", "\\040")

    return (
        f"{mount_id} 1 {major}:{minor} {escaped(root)} {escaped(mountpoint)} rw,relatime "
        f"- {fstype} {source} rw"
    )


def set_mountinfo(proc: Path, *lines: str) -> None:
    (proc / "self" / "mountinfo").write_text("\n".join(lines) + ("\n" if lines else ""))


def statvfs_result(*, blocks: int = 100, free: int = 25, available: int = 20) -> SimpleNamespace:
    return SimpleNamespace(f_frsize=4096, f_bsize=4096, f_blocks=blocks, f_bfree=free, f_bavail=available)


def test_discovers_whole_disk_for_mounted_partition_and_filesystem_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc, sysfs, block = configure_roots(tmp_path, monkeypatch)
    disk = add_block(sysfs, block, "sda", 8, 0, sectors=20_000, model="Drive X")
    part = add_partition(block, disk, "sda1", 8, 1, number=1)
    set_diskstats(
        proc,
        disk_line(8, 0, "sda", read_sectors=100, write_sectors=20),
        disk_line(8, 1, "sda1", read_sectors=50, write_sectors=10),
    )
    set_mountinfo(proc, mount_line(1, 8, 1, "/mnt/data", "ext4", "/dev/sda1"))
    monkeypatch.setattr(storage.os, "statvfs", lambda _: statvfs_result())

    sample = StorageSampler().sample(10.0)

    assert len(sample.devices) == 1
    drive = next(iter(sample.devices.values()))
    assert drive.name == "sda"
    assert drive.kind == "SATA SSD"
    assert drive.label == "Example Drive X (sda)"
    assert drive.capacity == 20_000 * 512
    assert drive.bytes_read == 100 * 512
    assert part.exists()
    assert sample.filesystems == (
        storage.Filesystem("/mnt/data", "ext4", 409_600, 307_200, 81_920, 75.0),
    )


def test_mounted_device_mapper_keeps_logical_card_and_physical_disk_separate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc, sysfs, block = configure_roots(tmp_path, monkeypatch)
    disk = add_block(sysfs, block, "sdb", 8, 16)
    part = add_partition(block, disk, "sdb2", 8, 18, number=2)
    logical = add_dm(block, sysfs, "dm-0", 253, 0, part)
    set_diskstats(
        proc,
        disk_line(8, 16, "sdb", read_sectors=80),
        disk_line(8, 18, "sdb2", read_sectors=60),
        disk_line(253, 0, "dm-0", read_sectors=40),
    )
    set_mountinfo(proc, mount_line(2, 0, 42, "/", "ext4", "/dev/dm-0"))
    monkeypatch.setattr(storage.os, "statvfs", lambda _: statvfs_result())

    sample = StorageSampler().sample(1.0)

    assert {device.name for device in sample.devices.values()} == {"sdb", "dm-0"}
    assert next(device for device in sample.devices.values() if device.name == "dm-0").kind == "Logical"
    assert next(device for device in sample.devices.values() if device.name == "dm-0").label == "vg-root (dm-0)"
    assert logical.exists()
    assert len(sample.filesystems) == 1


def test_btrfs_sources_ntfs_and_bind_mounts_are_deduplicated_without_remote_filesystems(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc, sysfs, block = configure_roots(tmp_path, monkeypatch)
    disk_a = add_block(sysfs, block, "nvme0n1", 259, 0, model="Fast Drive", layout=("pci0000:00", "nvme"))
    part_a1 = add_partition(block, disk_a, "nvme0n1p1", 259, 1, number=1)
    part_a2 = add_partition(block, disk_a, "nvme0n1p2", 259, 2, number=2)
    disk_b = add_block(
        sysfs, block, "sdb", 8, 16, model="USB Drive", layout=("pci0000:00", "usb2", "block"),
    )
    part_b1 = add_partition(block, disk_b, "sdb1", 8, 17, number=1)

    uuid = sysfs / "fs" / "btrfs" / "fs-uuid"
    (uuid / "devices" / "1").mkdir(parents=True)
    (uuid / "devices" / "1" / "dev").write_text("259:1\n")
    (uuid / "devices" / "2").mkdir(parents=True)
    (uuid / "devices" / "2" / "dev").write_text("259:2\n")
    set_diskstats(
        proc,
        disk_line(259, 0, "nvme0n1"),
        disk_line(259, 1, "nvme0n1p1"),
        disk_line(259, 2, "nvme0n1p2"),
        disk_line(8, 16, "sdb"),
        disk_line(8, 17, "sdb1"),
    )
    set_mountinfo(
        proc,
        mount_line(1, 8, 17, "/mnt/windows", "ntfs3", "/dev/sdb1"),
        mount_line(2, 259, 1, "/data", "ext4", "/dev/nvme0n1p1"),
        mount_line(3, 259, 1, "/data/bind", "ext4", "/dev/nvme0n1p1", root="/subdir"),
        mount_line(4, 0, 28, "/", "btrfs", "/dev/nvme0n1p1"),
        mount_line(5, 0, 44, "/home", "btrfs", "/dev/nvme0n1p2", root="/home-subvol"),
        mount_line(6, 0, 55, "/net", "nfs4", "server:/share"),
    )
    calls: list[str] = []

    def fake_statvfs(path: str) -> SimpleNamespace:
        calls.append(path)
        if path == "/data":
            raise PermissionError(path)
        return statvfs_result()

    monkeypatch.setattr(storage.os, "statvfs", fake_statvfs)
    sample = StorageSampler().sample(1.0)

    assert [filesystem.mountpoint for filesystem in sample.filesystems] == ["/", "/data", "/mnt/windows"]
    assert [filesystem.fstype for filesystem in sample.filesystems] == ["btrfs", "ext4", "ntfs3"]
    assert sample.filesystems[1].total is None
    assert len(calls) == 3
    assert {device.name for device in sample.devices.values()} == {"nvme0n1", "sdb"}
    assert next(device for device in sample.devices.values() if device.name == "sdb").kind == "USB storage"
    assert part_a1.exists() and part_a2.exists() and part_b1.exists()


def test_rates_use_elapsed_time_activity_capability_and_raw_byte_totals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc, sysfs, block = configure_roots(tmp_path, monkeypatch)
    add_block(sysfs, block, "nvme3n1", 259, 16, layout=("pci0000:00", "nvme"))
    set_mountinfo(proc)
    set_diskstats(proc, disk_line(259, 16, "nvme3n1", read_sectors=100, write_sectors=50, io_ms=100))
    sampler = StorageSampler()
    first = sampler.sample(10.0)
    initial_id, initial = next(iter(first.devices.items()))
    assert initial.read_rate is None and initial.write_rate is None and initial.activity is None
    assert initial.activity_supported
    assert initial.bytes_read == 100 * 512 and initial.bytes_written == 50 * 512

    set_diskstats(proc, disk_line(259, 16, "nvme3n1", read_sectors=110, write_sectors=55, io_ms=600))
    second = sampler.sample(12.0).devices[initial_id]
    assert second.read_rate == pytest.approx(2_560.0)
    assert second.write_rate == pytest.approx(1_280.0)
    assert second.activity == pytest.approx(25.0)
    assert second.bytes_read == 110 * 512

    sampler.reset()
    set_diskstats(proc, disk_line(259, 16, "nvme3n1", read_sectors=120, write_sectors=60, io_ms=700))
    after_reset = sampler.sample(13.0).devices[initial_id]
    assert after_reset.read_rate is None and after_reset.activity is None
    assert after_reset.bytes_read == 120 * 512


def test_counter_reset_and_wrap_handling_does_not_create_artificial_spikes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc, sysfs, block = configure_roots(tmp_path, monkeypatch)
    add_block(sysfs, block, "sdc", 8, 32)
    set_mountinfo(proc)
    set_diskstats(proc, disk_line(8, 32, "sdc", read_sectors=50_000_000_000))
    sampler = StorageSampler()
    first = sampler.sample(1.0)
    identity = next(iter(first.devices))

    set_diskstats(proc, disk_line(8, 32, "sdc", read_sectors=0))
    reset = sampler.sample(2.0).devices[identity]
    assert reset.read_rate is None
    assert reset.bytes_read == 0

    set_diskstats(proc, disk_line(8, 32, "sdc", read_sectors=5))
    resumed = sampler.sample(3.0).devices[identity]
    assert resumed.read_rate == pytest.approx(5 * 512)

    assert storage._counter_delta((1 << 32) - 5, 3) == 8
    assert storage._counter_delta((1 << 64) - 2, 1) == 3
    assert storage._counter_delta(50_000_000_000, 0) is None
    assert storage._counter_delta(3 * (1 << 30) + 1, 0) is None


def test_unreadable_mountinfo_is_distinct_from_no_mounts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    proc, _, _ = configure_roots(tmp_path, monkeypatch)
    set_mountinfo(proc, mount_line(1, 0, 9, "/", "tmpfs", "tmpfs"))
    sampler = StorageSampler()
    empty = sampler.sample(1.0)
    assert empty.filesystems_available and empty.filesystems == ()
    (proc / "self" / "mountinfo").unlink()
    unavailable = sampler.sample(2.0)
    assert not unavailable.filesystems_available


def test_temperature_is_device_scoped_and_capability_survives_sensor_read_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc, sysfs, block = configure_roots(tmp_path, monkeypatch)
    disk = add_block(
        sysfs, block, "nvme4n1", 259, 32, layout=("pci0000:00", "nvme"),
        temperature="26850", temperature_label="Composite",
    )
    sensor = disk / "device" / "hwmon2" / "temp1_input"
    set_mountinfo(proc)
    set_diskstats(proc, disk_line(259, 32, "nvme4n1"))
    sampler = StorageSampler()
    first = sampler.sample(1.0)
    identity = next(iter(first.devices))
    assert first.devices[identity].temperature_supported
    assert first.devices[identity].temperature_c == pytest.approx(26.85)

    sensor.unlink()
    failed = sampler.sample(2.0).devices[identity]
    assert failed.temperature_supported
    assert failed.temperature_c is None


def test_diskstats_failure_retains_device_and_activity_capability(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    proc, sysfs, block = configure_roots(tmp_path, monkeypatch)
    add_block(sysfs, block, "sdd", 8, 48)
    set_mountinfo(proc)
    diskstats_path = proc / "diskstats"
    set_diskstats(proc, disk_line(8, 48, "sdd", read_sectors=100))
    sampler = StorageSampler()
    first = sampler.sample(1.0)
    identity = next(iter(first.devices))
    monkeypatch.setattr(storage, "PROC_DISKSTATS", proc / "missing-diskstats")

    failed = sampler.sample(2.0)
    assert set(failed.devices) == {identity}
    assert failed.devices[identity].activity_supported
    assert failed.devices[identity].read_rate is None
    assert failed.devices[identity].bytes_read is None

    monkeypatch.setattr(storage, "PROC_DISKSTATS", diskstats_path)
    set_diskstats(proc, disk_line(8, 48, "sdd", read_sectors=120))
    recovered = sampler.sample(3.0).devices[identity]
    assert recovered.activity_supported
    assert recovered.read_rate is None
    assert recovered.bytes_read == 120 * 512


def test_diskseq_change_starts_a_new_device_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    proc, sysfs, block = configure_roots(tmp_path, monkeypatch)
    disk = add_block(sysfs, block, "sde", 8, 64)
    set_mountinfo(proc)
    set_diskstats(proc, disk_line(8, 64, "sde"))
    sampler = StorageSampler()
    first_id = next(iter(sampler.sample(1.0).devices))

    (disk / "diskseq").write_text("2\n")
    second_id = next(iter(sampler.sample(2.0).devices))
    assert second_id != first_id
