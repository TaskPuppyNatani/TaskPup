from pathlib import Path

from taskpup.gpu import discover


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_discovery_deduplicates_and_samples_partial_amd(tmp_path: Path) -> None:
    drm, devices = tmp_path / 'drm', tmp_path / 'devices'
    drm.mkdir()
    amd = devices / '0000:03:00.0'
    other = devices / '0000:04:00.0'
    for device, vendor in ((amd, '0x1002'), (other, '0x8086')):
        write(device / 'vendor', vendor)
        write(device / 'device', '0x1234')
    driver = tmp_path / 'drivers' / 'amdgpu'
    driver.mkdir(parents=True)
    (amd / 'driver').symlink_to(driver)
    for card, device in (('card0', amd), ('card3', amd), ('card4', other), ('card0-HDMI-A-1', amd)):
        (drm / card).mkdir()
        (drm / card / 'device').symlink_to(device)
    write(amd / 'gpu_busy_percent', '35')
    write(amd / 'mem_info_vram_used', '25')
    write(amd / 'mem_info_vram_total', '100')
    write(amd / 'mem_info_gtt_total', '1000')
    hw = amd / 'hwmon' / 'hwmon0'
    write(hw / 'temp1_label', 'junction')
    write(hw / 'temp1_input', '76000')
    write(hw / 'temp2_label', 'unknown')
    write(hw / 'temp2_input', '90000')
    write(hw / 'freq1_input', '300000000')
    write(hw / 'power1_average', '22000000')
    write(hw / 'fan1_input', '0')
    gpus = discover(drm)
    assert len(gpus) == 2
    assert gpus[0].identity == str(amd) and gpus[0].driver == 'amdgpu'
    sample = gpus[0].sample()
    assert sample.utilization == 35 and sample.memory_percent == 25
    assert sample.gtt_used is None and sample.gtt_total == 1000
    assert sample.sensors == {'Hotspot temperature': 76, 'Core clock': 300, 'Power': 22, 'Fan': 0}
    assert sample.capabilities == {
        "utilization", "memory_used", "memory_total", "gtt_total", "Hotspot temperature",
        "Core clock", "Power", "Fan",
    }
    assert gpus[1].sample().utilization is None
    assert gpus[1].sample().capabilities == frozenset()
    write(amd / 'gpu_busy_percent', '101')
    write(amd / 'mem_info_vram_used', '-1')
    write(hw / 'temp1_input', 'broken')
    sample = gpus[0].sample()
    assert sample.utilization is None and sample.memory_percent is None
    assert 'Hotspot temperature' not in sample.sensors
    assert 'Hotspot temperature' in sample.capabilities
    (amd / 'gpu_busy_percent').unlink()
    assert gpus[0].sample().utilization is None


def test_inaccessible_file_is_unavailable(tmp_path: Path, monkeypatch) -> None:
    from taskpup.gpu import number

    def denied(*args, **kwargs):
        raise PermissionError('denied')

    monkeypatch.setattr(Path, 'read_text', denied)
    assert number(tmp_path / 'sensor') is None
