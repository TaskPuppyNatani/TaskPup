import errno
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from taskpup.platform import desktop_icons


def test_desktop_icons_skips_special_and_malformed_entries_and_reads_symlinks(tmp_path: Path) -> None:
    data_home = tmp_path / "data"
    applications = data_home / "applications"
    applications.mkdir(parents=True)
    target = tmp_path / "launcher-target"
    target.write_text(
        "[Desktop Entry]\nType=Application\nName=Scanner fixture\n"
        "Exec=/usr/bin/scanner-fixture\nIcon=scanner-fixture-icon\n",
        encoding="utf-8",
    )
    (applications / "linked.desktop").symlink_to(target)
    (applications / "fifo.desktop").symlink_to(target, target_is_directory=False)
    (applications / "malformed.desktop").write_text("not a desktop entry", encoding="utf-8")
    (applications / "invalid-utf8.desktop").write_bytes(b"\xff\xfe")
    (applications / "oversized.desktop").write_bytes(b"x" * (1024 * 1024 + 1))
    os.mkfifo(applications / "special.desktop")

    environment = os.environ.copy()
    environment["XDG_DATA_HOME"] = str(data_home)
    environment["XDG_DATA_DIRS"] = str(tmp_path / "system")
    source = Path(__file__).resolve().parents[1] / "src"
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(source), environment.get("PYTHONPATH", "")) if part
    )
    script = "import json; from taskpup.platform import desktop_icons; print(json.dumps(desktop_icons()))"
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
        timeout=3,
        env=environment,
    )
    assert json.loads(result.stdout) == {"scanner-fixture": "scanner-fixture-icon"}


def test_desktop_icons_skips_unreadable_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data_home = tmp_path / "data"
    applications = data_home / "applications"
    applications.mkdir(parents=True)
    unreadable = applications / "unreadable.desktop"
    unreadable.write_text(
        "[Desktop Entry]\nType=Application\nName=Hidden\nExec=/usr/bin/hidden\nIcon=hidden-icon\n",
        encoding="utf-8",
    )
    valid = applications / "valid.desktop"
    valid.write_text(
        "[Desktop Entry]\nType=Application\nName=Valid\nExec=/usr/bin/valid-app\nIcon=valid-icon\n",
        encoding="utf-8",
    )
    real_open = os.open

    def deny_open(path, flags, *args, **kwargs):
        if Path(path) == unreadable:
            raise PermissionError(errno.EACCES, "Permission denied", str(unreadable))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
    monkeypatch.setenv("XDG_DATA_DIRS", str(tmp_path / "system"))
    monkeypatch.setattr(os, "open", deny_open)
    assert desktop_icons() == {"valid-app": "valid-icon"}
