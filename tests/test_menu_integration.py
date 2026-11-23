from pathlib import Path
import os
import shutil
import subprocess
import time

import pytest

from taskpup import menu_integration


@pytest.fixture
def image_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    image = tmp_path / 'Task Pup =$`"% \\ demo.AppImage'
    image.write_bytes(b"executable")
    image.chmod(0o755)
    icon = tmp_path / "icon.png"
    icon.write_bytes(b"fixture icon")
    monkeypatch.setenv("APPIMAGE", str(image))
    monkeypatch.setenv("TASKPUP_APPIMAGE_ICON", str(icon))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_DATA_DIRS", str(tmp_path / "system"))
    monkeypatch.delenv("APPDIR", raising=False)
    monkeypatch.delenv("DESKTOPINTEGRATION", raising=False)
    monkeypatch.setattr(menu_integration.psutil, "process_iter", lambda *_: [])
    return image, icon, tmp_path / "data"


def test_development_mode_does_not_create_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APPIMAGE", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    with pytest.raises(menu_integration.MenuIntegrationError, match="only from an executable AppImage"):
        menu_integration.install_appimage_menu()
    assert not (tmp_path / "data").exists()


def test_launcher_and_icon_are_persistent_and_valid(image_environment) -> None:
    image, icon, data = image_environment
    desktop = menu_integration.install_appimage_menu()
    text = desktop.read_text()
    assert 'Exec=/bin/sh -c ' in text and "%%" in text
    assert f"Icon={data / 'icons/hicolor/256x256/apps/taskpup-appimage.png'}\n" in text
    assert "StartupWMClass=TaskPup" in text
    assert (data / "icons/hicolor/256x256/apps/taskpup-appimage.png").read_bytes() == icon.read_bytes()
    assert str(image.parent) in text
    validator = shutil.which("desktop-file-validate")
    if validator:
        subprocess.run([validator, str(desktop)], check=True, capture_output=True, text=True)
    with pytest.raises(menu_integration.MenuIntegrationError):
        menu_integration.install_appimage_menu()


def test_custom_data_home_icon_path_round_trips_in_desktop_entry(image_environment, monkeypatch: pytest.MonkeyPatch) -> None:
    import ctypes
    import ctypes.util

    _, icon, data = image_environment
    custom = data.parent / 'custom data $% "quote" \\ folder'
    monkeypatch.setenv("XDG_DATA_HOME", str(custom))
    desktop = menu_integration.install_appimage_menu()
    installed = custom / "icons/hicolor/256x256/apps/taskpup-appimage.png"
    assert installed.is_absolute() and installed.read_bytes() == icon.read_bytes()
    validator = shutil.which("desktop-file-validate")
    if validator:
        subprocess.run([validator, str(desktop)], check=True, capture_output=True, text=True)

    # GLib is the desktop entry parser used by the target desktop environment.
    library = ctypes.util.find_library("glib-2.0")
    if not library:
        pytest.skip("GLib is unavailable")
    glib = ctypes.CDLL(library)
    glib.g_key_file_new.restype = ctypes.c_void_p
    glib.g_key_file_load_from_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    glib.g_key_file_get_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p]
    glib.g_key_file_get_string.restype = ctypes.c_void_p
    glib.g_key_file_unref.argtypes = [ctypes.c_void_p]
    glib.g_free.argtypes = [ctypes.c_void_p]
    keyfile = glib.g_key_file_new()
    try:
        assert glib.g_key_file_load_from_file(keyfile, os.fsencode(desktop), 0, None)
        value = glib.g_key_file_get_string(keyfile, b"Desktop Entry", b"Icon", None)
        assert value
        try:
            assert os.fsdecode(ctypes.string_at(value)) == str(installed)
        finally:
            glib.g_free(value)
    finally:
        glib.g_key_file_unref(keyfile)


def test_desktop_launcher_executes_special_character_path(image_environment, monkeypatch: pytest.MonkeyPatch) -> None:
    gio = shutil.which("gio")
    if not gio:
        pytest.skip("gio is unavailable")
    image, _, data = image_environment
    marker = data.parent / "launched"
    image.write_text('#!/bin/sh\nprintf ok > "$TASKPUP_MENU_TEST_MARKER"\n')
    monkeypatch.setenv("TASKPUP_MENU_TEST_MARKER", str(marker))
    desktop = menu_integration.install_appimage_menu()
    subprocess.run([gio, "launch", str(desktop)], check=True, capture_output=True, timeout=5)
    deadline = time.monotonic() + 3
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert marker.read_text() == "ok"


def test_existing_manual_launcher_is_preserved(image_environment) -> None:
    _, _, data = image_environment
    applications = data / "applications"
    applications.mkdir(parents=True)
    existing = applications / "manual.desktop"
    existing.write_text("[Desktop Entry]\nName=TaskPup\nExec=/other\n")
    with pytest.raises(menu_integration.MenuIntegrationError, match="existing TaskPup launcher"):
        menu_integration.install_appimage_menu()
    assert existing.read_text() == "[Desktop Entry]\nName=TaskPup\nExec=/other\n"
    assert not (applications / "taskpup-appimage.desktop").exists()


def test_system_launcher_conflict_and_own_appdir(image_environment, monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, data = image_environment
    system_apps = data.parent / "system/applications"
    system_apps.mkdir(parents=True)
    launcher = system_apps / "taskpup.desktop"
    launcher.write_text("[Desktop Entry]\nName=TaskPup\nExec=/other\n")
    with pytest.raises(menu_integration.MenuIntegrationError, match="existing TaskPup launcher"):
        menu_integration.install_appimage_menu()
    assert not data.exists()
    monkeypatch.setenv("APPDIR", str(data.parent / "mount"))
    monkeypatch.setenv("XDG_DATA_DIRS", str(data.parent / "mount/usr/share"))
    own_apps = data.parent / "mount/usr/share/applications"
    own_apps.mkdir(parents=True)
    (own_apps / "taskpup.desktop").write_text(launcher.read_text())
    assert menu_integration.install_appimage_menu().is_file()


def test_existing_desktop_conflict_preserves_new_icon_and_reports_recovery(image_environment) -> None:
    _, _, data = image_environment
    applications = data / "applications"
    applications.mkdir(parents=True)
    existing = applications / "taskpup-appimage.desktop"
    existing.write_text("not a desktop entry")
    icon = data / "icons/hicolor/256x256/apps/taskpup-appimage.png"
    with pytest.raises(menu_integration.MenuIntegrationError) as raised:
        menu_integration.install_appimage_menu()
    assert existing.read_text() == "not a desktop entry"
    assert icon.is_file()
    assert str(existing) in str(raised.value)
    assert str(icon) in str(raised.value)
    assert "Manual recovery" in str(raised.value)
    assert "verify" in str(raised.value)


def test_partial_icon_write_is_preserved_and_reported(image_environment, monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, data = image_environment
    icon_target = data / "icons/hicolor/256x256/apps/taskpup-appimage.png"
    real_open = Path.open

    class FailingWriter:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def write(self, content: bytes) -> int:
            self.stream.write(content[:3])
            self.stream.flush()
            raise OSError("injected disk-full failure")

    def failing_open(path: Path, *args, **kwargs):
        stream = real_open(path, *args, **kwargs)
        if path == icon_target and args and args[0] == "xb":
            return FailingWriter(stream)
        return stream

    monkeypatch.setattr(Path, "open", failing_open)
    with pytest.raises(menu_integration.MenuIntegrationError) as raised:
        menu_integration.install_appimage_menu()
    assert icon_target.read_bytes() == b"fix"
    assert str(icon_target) in str(raised.value)
    assert "Manual recovery" in str(raised.value)
    assert not (data / "applications/taskpup-appimage.desktop").exists()


def test_partial_launcher_write_reports_both_preserved_files(image_environment, monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, data = image_environment
    icon_target = data / "icons/hicolor/256x256/apps/taskpup-appimage.png"
    desktop = data / "applications/taskpup-appimage.desktop"
    real_open = Path.open

    class FailingWriter:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self) -> int:
            return self.stream.fileno()

        def write(self, content: str) -> int:
            self.stream.write(content[:12])
            self.stream.flush()
            raise OSError("injected disk-full failure")

    def failing_open(path: Path, *args, **kwargs):
        stream = real_open(path, *args, **kwargs)
        if path == desktop and args and args[0] == "x":
            return FailingWriter(stream)
        return stream

    monkeypatch.setattr(Path, "open", failing_open)
    with pytest.raises(menu_integration.MenuIntegrationError) as raised:
        menu_integration.install_appimage_menu()
    message = str(raised.value)
    assert icon_target.is_file()
    assert desktop.read_text() == "[Desktop Ent"
    assert str(icon_target) in message
    assert str(desktop) in message
    assert "Manual recovery" in message


def test_replaced_files_survive_later_launcher_conflict(image_environment, monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, data = image_environment
    icon_target = data / "icons/hicolor/256x256/apps/taskpup-appimage.png"
    desktop = data / "applications/taskpup-appimage.desktop"
    real_open = Path.open

    def conflict_after_icon(path: Path, *args, **kwargs):
        if path == desktop and args and args[0] == "x":
            replacement = data / "replacement-icon.png"
            replacement.write_bytes(b"replacement icon")
            os.replace(replacement, icon_target)
            desktop.write_text("racing user-created launcher")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", conflict_after_icon)

    def forbidden_unlink(path: Path, *args, **kwargs):
        pytest.fail(f"installer attempted destructive rollback: {path}")

    monkeypatch.setattr(Path, "unlink", forbidden_unlink)
    with pytest.raises(menu_integration.MenuIntegrationError) as raised:
        menu_integration.install_appimage_menu()
    assert icon_target.read_bytes() == b"replacement icon"
    assert desktop.read_text() == "racing user-created launcher"
    assert str(icon_target) in str(raised.value)
    assert str(desktop) in str(raised.value)
    assert "Manual recovery" in str(raised.value)


def test_opt_out_and_existing_icon_are_respected(image_environment, monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, data = image_environment
    monkeypatch.setenv("DESKTOPINTEGRATION", "manager")
    with pytest.raises(menu_integration.MenuIntegrationError, match="disabled"):
        menu_integration.install_appimage_menu()
    monkeypatch.delenv("DESKTOPINTEGRATION")
    target = data / "icons/hicolor/256x256/apps/taskpup-appimage.png"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"existing")
    with pytest.raises(menu_integration.MenuIntegrationError):
        menu_integration.install_appimage_menu()
    assert target.read_bytes() == b"existing"
