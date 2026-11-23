"""Explicit, user-local AppImage menu integration."""

from configparser import ConfigParser, Error
import os
from pathlib import Path
import psutil

from taskpup.platform import DesktopEntryTooLarge, _read_regular_desktop_entry


class MenuIntegrationError(Exception):
    """An integration failure suitable for display to the user."""


def _failure_message(reason: str, preserved_paths: list[Path]) -> str:
    if not preserved_paths:
        return (
            f"{reason}\nNo destination files were created by this attempt. "
            "Existing files were left untouched."
        )
    locations = "\n".join(f"  {path}" for path in preserved_paths)
    return (
        f"{reason}\nThese destination paths may contain files created or encountered "
        f"during this attempt, and they were left untouched:\n{locations}\n"
        "Manual recovery: inspect each listed path. Remove a file only if you can "
        "verify it is a partial file created by this failed attempt. Keep any file "
        "that existed before the attempt or may have been replaced by another "
        "process, then retry after resolving the conflict."
    )


def _exec_arg(path: str) -> str:
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise MenuIntegrationError("The AppImage path contains characters unsupported by desktop launchers.")
    # Desktop-entry string escaping is applied before Exec argument unquoting.
    encoded = path.replace("\\", "\\\\\\\\").replace('"', '\\\\"').replace("`", "\\\\`").replace("$", "\\\\$").replace("%", "%%")
    return f'"{encoded}"'


def install_appimage_menu() -> Path:
    """Install new files only; never replace an existing launcher or icon."""
    image_value = os.environ.get("APPIMAGE", "")
    icon_value = os.environ.get("TASKPUP_APPIMAGE_ICON", "")
    image, icon = Path(image_value), Path(icon_value)
    if not image_value or not image.is_absolute() or not image.is_file() or not os.access(image, os.X_OK):
        raise MenuIntegrationError("Application-menu integration is available only from an executable AppImage.")
    if not icon_value or not icon.is_absolute() or not icon.is_file():
        raise MenuIntegrationError("The bundled AppImage icon is unavailable.")
    exec_value = _exec_arg(str(image))
    shell_command = _exec_arg('exec "$1"')
    data_value = os.environ.get("XDG_DATA_HOME", "")
    data_home = Path(data_value) if data_value and Path(data_value).is_absolute() else Path.home() / ".local/share"
    markers = (data_home / "appimagekit/no_desktopintegration", Path("/etc/appimagekit/no_desktopintegration"), Path("/usr/share/appimagekit/no_desktopintegration"))
    if os.environ.get("DESKTOPINTEGRATION") or any(marker.exists() for marker in markers):
        raise MenuIntegrationError("AppImage desktop integration is disabled by the desktop environment or user settings.")
    for process in psutil.process_iter(["name"]):
        try:
            if process.info.get("name") == "appimaged":
                raise MenuIntegrationError("An AppImage integration manager is running; use it to manage the launcher.")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    applications = data_home / "applications"
    icon_dir = data_home / "icons/hicolor/256x256/apps"
    desktop = applications / "taskpup-appimage.desktop"
    icon_target = icon_dir / "taskpup-appimage.png"
    if any(ord(char) < 32 or ord(char) == 127 for char in str(icon_target)):
        raise MenuIntegrationError("The icon destination contains characters unsupported by desktop launchers.")
    icon_value = str(icon_target).replace("\\", "\\\\")
    try:
        # Do not duplicate a manual or integration-manager TaskPup launcher.
        data_dirs = os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share"
        appdir = os.environ.get("APPDIR", "")
        roots = [applications] + [Path(path) / "applications" for path in data_dirs.split(":") if path and Path(path).is_absolute() and (not appdir or Path(path) != Path(appdir) / "usr/share")]
        for entry in (item for root in roots for item in root.glob("*.desktop")):
            parser = ConfigParser(interpolation=None, strict=False)
            try:
                try:
                    content = _read_regular_desktop_entry(entry)
                except DesktopEntryTooLarge as error:
                    raise MenuIntegrationError(
                        _failure_message(
                            f"Cannot check oversized desktop entry: {entry}. Review it before installing.",
                            [],
                        )
                    ) from error
                except OSError as error:
                    if isinstance(error, FileNotFoundError) and not entry.is_symlink():
                        continue
                    raise MenuIntegrationError(
                        _failure_message(
                            f"Could not read existing desktop entry {entry} during conflict check: {error}. "
                            "Fix its permissions or remove the unreadable entry, then retry.",
                            [],
                        )
                    ) from error
                if content is None:
                    continue
                parser.read_string(content)
                section = parser["Desktop Entry"]
                existing_exec = section.get("Exec", "")
                if (section.get("Name", "").strip().casefold() == "taskpup"
                        or section.get("X-AppImage-Name", "").strip().casefold() == "taskpup"
                        or image_value in existing_exec or exec_value in existing_exec):
                    raise MenuIntegrationError(f"An existing TaskPup launcher was found: {entry}. It was not changed.")
            except (Error, KeyError, UnicodeError):
                continue
        icon_bytes = icon.read_bytes()
        applications.mkdir(parents=True, exist_ok=True)
        icon_dir.mkdir(parents=True, exist_ok=True)
        icon_created = False
        try:
            with icon_target.open("xb") as output:
                icon_created = True
                output.write(icon_bytes)
        except OSError as error:
            if isinstance(error, FileExistsError) and not icon_created:
                reason = f"The icon destination already exists and was not changed: {icon_target}."
                raise MenuIntegrationError(_failure_message(reason, [])) from error
            reason = f"Could not write the application icon at {icon_target}: {error}"
            raise MenuIntegrationError(
                _failure_message(reason, [icon_target] if icon_created else [])
            ) from error

        text = ("[Desktop Entry]\nType=Application\nName=TaskPup\n"
                "GenericName=Linux process and system manager\n"
                "Comment=Monitor and manage Linux processes, system services, and hardware\n"
                f"Exec=/bin/sh -c {shell_command} taskpup {exec_value}\nIcon={icon_value}\n"
                "Terminal=false\nCategories=System;Monitor;\nStartupNotify=true\nStartupWMClass=TaskPup\n")
        desktop_created = False
        try:
            with desktop.open("x", encoding="utf-8") as output:
                desktop_created = True
                output.write(text)
        except OSError as error:
            if isinstance(error, FileExistsError) and not desktop_created:
                reason = f"The launcher destination already exists and was not changed: {desktop}."
            else:
                reason = f"Could not write the application launcher at {desktop}: {error}"
            preserved = [icon_target]
            if desktop_created:
                preserved.append(desktop)
            raise MenuIntegrationError(_failure_message(reason, preserved)) from error
    except MenuIntegrationError:
        raise
    except OSError as error:
        raise MenuIntegrationError(
            _failure_message(f"Could not prepare menu integration: {error}", [])
        ) from error
    return desktop
