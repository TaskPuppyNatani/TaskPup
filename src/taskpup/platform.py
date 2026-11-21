"""Linux desktop integration."""

from configparser import ConfigParser, Error
import os
from pathlib import Path
import shlex

from PySide6.QtCore import QProcess, QUrl
from PySide6.QtGui import QDesktopServices
import psutil

from taskpup.management import ProcessActionError, check_identity
from taskpup.processes import Identity


def logo_path() -> Path:
    packaged = Path(__file__).with_name("TaskPuppyLogo.png")
    if packaged.is_file():
        return packaged
    return Path(__file__).parents[2] / "assets" / packaged.name


def desktop_icons() -> dict[str, str]:
    user_data = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local/share")
    system_data = os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share"
    icons: dict[str, str] = {}
    seen: set[str] = set()
    for directory in (user_data, *system_data.split(":")):
        applications = Path(directory) / "applications"
        if not applications.is_absolute():
            continue
        for path in sorted(applications.glob("**/*.desktop")):
            desktop_id = "-".join(path.relative_to(applications).parts)
            if desktop_id in seen:
                continue
            parser = ConfigParser(interpolation=None, strict=False)
            try:
                with path.open(encoding="utf-8") as stream:
                    parser.read_file(stream)
                entry = parser["Desktop Entry"]
            except (OSError, UnicodeError, Error, KeyError):
                continue
            seen.add(desktop_id)
            icon = entry.get("Icon", "")
            if not icon or entry.get("Hidden", "").lower() == "true":
                continue
            for key in ("Exec", "TryExec"):
                try:
                    args = shlex.split(entry.get(key, ""))
                except ValueError:
                    continue
                if args:
                    program = Path(args[0]).name
                    if program not in {"env", "flatpak", "sh", "bash", "snap"}:
                        icons.setdefault(program, icon)
    return icons


def open_executable_location(identity: Identity) -> None:
    check_identity(identity)
    try:
        executable = psutil.Process(identity.pid).exe()
    except psutil.ZombieProcess as error:
        raise ProcessActionError("The process has already exited.") from error
    except psutil.AccessDenied as error:
        raise ProcessActionError("Permission denied when reading the executable.") from error
    except psutil.NoSuchProcess as error:
        raise ProcessActionError("The process is no longer available.") from error
    check_identity(identity)
    if not os.path.isabs(executable):
        raise ProcessActionError("The executable location is unavailable.")
    directory = str(Path(executable).parent)
    if not QDesktopServices.openUrl(QUrl.fromLocalFile(directory)):
        raise ProcessActionError(f"The file manager could not open {directory}.")


def online_cpus() -> set[int]:
    ranges = Path("/sys/devices/system/cpu/online").read_text().strip()
    cpus: set[int] = set()
    for interval in ranges.split(","):
        first, _, last = interval.partition("-")
        cpus.update(range(int(first), int(last or first) + 1))
    return cpus


def start_task(command: str) -> None:
    try:
        args = shlex.split(command)
    except ValueError as error:
        raise ProcessActionError(f"Invalid command line. {error}") from error
    if not args or not args[0] or any("\x00" in arg for arg in args):
        raise ProcessActionError("Enter a valid executable and any arguments.")
    started, _ = QProcess.startDetached(args[0], args[1:], str(Path.home()))
    if not started:
        raise ProcessActionError(f"Could not start {args[0]}. Check the name and permissions.")
