"""Application entry point and lifecycle."""

import os
import sys

from PySide6.QtCore import QStandardPaths
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from taskpup.platform import logo_path
from taskpup.style import apply_style
from taskpup.window import MainWindow


def main() -> int:
    if os.getuid() == 0 or os.geteuid() == 0:
        print("TaskPup must be started from a regular user account.", file=sys.stderr)
        return 1
    # The portal needs an installed desktop entry and Qt reads the ID at startup.
    if QStandardPaths.locate(QStandardPaths.StandardLocation.ApplicationsLocation, "taskpup.desktop"):
        QApplication.setDesktopFileName("taskpup")
    app = QApplication(sys.argv)
    app.setApplicationName("TaskPup")
    app.setOrganizationName("TaskPup")
    icon_path = os.environ.get("TASKPUP_APPIMAGE_ICON") or str(logo_path())
    app.setWindowIcon(QIcon(icon_path))
    apply_style(app)
    window = MainWindow()
    window.show()
    return app.exec()
