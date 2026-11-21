import os

import pytest
from PySide6.QtWidgets import QApplication

from taskpup.style import apply_style


@pytest.fixture(scope="session")
def qt_app() -> QApplication:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    application = QApplication([])
    apply_style(application)
    return application
