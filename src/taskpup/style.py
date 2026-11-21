"""TaskPup's application palette and widget styling."""

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication


def apply_style(app: QApplication) -> None:
    app.setStyle("Fusion")
    palette = QPalette()
    colors = {
        QPalette.ColorRole.Window: "#19181e",
        QPalette.ColorRole.WindowText: "#f1eef7",
        QPalette.ColorRole.Base: "#18171d",
        QPalette.ColorRole.AlternateBase: "#1e1c24",
        QPalette.ColorRole.Text: "#edeaf4",
        QPalette.ColorRole.Button: "#282533",
        QPalette.ColorRole.ButtonText: "#f1eef7",
        QPalette.ColorRole.Highlight: "#633c91",
        QPalette.ColorRole.HighlightedText: "#ffffff",
        QPalette.ColorRole.Link: "#d0a7ff",
        QPalette.ColorRole.PlaceholderText: "#a9a1b5",
        QPalette.ColorRole.ToolTipBase: "#292633",
        QPalette.ColorRole.ToolTipText: "#f1eef7",
    }
    for role, color in colors.items():
        palette.setColor(role, QColor(color))
    for role in (QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText, QPalette.ColorRole.WindowText):
        palette.setColor(QPalette.ColorGroup.Disabled, role, QColor("#a19aaa"))
    app.setPalette(palette)
    app.setStyleSheet("""
        QMainWindow, QDialog { background: #19181e; }
        QLabel#brand { color: #f7f2ff; font-size: 26px; font-weight: 700; }
        QLabel#brandTagline { color: #c4b0d8; font-size: 13px; font-weight: 500; }
        QLabel#section { font-size: 17px; font-weight: 700; }
        QLabel#count, QLabel#metricTitle { color: #c4bdcf; }
        QFrame#metric { background: #222029; border: 1px solid #373142; border-radius: 8px; }
        QLabel#metricValue { font-size: 23px; font-weight: 700; color: #f3edff; }
        QProgressBar { background: #36303f; border: 0; border-radius: 2px; }
        QProgressBar::chunk { background: #cb94ff; border-radius: 2px; }
        QProgressBar#secondary::chunk { background: #8fe7ac; }
        QLineEdit, QSpinBox, QComboBox {
            border: 1px solid #494054; border-radius: 6px; padding: 6px 9px; min-height: 18px;
            background: #1b1921;
        }
        QPushButton {
            border: 1px solid #4b425a; border-radius: 6px; padding: 6px 10px;
            background: #282533; min-height: 18px;
        }
        QPushButton:hover { background: #363043; border-color: #7d628e; }
        QPushButton:pressed { background: #473456; }
        QPushButton:disabled { background: #231f2a; border-color: #3a3344; }
        QPushButton#primary { background: #d0a0ff; color: #20132e; border-color: #d0a0ff; font-weight: 700; }
        QPushButton#primary:hover { background: #e1beff; }
        QPushButton#danger { color: #ffc1cd; border-color: #8a5062; background: #38252e; }
        QPushButton#danger:hover { background: #503040; }
        QPushButton#danger:disabled { color: #ad9aa2; border-color: #46343c; background: #251f26; }
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPushButton:focus {
            border: 2px solid #c595fa;
        }
        QTreeView { border: 1px solid #3d3549; font-size: 13px; }
        QTreeView::item { min-height: 27px; padding: 1px 5px; }
        QTreeView::item:selected { background: #623c8c; color: #ffffff; }
        QHeaderView::section {
            background: #2a2533; color: #e7ddf3; border: 0;
            border-bottom: 1px solid #463a53; padding: 7px 5px; font-weight: 600;
        }
        QHeaderView::section:hover { background: #383043; }
        QMenu { background: #24212c; border: 1px solid #514360; padding: 4px; }
        QMenu::item { padding: 6px 23px; }
        QMenu::item:selected { background: #56377a; color: white; }
        QStatusBar { color: #c4bdcf; background: #19181e; }
    """)
