"""User-initiated diagnostic export without blocking the Qt event loop."""

from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QGridLayout, QHBoxLayout,
    QLabel, QMessageBox, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from taskpup.report_collect import SECTIONS, collect_report
from taskpup.report_render import write_report


FORMATS = {
    "Markdown (.md)": ("md", "Markdown (*.md)"),
    "JSON Lines (.jsonl)": ("jsonl", "JSON Lines (*.jsonl)"),
    "HTML (.html)": ("html", "HTML (*.html)"),
    "All formats (.zip)": ("zip", "ZIP archive (*.zip)"),
}


def export_report(
    selected: set[str], private: bool, path: Path, format_name: str, overwrite: bool,
    screens: list[dict[str, int | float]],
) -> None:
    snapshot = collect_report(selected, private, screen_info=screens)
    write_report(snapshot, path, format_name, overwrite=overwrite)


class ReportDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Export System Report")
        self.resize(590, 570)
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="taskpup-report")
        self.future: Future[None] | None = None
        layout = QVBoxLayout(self)
        intro = QLabel("Choose the sections and format for a read-only system report.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        options = QVBoxLayout(content)
        options.addWidget(QLabel("Report sections"))
        grid = QGridLayout()
        self.sections: dict[str, QCheckBox] = {}
        for index, (key, label) in enumerate(SECTIONS.items()):
            checkbox = QCheckBox(label)
            checkbox.setChecked(True)
            checkbox.toggled.connect(self.update_summary)
            self.sections[key] = checkbox
            grid.addWidget(checkbox, index // 2, index % 2)
        options.addLayout(grid)
        options.addWidget(QLabel("Export format"))
        self.format = QComboBox()
        self.format.addItems(list(FORMATS))
        self.format.currentIndexChanged.connect(self.update_summary)
        options.addWidget(self.format)
        self.privacy = QCheckBox("Protect identifying information (recommended)")
        self.privacy.setChecked(True)
        self.privacy.toggled.connect(self.update_summary)
        options.addWidget(self.privacy)
        warning = QLabel("Disabling protection includes additional identifiers. Passwords, tokens and private keys are never intentionally included. Automated redaction cannot guarantee removal of every sensitive value. Review the report before sharing it.")
        warning.setWordWrap(True)
        options.addWidget(warning)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        options.addWidget(self.summary)
        options.addStretch()
        scroll.setWidget(content)
        layout.addWidget(scroll, 1)
        buttons = QHBoxLayout()
        buttons.addStretch()
        self.cancel = QPushButton("Close")
        self.cancel.clicked.connect(self.reject)
        self.generate = QPushButton("Choose destination and export…")
        self.generate.setObjectName("primary")
        self.generate.clicked.connect(self.start_export)
        buttons.addWidget(self.cancel)
        buttons.addWidget(self.generate)
        layout.addLayout(buttons)
        self.poll = QTimer(self)
        self.poll.setInterval(50)
        self.poll.timeout.connect(self.finish_export)
        self.update_summary()

    def update_summary(self, *_: object) -> None:
        selected = [box.text() for box in self.sections.values() if box.isChecked()]
        state = "enabled" if self.privacy.isChecked() else "disabled: identifying details may be included"
        self.summary.setText(f"Sections: {', '.join(selected) if selected else 'none'}\nFormat: {self.format.currentText()}\nPrivacy protection: {state}")
        self.generate.setEnabled(bool(selected) and self.future is None)

    def start_export(self) -> None:
        selected = {key for key, box in self.sections.items() if box.isChecked()}
        if not selected or self.future is not None:
            return
        extension, file_filter = FORMATS[self.format.currentText()]
        name = f"taskpup-system-report-{datetime.now(timezone.utc):%Y%m%d-%H%M%S-utc}.{extension}"
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export System Report", name, file_filter,
            options=QFileDialog.Option.DontConfirmOverwrite,
        )
        if not filename:
            return
        path = Path(filename)
        if path.suffix.lower() != f".{extension}":
            path = path.with_name(path.name + f".{extension}")
        overwrite = path.exists()
        if overwrite and QMessageBox.question(
            self, "Replace report?", f"Replace the existing file {path.name}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        screens = [
            {"width": screen.geometry().width(), "height": screen.geometry().height(),
             "scale": screen.devicePixelRatio()}
            for screen in QApplication.screens()
        ]
        self.future = self.executor.submit(export_report, selected, self.privacy.isChecked(), path, extension, overwrite, screens)
        self.generate.setEnabled(False)
        self.cancel.setEnabled(False)
        self.format.setEnabled(False)
        self.privacy.setEnabled(False)
        for box in self.sections.values():
            box.setEnabled(False)
        self.summary.setText("Collecting and exporting the report…")
        self.poll.start()

    def finish_export(self) -> None:
        if self.future is None or not self.future.done():
            return
        future, self.future = self.future, None
        self.poll.stop()
        self.cancel.setEnabled(True)
        self.format.setEnabled(True)
        self.privacy.setEnabled(True)
        for box in self.sections.values():
            box.setEnabled(True)
        self.update_summary()
        try:
            future.result()
        except Exception as error:
            QMessageBox.warning(self, "Export failed", f"The report could not be exported: {error}")
        else:
            QMessageBox.information(self, "Report exported", "The system report was saved. Review it before sharing.")

    def reject(self) -> None:
        if self.future is None:
            self.executor.shutdown(wait=False, cancel_futures=True)
            super().reject()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.future is not None:
            event.ignore()
            return
        self.executor.shutdown(wait=False, cancel_futures=True)
        super().closeEvent(event)
