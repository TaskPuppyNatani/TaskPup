import threading
import time
from pathlib import Path

from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox

from taskpup import report_dialog
from taskpup.report_dialog import ReportDialog


def wait_until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 20)
        time.sleep(0.005)
    assert predicate()


def test_dialog_defaults_and_background_export(qt_app, tmp_path, monkeypatch):
    destination = tmp_path / "diagnostics"
    calls = []
    started = threading.Event()
    release = threading.Event()

    def export(selected, private, path, format_name, overwrite, screens):
        calls.append((selected, private, path, format_name, overwrite, screens))
        started.set()
        assert release.wait(3)

    monkeypatch.setattr(report_dialog, "export_report", export)
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **kw: (str(destination), ""))
    messages = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a: messages.append(a[1]))
    dialog = ReportDialog()
    dialog.show()
    try:
        assert dialog.privacy.isChecked()
        for box in dialog.sections.values():
            box.setChecked(False)
        assert not dialog.generate.isEnabled()
        first = next(iter(dialog.sections))
        dialog.sections[first].setChecked(True)
        dialog.format.setCurrentText("JSON Lines (.jsonl)")
        dialog.start_export()
        wait_until(started.is_set)
        assert calls[0][:5] == ({first}, True, Path(str(destination) + ".jsonl"), "jsonl", False)
        assert not dialog.generate.isEnabled()
        assert not dialog.privacy.isEnabled() and not dialog.format.isEnabled()
        assert all(not box.isEnabled() for box in dialog.sections.values())
        ticks = []
        QTimer.singleShot(0, lambda: ticks.append(True))
        wait_until(lambda: bool(ticks))
        release.set()
        wait_until(lambda: bool(messages))
        assert dialog.generate.isEnabled()
        assert dialog.privacy.isEnabled() and dialog.format.isEnabled()
    finally:
        release.set()
        dialog.close()


def test_dialog_reports_export_failure(qt_app, tmp_path, monkeypatch):
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **kw: (str(tmp_path / "a.md"), ""))
    def fail(*args):
        raise OSError("fixture failure")
    monkeypatch.setattr(report_dialog, "export_report", fail)
    messages = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a: messages.append(a[2]))
    dialog = ReportDialog()
    try:
        dialog.start_export()
        wait_until(lambda: bool(messages))
        assert "fixture failure" in messages[0]
    finally:
        dialog.close()


def test_full_diagnostics_requires_confirmation(qt_app, monkeypatch):
    calls = []
    monkeypatch.setattr(QMessageBox, "question", lambda *args: calls.append(args) or QMessageBox.StandardButton.No)
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("save dialog opened")))
    dialog = ReportDialog()
    try:
        assert dialog.privacy.isChecked()
        assert "JSON (.json)" in [dialog.format.itemText(i) for i in range(dialog.format.count())]
        dialog.privacy.setChecked(False)
        dialog.start_export()
        assert len(calls) == 1 and "Full diagnostics may include usernames" in calls[0][2]
        assert dialog.future is None
        monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.StandardButton.Yes)
        save_calls = []
        monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **kw: (save_calls.append(True) or "", ""))
        dialog.start_export()
        assert save_calls == [True] and dialog.future is None
    finally:
        dialog.close()
