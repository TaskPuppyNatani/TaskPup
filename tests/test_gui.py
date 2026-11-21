from collections.abc import Callable
from dataclasses import replace
import os
from pathlib import Path
import shlex
import signal
import sys
from threading import Event, get_ident
import time

import pytest
from PySide6.QtCore import QEventLoop, QItemSelectionModel, QObject, QPoint, QSettings, Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel, QPushButton

from taskpup import app, dialogs, management
from taskpup.metrics import MemorySample, SwapSample, SystemSample, SystemSampler
from taskpup.model import ProcessModel
from taskpup.platform import start_task
from taskpup.processes import Identity, ProcessRow, ProcStat, Resources, Snapshot
from taskpup.refresh import RefreshController
from taskpup.settings import Settings
from taskpup.window import MainWindow


@pytest.fixture
def window(qt_app: QApplication, tmp_path: Path):
    settings = Settings(QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat))
    window = MainWindow(settings)
    window.show()
    try:
        yield window
    finally:
        window.close()


def wait_for(condition: Callable[[], bool], timeout: float = 3) -> None:
    if condition():
        return
    loop = QEventLoop()
    poll = QTimer()
    poll.setInterval(10)
    deadline = time.monotonic() + timeout

    def check() -> None:
        if condition() or time.monotonic() >= deadline:
            loop.quit()

    poll.timeout.connect(check)
    poll.start()
    loop.exec()
    assert condition(), "Timed out waiting for the Qt event"


def row(pid: int, name: str, *, parent: int = 0, uid: int = 1000, start: int = 1) -> ProcessRow:
    stat = ProcStat(Identity(pid, start), name, "S", parent, 0, 0, 0, 1, pid * 1024)
    return ProcessRow(stat, uid, f"owner-{uid}", float(pid), "/test/bin/example", f"{name} --sample")


def snapshot(*rows: ProcessRow) -> Snapshot:
    return Snapshot(rows, Resources(20.5, 43.3, None))


def system_reading(logical: dict[int, float | None] | None = None) -> SystemSample:
    cores: dict[int, float | None] = logical if logical is not None else {0: 7.5, 2: 25.4}
    return SystemSample(
        time.monotonic(), 15.2, cores, "Test CPU", 3200.0, 2, len(cores), None, 1200.0,
        MemorySample(1024**3, 512 * 1024**2, 512 * 1024**2, 50.0, None, None),
        SwapSample(0, 0, 0, None, None, None),
    )


def test_performance_navigation_retains_process_state_and_history(window: MainWindow) -> None:
    window.refresh.stop()
    target = row(311, "editor", uid=os.getuid())
    window.apply_snapshot(snapshot(target, row(312, "worker", uid=os.getuid())))
    window.search.setText("editor")
    window.view.setCurrentIndex(window.model.index_for(target.identity))
    window.apply_performance(system_reading())
    dashboard = window.performance

    window.navigation.setCurrentIndex(1)
    assert dashboard.isVisible() and dashboard.statistics[0]["Utilization"].text() == "15.2%"
    QApplication.processEvents()
    assert all(card.rect().contains(card.graph.geometry()) for card in dashboard.cards)
    dashboard.logical_mode.click()
    assert set(dashboard.logical_tiles) == {0, 2}
    tile = dashboard.logical_tiles[2][0]
    dashboard.cards[1].click()
    window.apply_performance(system_reading({2: None, 4: 11.0}))
    assert dashboard.statistics[1]["Used"].text() == "512.0 MiB"
    dashboard.cards[0].click()
    assert set(dashboard.logical_tiles) == {2, 4} and dashboard.logical_tiles[2][0] is tile
    assert dashboard.logical_histories[2].samples[-1][1] is None
    dashboard.cards[2].click()
    assert dashboard.subtitles[2].text() == "No swap configured"
    assert dashboard.statistics[2]["Utilization"].text() == "Unavailable"
    assert [value for _, value in dashboard.histories[2].samples] == [None, None]

    window.navigation.setCurrentIndex(0)
    assert window.selected() == target and window.search.text() == "editor"
    window.navigation.setCurrentIndex(1)
    assert dashboard.details.currentIndex() == 2 and len(dashboard.histories[0].samples) == 2


def test_performance_pause_and_settings_survive_reopening(window: MainWindow) -> None:
    window.refresh.stop()
    page = window.performance
    page.record_sample(system_reading())
    page.pause.click()
    held = page.histories[0].samples
    assert page.state.text() == "Paused" and held[-1][1] is None
    page.record_sample(system_reading())
    assert page.histories[0].samples == held
    page.pause.click()
    page.record_sample(system_reading())
    assert page.state.text() == "Live" and page.histories[0].samples[-1][1] == 15.2

    page.duration_box.setCurrentIndex(page.duration_box.findData(900))
    page.interval_box.setCurrentIndex(page.interval_box.findData(5))
    page.logical_mode.setChecked(True)
    page.cards[1].click()
    page.pause.click()
    window.close()
    reopened = MainWindow(window.settings)
    try:
        page = reopened.performance
        assert (page.duration, page.interval, page.resource) == (900, 5, 1)
        assert page.logical_mode.isChecked() and page.pause.isChecked()
        assert not reopened.refresh.performance_interval.isActive()
        assert reopened.refresh.interval.isActive()
    finally:
        reopened.close()


def test_worker_discards_inflight_reading_on_pause_and_resumes(qt_app: QApplication) -> None:
    started = Event()
    release = Event()
    detailed_calls: list[int] = []
    deliveries: list[int] = []
    scans: list[int] = []

    class ControlledSystem(SystemSampler):
        def sample(self, *, detailed: bool = True) -> SystemSample:
            assert detailed
            detailed_calls.append(get_ident())
            if len(detailed_calls) == 1:
                started.set()
                release.wait(3)
            return system_reading()

    def sample_processes(_: Event) -> Snapshot:
        scans.append(get_ident())
        return snapshot()

    controller = RefreshController(qt_app, sample_processes, ControlledSystem())
    controller.load_icons = False
    controller.performance_ready.connect(lambda _: deliveries.append(get_ident()))
    try:
        controller.set_performance(5000, True)
        wait_for(started.is_set)
        controller.set_performance(5000, False)
        controller.manual()
        release.set()
        wait_for(lambda: len(scans) == 1 and controller.future is None)
        assert not deliveries and not controller.performance_interval.isActive()
        controller.set_performance(5000, True)
        wait_for(lambda: len(deliveries) == 1)
        assert len(set(scans + detailed_calls)) == 1 and detailed_calls[0] != get_ident()
        assert deliveries == [get_ident()] and len(scans) == 1
    finally:
        release.set()
        controller.stop()
    assert controller.stop_requested.is_set() and not controller.performance_interval.isActive()


def test_total_processes_uses_latest_valid_unfiltered_snapshot(window: MainWindow) -> None:
    window.refresh.stop()
    uid = os.getuid()
    mine = row(81, "editor", uid=uid)
    foreign = row(82, "service", uid=uid + 1)
    window.apply_snapshot(snapshot(mine, foreign))
    assert window.total_processes.value.text() == "2"

    window.mine.setChecked(True)
    assert window.model.rowCount() == 1
    window.search.setText("no matching processes")
    assert window.model.rowCount() == 0
    assert window.total_processes.value.text() == "2"

    window.apply_snapshot(snapshot(mine, foreign, row(83, "another service", uid=uid + 1)))
    assert window.model.rowCount() == 0
    assert window.total_processes.value.text() == "3"
    window.refresh_failed("sample unavailable")
    assert window.total_processes.value.text() == "3"


def test_sort_search_owner_filter_and_tree_ancestors(qt_app: QApplication) -> None:
    model = ProcessModel()
    records = [row(14, "parent"), row(9, "needle", parent=14), row(101, "other", uid=55)]
    ascending = Qt.SortOrder.AscendingOrder
    model.replace(records, "", None, False, 1, ascending)
    assert [model.data(model.index(number, 1)) for number in range(3)] == [9, 14, 101]
    model.replace(records, "NEEDLE --sample", 1000, True, 0, ascending)
    assert model.rowCount() == 1
    parent = model.index(0, 0)
    child = model.index(0, 0, parent)
    assert model.data(parent) == "parent"
    assert model.data(child) == "needle"
    assert model.parent(child) == parent
    model.replace(records, "other", 1000, False, 0, ascending)
    assert model.rowCount() == 0


def test_refresh_keeps_selection_and_scroll_anchor(window: MainWindow) -> None:
    window.refresh.stop()
    window.view.header().setSortIndicator(1, Qt.SortOrder.AscendingOrder)
    rows = [row(pid, f"program-{pid}") for pid in range(1000, 1080)]
    window.apply_snapshot(snapshot(*rows))
    window.view.setCurrentIndex(window.model.index_for(rows[45].identity))
    window.view.selectionModel().setCurrentIndex(
        window.model.index_for(rows[46].identity), QItemSelectionModel.SelectionFlag.NoUpdate,
    )
    window.view.verticalScrollBar().setValue(700)
    anchor = window.model.process_at(window.view.indexAt(QPoint(1, 1)))
    assert anchor is not None and anchor != rows[0]
    window.apply_snapshot(snapshot(row(900, "new"), *rows))
    assert window.selected() == rows[45]
    assert window.model.process_at(window.view.indexAt(QPoint(1, 1))) == anchor

    replacement = replace(rows[45], stat=replace(rows[45].stat, identity=Identity(rows[45].identity.pid, 2)))
    window.apply_snapshot(snapshot(*rows[:45], replacement, *rows[46:]))
    assert window.selected() is None
    assert not window.stop_button.isEnabled()


def test_gui_header_and_search_controls(window: MainWindow) -> None:
    window.refresh.stop()
    window.apply_snapshot(snapshot(row(15, "alpha"), row(7, "beta")))
    header = window.view.header()
    point = QPoint(header.sectionViewportPosition(1) + 20, header.height() // 2)
    QTest.mouseClick(header.viewport(), Qt.MouseButton.LeftButton, pos=point)
    assert header.sortIndicatorSection() == 1
    original = window.model.data(window.model.index(0, 1))
    QTest.mouseClick(header.viewport(), Qt.MouseButton.LeftButton, pos=point)
    assert window.model.data(window.model.index(0, 1)) != original
    window.focus_search()
    QTest.keyClicks(window.search, "beta")
    assert window.model.rowCount() == 1
    assert window.model.data(window.model.index(0, 0)) == "beta"


def test_collapsed_tree_survives_refresh_and_expands_for_search(window: MainWindow) -> None:
    window.refresh.stop()
    parent, child = row(401, "parent"), row(402, "child", parent=401)
    window.mode.setCurrentIndex(1)
    window.apply_snapshot(snapshot(parent, child))
    index = window.model.index_for(parent.identity)
    assert window.view.isExpanded(index)
    window.view.collapse(index)
    window.apply_snapshot(snapshot(parent, child))
    assert not window.view.isExpanded(window.model.index_for(parent.identity))
    window.search.setText("child")
    assert window.view.isExpanded(window.model.index_for(parent.identity))
    window.search.clear()
    assert not window.view.isExpanded(window.model.index_for(parent.identity))


def test_confirmation_uses_original_identity(window: MainWindow, monkeypatch: pytest.MonkeyPatch) -> None:
    window.refresh.stop()
    target = row(500, "original", start=10)
    replacement = row(500, "replacement", start=20)
    window.apply_snapshot(snapshot(target))
    window.view.setCurrentIndex(window.model.index_for(target.identity))

    def confirm(*args) -> bool:
        window.apply_snapshot(snapshot(replacement))
        window.view.setCurrentIndex(window.model.index_for(replacement.identity))
        return True

    sent: list[tuple[Identity, signal.Signals]] = []

    def record(identity: Identity, value: signal.Signals) -> None:
        sent.append((identity, value))

    monkeypatch.setattr(dialogs, "confirm_signal", confirm)
    monkeypatch.setattr(management, "send_signal", record)
    window.stop_button.click()
    assert sent == [(target.identity, signal.SIGTERM)]


def test_worker_refresh_coalesces_manual_requests_and_stops(qt_app: QApplication) -> None:
    started = Event()
    release = Event()
    first = Event()
    thread_ids: list[int] = []
    deliveries: list[int] = []
    gui_thread = get_ident()

    def sample(stop: Event) -> Snapshot:
        thread_ids.append(get_ident())
        if not first.is_set():
            first.set()
            started.set()
            release.wait(3)
        else:
            stop.wait(3)
        return snapshot()

    parent = QObject()
    controller = RefreshController(parent, sample)
    controller.load_icons = False
    controller.ready.connect(lambda _: deliveries.append(get_ident()))
    try:
        controller.request()
        wait_for(started.is_set)
        controller.manual()
        controller.manual()
        assert len(thread_ids) == 1
        release.set()
        wait_for(lambda: len(thread_ids) == 2)
        assert thread_ids == [thread_ids[0], thread_ids[0]]
        assert thread_ids[0] != gui_thread
        assert deliveries == [gui_thread]
        future = controller.future
        assert future is not None
        controller.stop()
        wait_for(future.done)
        QTest.qWait(45)
        assert len(thread_ids) == 2 and deliveries == [gui_thread]
    finally:
        release.set()
        controller.stop()


def test_live_window_startup_auto_refresh_and_settings(window: MainWindow) -> None:
    window.refresh.interval.setInterval(60)
    wait_for(lambda: window.cpu.value.text().endswith("%"))
    assert window.model.index_for(next(record.identity for record in window.rows if record.identity.pid == os.getpid())).isValid()
    assert window.ram.value.text().endswith("%")
    window.auto.setChecked(False)
    assert not window.refresh.interval.isActive()
    assert window.refresh.performance_interval.isActive()
    window.mode.setCurrentIndex(1)
    window.view.setColumnHidden(3, True)
    window.close()
    assert window.refresh.stop_requested.is_set()
    reopened = MainWindow(window.settings)
    try:
        assert not reopened.auto.isChecked()
        assert reopened.mode.currentIndex() == 1
        assert reopened.view.isColumnHidden(3)
    finally:
        reopened.close()


def test_branding_layout_at_normal_and_minimum_width(window: MainWindow) -> None:
    logo = window.findChild(QLabel, "brandLogo")
    title = window.findChild(QLabel, "brand")
    tagline = window.findChild(QLabel, "brandTagline")
    run = window.findChild(QPushButton, "primary")
    assert logo is not None and title is not None and tagline is not None and run is not None
    assert title.text() == "TaskPup"
    assert tagline.text() == "Sit. Stay. SIGKILL."
    pixmap = logo.pixmap()
    assert not pixmap.isNull() and pixmap.hasAlphaChannel()

    for width in (1210, window.minimumWidth()):
        window.resize(width, 550)
        QApplication.processEvents()
        assert logo.height() == 48
        assert abs(logo.width() - 48 * pixmap.width() / pixmap.height()) <= 1
        assert title.x() == tagline.x() == logo.geometry().right() + 13
        assert tagline.y() - title.geometry().bottom() == 3
        text = title.geometry().united(tagline.geometry())
        assert abs(text.center().y() - logo.geometry().center().y()) <= 2
        assert abs(run.geometry().center().y() - logo.geometry().center().y()) <= 2
        assert run.geometry().right() == window.width() - 21


def test_run_task_passes_literal_arguments(qt_app: QApplication, tmp_path: Path) -> None:
    marker = tmp_path / "task output.txt"
    code = "from pathlib import Path; import sys; Path(sys.argv[1]).write_text(sys.argv[2])"
    literal = "$HOME ; | >"
    start_task(shlex.join([sys.executable, "-c", code, str(marker), literal]))
    wait_for(lambda: marker.exists() and marker.read_text() == literal)
    with pytest.raises(management.ProcessActionError, match="Invalid command line"):
        start_task("'unclosed")


def test_root_startup_is_rejected(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    monkeypatch.setattr(app.os, "geteuid", lambda: 0)
    assert app.main() == 1
    assert "regular user account" in capsys.readouterr().err


@pytest.mark.parametrize("has_entry", [True, False])
def test_portal_id_before_qt_startup(
    has_entry: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_DIRS", str(tmp_path / "system"))
    if has_entry:
        applications = tmp_path / "applications"
        applications.mkdir()
        (applications / "taskpup.desktop").write_text(
            "[Desktop Entry]\nType=Application\nName=TaskPup\nExec=taskpup\n",
            encoding="utf-8",
        )
    registered: list[str] = []

    class StartupReached(Exception):
        pass

    class ApplicationProbe:
        setDesktopFileName = staticmethod(registered.append)

        def __init__(self, argv: list[str]) -> None:
            assert registered == (["taskpup"] if has_entry else [])
            raise StartupReached

    monkeypatch.setattr(app, "QApplication", ApplicationProbe)
    with pytest.raises(StartupReached):
        app.main()
