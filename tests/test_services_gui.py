from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from threading import Event, get_ident
import time

import pytest
from PySide6.QtCore import QEventLoop, QObject, QSettings, Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QPushButton

from taskpup.refresh import RefreshController
from taskpup.services import ScopeStatus, ServiceIdentity, ServiceRecord, ServicesSnapshot
from taskpup.settings import Settings
from taskpup.window import MainWindow


def wait_for(condition: Callable[[], bool], timeout: float = 3.0) -> None:
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


@pytest.fixture
def window(qt_app: QApplication, tmp_path: Path):
    settings = Settings(QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat))
    win = MainWindow(settings)
    win.refresh.stop()
    win.show()
    try:
        yield win
    finally:
        win.close()


def sample_snapshot(
    *records: ServiceRecord,
    system_status: ScopeStatus | None = None,
    user_status: ScopeStatus | None = None,
) -> ServicesSnapshot:
    return ServicesSnapshot(
        services=records,
        system=system_status or ScopeStatus("system", available=True),
        user=user_status or ScopeStatus("user", available=True),
        timestamp=time.monotonic(),
    )


def make_service(
    unit: str,
    *,
    scope: str = "system",
    description: str | None = None,
    loaded: bool = True,
    load_state: str | None = "loaded",
    active_state: str | None = "active",
    sub_state: str | None = "running",
    unit_file_state: str | None = "enabled",
    fragment_path: str | None = None,
    main_pid: int | None = 1234,
    status_text: str | None = None,
) -> ServiceRecord:
    typed_scope = "user" if scope == "user" else "system"
    return ServiceRecord(
        identity=ServiceIdentity(typed_scope, unit),
        description=description,
        loaded=loaded,
        load_state=load_state,
        active_state=active_state,
        sub_state=sub_state,
        unit_file_state=unit_file_state,
        unit_file_preset="enabled",
        fragment_path=fragment_path,
        main_pid=main_pid,
        service_type="simple" if loaded else None,
        user=None,
        transient=False if loaded else None,
        result="success" if loaded else None,
        active_enter_timestamp="Fri 2026-11-20 23:05:01 PST" if active_state == "active" else None,
        status_text=status_text,
        triggered_by=(),
    )


def test_services_navigation_filtering_selection_details_and_disappearing_service(window: MainWindow) -> None:
    assert [window.navigation.tabText(i) for i in range(window.navigation.count())] == [
        "Processes",
        "Performance",
        "Services",
    ]
    refresh_calls: list[int] = []
    window.services.refresh_requested.connect(lambda: refresh_calls.append(1))

    # Switching to Services triggers initial discovery once.
    window.navigation.setCurrentIndex(2)
    assert window.services.isVisible()
    assert len(refresh_calls) == 1

    sys_dbus = make_service(
        "dbus.service",
        scope="system",
        description="D-Bus System Message Bus",
        unit_file_state="static",
        fragment_path="/usr/lib/systemd/system/dbus.service",
        main_pid=500,
    )
    user_dbus = make_service(
        "dbus.service",
        scope="user",
        description="D-Bus User Message Bus",
        unit_file_state="static",
        fragment_path="/usr/lib/systemd/user/dbus.service",
        main_pid=1500,
        status_text="Ready.",
    )
    failed_svc = make_service(
        "broken.service",
        scope="system",
        description="Broken helper",
        active_state="failed",
        sub_state="failed",
        unit_file_state="enabled",
        main_pid=None,
    )
    masked_svc = make_service(
        "alsa-utils.service",
        scope="system",
        description=None,
        loaded=False,
        load_state=None,
        active_state=None,
        sub_state=None,
        unit_file_state="masked",
        main_pid=None,
    )
    window.apply_services(sample_snapshot(sys_dbus, user_dbus, failed_svc, masked_svc))

    page = window.services
    assert page.model.rowCount() == 4
    assert page.count.text() == "4"
    assert page.notice.isHidden()

    # Select User dbus.service and verify details and read-only boundary.
    user_index = page.model.index_for(user_dbus.identity)
    assert user_index.isValid()
    page.view.setCurrentIndex(user_index)
    assert page.selected() == user_dbus
    assert page.details.fields["Unit name"].text() == "dbus.service"
    assert page.details.fields["Scope"].text() == "User"
    assert page.details.fields["Enablement"].text() == "Static"
    assert page.details.fields["Unit file path"].text() == "/usr/lib/systemd/user/dbus.service"
    assert page.details.fields["Main PID"].text() == "1500"
    assert page.details.fields["Status"].text() == "Ready."
    assert page.details.rows["Status"].isVisible()

    # Ensure strictly read-only UI: only the Refresh button exists on the Services page.
    buttons = [btn.text() for btn in page.findChildren(QPushButton)]
    assert buttons == ["Refresh"]

    # Search and filter operate purely in memory without triggering new systemd queries.
    calls_before_filter = len(refresh_calls)
    page.search.setText("dbus")
    assert page.model.rowCount() == 2
    assert page.count.text() == "2 of 4"
    assert page.selected() == user_dbus
    page.scope_filter.setCurrentIndex(page.scope_filter.findData("user"))
    assert page.model.rowCount() == 1
    assert page.selected() == user_dbus
    page.scope_filter.setCurrentIndex(page.scope_filter.findData("all"))
    page.search.clear()
    page.state_filter.setCurrentIndex(page.state_filter.findData("failed"))
    assert page.model.rowCount() == 1
    assert page.model.service_at(page.model.index(0, 0)) == failed_svc
    assert page.selected() is None
    assert page.details.details_scroll.isHidden() and page.details.empty_hint.isVisible()
    page.state_filter.setCurrentIndex(page.state_filter.findData("inactive"))
    assert page.model.rowCount() == 1
    assert page.model.service_at(page.model.index(0, 0)) == masked_svc
    page.state_filter.setCurrentIndex(page.state_filter.findData("all"))
    assert len(refresh_calls) == calls_before_filter

    # Selection stays bound to (scope, unit) across refresh and updates details.
    page.view.setCurrentIndex(page.model.index_for(user_dbus.identity))
    updated_user_dbus = replace(user_dbus, main_pid=2500, status_text=None)
    window.apply_services(sample_snapshot(sys_dbus, updated_user_dbus, failed_svc))
    assert page.selected() == updated_user_dbus
    assert page.details.fields["Main PID"].text() == "2500"
    assert page.details.rows["Status"].isHidden()

    # When the selected service disappears, selection and details clear cleanly.
    window.apply_services(sample_snapshot(sys_dbus, failed_svc))
    assert page.selected() is None
    assert page.details.details_scroll.isHidden()
    assert page.details.fields["Unit name"].text() == ""

    # Unavailable user manager surfaces a clear banner without crashing.
    window.apply_services(
        sample_snapshot(
            sys_dbus,
            user_status=ScopeStatus("user", available=False, unit_files_available=False, error="User systemd manager unavailable: no bus"),
        )
    )
    assert page.notice.isVisible()
    assert "User systemd manager unavailable" in page.notice_label.text()
    assert "User: unavailable" in page.state_summary.text()

    # Switching back to Processes and Performance preserves existing pages.
    window.navigation.setCurrentIndex(0)
    assert not page.isVisible()
    window.navigation.setCurrentIndex(1)
    assert window.performance.isVisible()
    window.navigation.setCurrentIndex(2)
    assert len(refresh_calls) == 1  # Already initialized; does not re-query automatically.


def test_services_layout_remains_usable_at_minimum_window_size(window: MainWindow) -> None:
    window.navigation.setCurrentIndex(2)
    window.apply_services(
        sample_snapshot(
            make_service(
                "very-long-service-unit-name-for-layout-check.service",
                description="Long description that should wrap inside the details pane cleanly",
                fragment_path="/usr/lib/systemd/system/very-long-service-unit-name-for-layout-check.service",
            )
        )
    )
    window.services.view.setCurrentIndex(window.services.model.index(0, 0))
    window.resize(window.minimumWidth(), window.minimumHeight())
    QApplication.processEvents()
    page = window.services
    assert page.view.width() >= 300
    assert page.details.width() >= 220
    assert page.search.isVisible() and page.refresh_button.isVisible()
    assert page.details.details_scroll.isVisible()


def test_services_worker_discards_stale_results_and_stops_cleanly(qt_app: QApplication) -> None:
    gui_thread = get_ident()
    first_started = Event()
    first_cancelled = Event()
    second_started = Event()
    second_release = Event()
    calls: list[tuple[int, int]] = []
    delivered: list[tuple[int, ServicesSnapshot]] = []
    errors: list[str] = []

    def loader(stop: Event) -> ServicesSnapshot:
        call_number = len(calls) + 1
        calls.append((call_number, get_ident()))
        if call_number == 1:
            first_started.set()
            if stop.wait(3.0):
                first_cancelled.set()
            return sample_snapshot(make_service("stale.service"))
        if call_number == 2:
            second_started.set()
            second_release.wait(3.0)
            return sample_snapshot(make_service("fresh.service"))
        stop.wait(3.0)
        return sample_snapshot(make_service("after-stop.service"))

    parent = QObject()
    controller = RefreshController(parent, services=loader)
    controller.services_ready.connect(lambda snap: delivered.append((get_ident(), snap)))
    controller.services_failed.connect(errors.append)
    try:
        # Start gen 1, then supersede it with rapid refresh clicks (gen 2 & gen 3 coalesced).
        controller.request_services()
        wait_for(first_started.is_set)
        controller.request_services()
        controller.request_services()
        wait_for(first_cancelled.is_set)
        wait_for(second_started.is_set)
        second_release.set()
        wait_for(lambda: len(delivered) == 1 and controller.services_future is None)

        assert len(calls) == 2
        assert calls[0][1] == calls[1][1] and calls[0][1] != gui_thread
        assert delivered[0][0] == gui_thread
        assert [r.unit for r in delivered[0][1].services] == ["fresh.service"]
        assert errors == []

        # Shutdown cancels an in-flight request and emits no further signals.
        controller.request_services()
        wait_for(lambda: len(calls) == 3)
        future = controller.services_future
        assert future is not None
        controller.stop()
        wait_for(future.done)
        QTest.qWait(45)
        assert len(delivered) == 1
    finally:
        second_release.set()
        controller.stop()


def test_services_worker_emits_failure_without_crashing(qt_app: QApplication) -> None:
    errors: list[str] = []

    def failing_loader(_: Event) -> ServicesSnapshot:
        raise RuntimeError("unexpected systemd failure")

    parent = QObject()
    controller = RefreshController(parent, services=failing_loader)
    controller.services_failed.connect(errors.append)
    try:
        controller.request_services()
        wait_for(lambda: len(errors) == 1)
        assert errors == ["unexpected systemd failure"]
    finally:
        controller.stop()
