from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from threading import Event, get_ident
import time

import pytest
from PySide6.QtCore import QEventLoop, QObject, QSettings, Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QCheckBox, QDialog, QDialogButtonBox, QLabel, QPushButton

from taskpup import dialogs
from taskpup.refresh import RefreshController
from taskpup.service_controls import ServiceAction, ServiceOperationResult, assess_service_risk
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

    # Verify Phase 3B context-sensitive control buttons for active + static User dbus.service:
    # Stop & Restart enabled (high-risk user session), Start/Enable/Disable disabled.
    assert page.start_button.text() == "Start" and not page.start_button.isEnabled()
    assert page.stop_button.text() == "Stop" and page.stop_button.isEnabled()
    assert page.restart_button.text() == "Restart" and page.restart_button.isEnabled()
    assert page.enable_button.text() == "Enable at Startup" and not page.enable_button.isEnabled()
    assert page.disable_button.text() == "Disable at Startup" and not page.disable_button.isEnabled()

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


def test_service_control_buttons_confirmations_stale_guard_and_feedback(
    window: MainWindow, monkeypatch: pytest.MonkeyPatch,
) -> None:
    page = window.services
    window.navigation.setCurrentIndex(2)

    cups = make_service("cups.service", scope="system", active_state="active", sub_state="running", unit_file_state="enabled")
    brltty = make_service(
        "brltty.service", scope="system", loaded=False, load_state=None,
        active_state=None, sub_state=None, unit_file_state="disabled", main_pid=None,
    )
    sys_dbus = make_service("dbus.service", scope="system", active_state="active", sub_state="running", unit_file_state="static")
    window.apply_services(sample_snapshot(cups, brltty, sys_dbus))

    # No selection -> all 5 buttons disabled.
    assert all(not button.isEnabled() for button in page.action_buttons.values())

    # Protected system dbus.service -> all 5 buttons disabled with reason tooltips.
    page.view.setCurrentIndex(page.model.index_for(sys_dbus.identity))
    assert all(not button.isEnabled() for button in page.action_buttons.values())
    assert "D-Bus" in page.stop_button.toolTip()

    # Unloaded disabled service -> Start and Enable enabled.
    page.view.setCurrentIndex(page.model.index_for(brltty.identity))
    assert page.start_button.isEnabled() and page.enable_button.isEnabled()
    assert not page.stop_button.isEnabled() and not page.restart_button.isEnabled() and not page.disable_button.isEnabled()

    # User cancelling confirmation emits no action.
    requested: list[tuple[ServiceIdentity, str, bool]] = []
    page.action_requested.connect(lambda ident, act, ack: requested.append((ident, act, ack)))
    monkeypatch.setattr(dialogs, "confirm_service_action", lambda *args: False)
    page.start_button.click()
    assert requested == []

    # Confirmed action emits immutable (identity, action, high_risk_acknowledged).
    monkeypatch.setattr(dialogs, "confirm_service_action", lambda *args: True)
    page.enable_button.click()
    assert requested == [(brltty.identity, "enable", False)]

    # While operation is in progress, all action buttons disable and changing selection does NOT redirect or unlock.
    page.set_operation_started(brltty.identity, "enable")
    assert page.feedback.isVisible() and "Enabling brltty.service" in page.feedback_label.text()
    assert page.feedback_dismiss.isHidden()
    page.view.setCurrentIndex(page.model.index_for(cups.identity))
    assert page.selected() == cups
    assert all(not button.isEnabled() for button in page.action_buttons.values())

    # Completing operation shows feedback, re-enables buttons according to current selection.
    page.apply_operation_result(
        ServiceOperationResult(brltty.identity, "enable", "succeeded", "Enabled brltty.service at startup (Enabled).")
    )
    assert page.feedback.isVisible() and page.feedback_dismiss.isVisible()
    assert "Enabled brltty.service" in page.feedback_label.text()
    assert page.stop_button.isEnabled() and page.restart_button.isEnabled() and page.disable_button.isEnabled()

    # Stale selection guard: if service disappears while confirmation dialog is open, do not emit action.
    requested.clear()

    def disappear_during_confirm(*args) -> bool:
        window.apply_services(sample_snapshot(brltty, sys_dbus))
        return True

    monkeypatch.setattr(dialogs, "confirm_service_action", disappear_during_confirm)
    page.stop_button.click()
    assert requested == []
    assert "no longer present" in page.feedback_label.text()


def test_high_risk_confirmation_dialog_requires_impact_checkbox(window: MainWindow, monkeypatch: pytest.MonkeyPatch) -> None:
    dm = make_service("lightdm.service", scope="system", active_state="active", sub_state="running", unit_file_state="indirect")
    risk = assess_service_risk(dm, "restart")
    assert risk.level == "high"

    inspected: dict[str, bool] = {}

    def fake_exec(dialog: QDialog) -> int:
        checkboxes = dialog.findChildren(QCheckBox)
        assert len(checkboxes) == 1
        button_box = dialog.findChild(QDialogButtonBox)
        assert button_box is not None
        accept = next(btn for btn in button_box.buttons() if button_box.buttonRole(btn) == QDialogButtonBox.ButtonRole.AcceptRole)
        inspected["initially_disabled"] = not accept.isEnabled()
        checkboxes[0].setChecked(True)
        inspected["enabled_after_check"] = accept.isEnabled()
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(QDialog, "exec", fake_exec)
    assert dialogs.confirm_service_action(window, dm, "restart", risk) is True
    assert inspected == {"initially_disabled": True, "enabled_after_check": True}


def test_service_action_worker_prevents_duplicates_discards_stale_refresh_and_stops_cleanly(
    qt_app: QApplication,
) -> None:
    gui_thread = get_ident()
    action_started = Event()
    action_release = Event()
    stale_refresh_started = Event()
    stale_refresh_cancelled = Event()
    refreshes: list[int] = []
    actions_run: list[tuple[ServiceIdentity, ServiceAction, bool, int]] = []
    finished: list[tuple[int, ServiceOperationResult]] = []
    snapshots: list[ServicesSnapshot] = []

    def loader(stop: Event) -> ServicesSnapshot:
        call = len(refreshes) + 1
        refreshes.append(call)
        if call == 1:
            stale_refresh_started.set()
            if stop.wait(3.0):
                stale_refresh_cancelled.set()
            return sample_snapshot(make_service("stale-before-action.service"))
        return sample_snapshot(make_service("fresh-after-action.service"))

    def executor(
        identity: ServiceIdentity,
        action: ServiceAction,
        stop: Event,
        high_risk_acknowledged: bool,
    ) -> ServiceOperationResult:
        actions_run.append((identity, action, high_risk_acknowledged, get_ident()))
        if len(actions_run) == 1:
            action_started.set()
            action_release.wait(3.0)
            return ServiceOperationResult(identity, action, "succeeded", f"Restarted {identity.unit} (Running).")
        stop.wait(3.0)
        return ServiceOperationResult(identity, action, "interrupted", "Stopped monitoring; final outcome unknown.")

    parent = QObject()
    controller = RefreshController(parent, services=loader, service_executor=executor)
    controller.services_ready.connect(snapshots.append)
    controller.service_action_finished.connect(lambda res: finished.append((get_ident(), res)))
    try:
        # Start a discovery refresh first; starting a service action invalidates that stale pre-action scan.
        controller.request_services()
        wait_for(stale_refresh_started.is_set)

        target = ServiceIdentity("system", "cups.service")
        assert controller.request_service_action(target, "restart", True) is True
        wait_for(action_started.is_set)
        wait_for(stale_refresh_cancelled.is_set)

        # Duplicate / concurrent control operation is rejected immediately.
        assert controller.request_service_action(ServiceIdentity("system", "other.service"), "stop") is False

        action_release.set()
        wait_for(lambda: len(finished) == 1 and len(snapshots) == 1 and controller.service_action_future is None)
        assert actions_run[0][:3] == (target, "restart", True)
        assert actions_run[0][3] != gui_thread
        assert finished[0][0] == gui_thread
        assert finished[0][1].outcome == "succeeded"
        # Stale pre-action snapshot was discarded; only post-action fresh snapshot was delivered.
        assert [r.unit for r in snapshots[0].services] == ["fresh-after-action.service"]

        # Shutdown cancels an in-flight action cleanly and emits no post-stop signals.
        assert controller.request_service_action(target, "stop") is True
        wait_for(lambda: len(actions_run) == 2)
        future = controller.service_action_future
        assert future is not None
        controller.stop()
        wait_for(future.done)
        QTest.qWait(45)
        assert len(finished) == 1
        assert future.result().outcome == "interrupted"
    finally:
        action_release.set()
        controller.stop()


def test_p2_close_behavior_idle_keep_open_exit_anyway_and_completion_during_prompt(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def make_window(executor, loader=None) -> MainWindow:
        settings = Settings(QSettings(str(tmp_path / f"s-{time.monotonic_ns()}.ini"), QSettings.Format.IniFormat))
        win = MainWindow(settings)
        win.refresh.interval.stop()
        win.refresh.performance_interval.stop()
        win.refresh.service_action_runner = executor
        if loader is not None:
            win.refresh.services_loader = loader
        win.show()
        return win

    # 1. Closing with NO operation pending closes immediately without any close dialog.
    prompted: list[tuple[ServiceIdentity, ServiceAction]] = []
    monkeypatch.setattr(
        dialogs,
        "confirm_close_with_pending_service_action",
        lambda parent, ident, act, **kw: prompted.append((ident, act)) or False,
    )
    idle_win = make_window(lambda *a: ServiceOperationResult(a[0], a[1], "succeeded", "ok"))
    idle_win.close()
    assert not idle_win.isVisible()
    assert prompted == []

    # 2. Closing with an operation in progress: Keep TaskPup Open preserves monitoring & prevents duplicate prompts.
    started = Event()
    release = Event()
    finished_results: list[ServiceOperationResult] = []
    target = ServiceIdentity("system", "cups.service")

    def slow_executor(ident: ServiceIdentity, act: ServiceAction, stop: Event, ack: bool) -> ServiceOperationResult:
        started.set()
        if release.wait(3.0):
            return ServiceOperationResult(ident, act, "succeeded", f"Restarted {ident.unit} (Running).")
        return ServiceOperationResult(ident, act, "interrupted", "Stopped monitoring; final outcome unknown.")

    keep_win = make_window(slow_executor, loader=lambda _s: sample_snapshot(make_service("cups.service")))
    keep_win.refresh.service_action_finished.connect(finished_results.append)
    try:
        assert keep_win.refresh.request_service_action(target, "restart", False) is True
        wait_for(started.is_set)

        dialog_text: dict[str, str] = {}
        duplicate_blocked = False

        def keep_open_exec(dialog: QDialog) -> int:
            nonlocal duplicate_blocked
            labels = [lbl.text() for lbl in dialog.findChildren(QLabel)]
            dialog_text["all"] = "\n".join(labels)
            button_box = dialog.findChild(QDialogButtonBox)
            assert button_box is not None
            texts = [btn.text() for btn in button_box.buttons()]
            assert "Keep TaskPup Open" in texts and "Exit Anyway" in texts
            # Attempt a duplicate close while the close dialog is open -> must be ignored without re-entering.
            keep_win.close()
            duplicate_blocked = keep_win._close_prompt_open
            return QDialog.DialogCode.Rejected

        monkeypatch.undo()
        monkeypatch.setattr(QDialog, "exec", keep_open_exec)

        keep_win.close()
        assert duplicate_blocked is True
        assert keep_win.isVisible() and not keep_win.refresh.stop_requested.is_set()
        assert "cups.service" in dialog_text["all"]
        assert "System service" in dialog_text["all"]
        assert "Restart" in dialog_text["all"]
        assert "unknown" in dialog_text["all"].casefold()

        release.set()
        wait_for(lambda: len(finished_results) == 1)
        assert finished_results[0].outcome == "succeeded"
        assert "Restarted cups.service" in keep_win.services.feedback_label.text()
    finally:
        release.set()
        keep_win.refresh.stop()
        keep_win.close()

    # 3. Explicitly choosing Exit Anyway exits cleanly, stops worker, and emits NO false success/cancellation.
    exit_started = Event()
    exit_stop_seen = Event()
    exit_finished: list[ServiceOperationResult] = []

    def blocking_executor(ident: ServiceIdentity, act: ServiceAction, stop: Event, ack: bool) -> ServiceOperationResult:
        exit_started.set()
        stop.wait(3.0)
        if stop.is_set():
            exit_stop_seen.set()
        return ServiceOperationResult(ident, act, "interrupted", "Stopped monitoring; final outcome unknown.")

    exit_win = make_window(blocking_executor)
    exit_win.refresh.service_action_finished.connect(exit_finished.append)
    try:
        assert exit_win.refresh.request_service_action(ServiceIdentity("user", "pipewire.service"), "stop") is True
        wait_for(exit_started.is_set)
        future = exit_win.refresh.service_action_future
        assert future is not None

        monkeypatch.setattr(QDialog, "exec", lambda _dialog: QDialog.DialogCode.Accepted)
        exit_win.close()
        assert not exit_win.isVisible()
        assert exit_win.refresh.stop_requested.is_set()
        wait_for(exit_stop_seen.is_set)
        wait_for(future.done)
        QTest.qWait(45)
        assert exit_finished == []
        assert future.result().outcome == "interrupted"
    finally:
        exit_win.refresh.stop()
        exit_win.close()

    # 4. Operation completing WHILE the real close confirmation dialog is open clears the warning naturally.
    monkeypatch.undo()
    comp_started = Event()
    comp_release = Event()
    comp_finished: list[ServiceOperationResult] = []

    def completing_executor(ident: ServiceIdentity, act: ServiceAction, stop: Event, ack: bool) -> ServiceOperationResult:
        comp_started.set()
        comp_release.wait(3.0)
        return ServiceOperationResult(ident, act, "succeeded", f"Started {ident.unit} (Running).")

    comp_win = make_window(completing_executor, loader=lambda _s: sample_snapshot(make_service("brltty.service")))
    comp_win.refresh.service_action_finished.connect(comp_finished.append)
    try:
        assert comp_win.refresh.request_service_action(ServiceIdentity("system", "brltty.service"), "start") is True
        wait_for(comp_started.is_set)
        # Release the worker 80 ms after the modal close dialog opens so completion happens during the close decision.
        QTimer.singleShot(80, comp_release.set)
        comp_win.close()
        # Dialog auto-dismissed on completion; window remained open showing the real result.
        assert comp_win.isVisible()
        assert len(comp_finished) == 1 and comp_finished[0].outcome == "succeeded"
        assert "Started brltty.service" in comp_win.services.feedback_label.text()
        assert comp_win.refresh.pending_service_action() is None
        # Subsequent close succeeds immediately without any pending-operation prompt.
        comp_win.close()
        assert not comp_win.isVisible()
    finally:
        comp_release.set()
        comp_win.refresh.stop()
        comp_win.close()
