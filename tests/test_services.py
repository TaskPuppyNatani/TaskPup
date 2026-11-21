from collections.abc import Sequence
import json
import sys
from threading import Event
import time

import pytest

from taskpup.services import (
    CommandResult,
    LoadedServiceEntry,
    MalformedOutputError,
    ServiceIdentity,
    ServiceRecord,
    UnitFileEntry,
    discover_scope,
    discover_services,
    matches_filters,
    merge_scope_services,
    parse_show_output,
    parse_unit_files_json,
    run_systemctl,
)


def test_parse_show_output_handles_properties_equals_and_non_services() -> None:
    raw = "\n".join(
        [
            "Id=accounts-daemon.service",
            "Description=Accounts Service (mode=strict)",
            "LoadState=loaded",
            "ActiveState=active",
            "SubState=running",
            "UnitFileState=enabled",
            "UnitFilePreset=enabled",
            "FragmentPath=/usr/lib/systemd/system/accounts-daemon.service",
            "MainPID=765",
            "Type=dbus",
            "User=",
            "Transient=no",
            "Result=success",
            "ActiveEnterTimestamp=Fri 2026-11-20 23:05:01 PST",
            "StatusText=Ready.",
            "TriggeredBy=accounts-daemon.socket",
            "",
            "Id=alsa-restore.service",
            "Description=Save/Restore Sound Card State",
            "LoadState=loaded",
            "ActiveState=active",
            "SubState=exited",
            "UnitFileState=static",
            "UnitFilePreset=",
            "FragmentPath=/usr/lib/systemd/system/alsa-restore.service",
            "MainPID=0",
            "Type=oneshot",
            "User=",
            "Transient=no",
            "Result=success",
            "ActiveEnterTimestamp=n/a",
            "StatusText=",
            "TriggeredBy=",
            "",
            "Id=basic.target",
            "Description=Basic System",
            "LoadState=loaded",
            "ActiveState=active",
            "SubState=active",
            "",
        ]
    )
    entries = parse_show_output(raw)
    assert len(entries) == 2
    first, second = entries
    assert first.unit == "accounts-daemon.service"
    assert first.description == "Accounts Service (mode=strict)"
    assert first.main_pid == 765
    assert first.user is None
    assert first.transient is False
    assert first.status_text == "Ready."
    assert first.triggered_by == ("accounts-daemon.socket",)
    assert second.unit == "alsa-restore.service"
    assert second.main_pid is None
    assert second.unit_file_preset is None
    assert second.active_enter_timestamp is None


def test_parse_unit_files_json_filters_services_and_rejects_malformed() -> None:
    payload = json.dumps(
        [
            {"unit_file": "ssh.service", "state": "enabled", "preset": "enabled"},
            {"unit_file": "alsa-utils.service", "state": "masked", "preset": "enabled"},
            {"unit_file": "apt-daily.timer", "state": "enabled", "preset": "enabled"},
            {"unit_file": "speech-dispatcher.service", "state": "generated", "preset": None},
        ]
    )
    entries = parse_unit_files_json(payload)
    assert entries == [
        UnitFileEntry("ssh.service", "enabled", "enabled"),
        UnitFileEntry("alsa-utils.service", "masked", "enabled"),
        UnitFileEntry("speech-dispatcher.service", "generated", None),
    ]
    assert parse_unit_files_json("") == []
    with pytest.raises(MalformedOutputError):
        parse_unit_files_json("{not json")
    with pytest.raises(MalformedOutputError):
        parse_unit_files_json(json.dumps({"unit_file": "ssh.service"}))
    with pytest.raises(MalformedOutputError):
        parse_unit_files_json(json.dumps([{"state": "enabled"}]))


def test_parse_show_output_rejects_malformed_blocks() -> None:
    assert parse_show_output("   \n") == []
    with pytest.raises(MalformedOutputError):
        parse_show_output("not a key value line\n")
    with pytest.raises(MalformedOutputError):
        parse_show_output("LoadState=loaded\nActiveState=active\n")


def test_merge_scope_services_and_state_enablement_semantics() -> None:
    loaded = [
        LoadedServiceEntry(
            unit="running.service",
            description="Running daemon",
            load_state="loaded",
            active_state="active",
            sub_state="running",
            unit_file_state="",
            fragment_path="/usr/lib/systemd/system/running.service",
            main_pid=420,
            transient=False,
        ),
        LoadedServiceEntry(
            unit="oneshot.service",
            description="Boot initialization",
            load_state="loaded",
            active_state="active",
            sub_state="exited",
            unit_file_state="static",
            transient=False,
        ),
        LoadedServiceEntry(
            unit="broken.service",
            description="Broken unit",
            load_state="loaded",
            active_state="failed",
            sub_state="failed",
            unit_file_state="enabled",
            result="exit-code",
        ),
        LoadedServiceEntry(
            unit="starting.service",
            description="Starting service",
            load_state="loaded",
            active_state="activating",
            sub_state="auto-restart",
            unit_file_state="enabled-runtime",
        ),
        LoadedServiceEntry(
            unit="stopping.service",
            description="Stopping service",
            load_state="loaded",
            active_state="deactivating",
            sub_state="stop-sigterm",
            unit_file_state="disabled",
        ),
        LoadedServiceEntry(
            unit="ephemeral.service",
            description="Run via systemd-run",
            load_state="loaded",
            active_state="active",
            sub_state="running",
            unit_file_state=None,
            transient=True,
        ),
        LoadedServiceEntry(
            unit="mystery.service",
            description="Unknown state unit",
            load_state="loaded",
            active_state="custom-phase",
            sub_state=None,
            unit_file_state=None,
            transient=False,
        ),
        LoadedServiceEntry(
            unit="missing.service",
            description="missing.service",
            load_state="not-found",
            active_state="inactive",
            sub_state="dead",
            unit_file_state=None,
        ),
    ]
    unit_files = [
        UnitFileEntry("running.service", "enabled", "enabled"),
        UnitFileEntry("masked-only.service", "masked", "enabled"),
        UnitFileEntry("disabled-only.service", "disabled", "disabled"),
        UnitFileEntry("generated-only.service", "generated", None),
        UnitFileEntry("getty@.service", "enabled", "enabled"),
        UnitFileEntry("display-manager.service", "alias", None),
    ]

    merged = {record.unit: record for record in merge_scope_services("system", loaded, unit_files)}

    assert merged["running.service"].state_label == "Running"
    assert merged["running.service"].enablement_label == "Enabled"
    assert merged["running.service"].state_category == "running"

    assert merged["oneshot.service"].state_label == "Active (exited)"
    assert merged["oneshot.service"].enablement_label == "Static"
    assert merged["oneshot.service"].state_category == "active_other"

    assert merged["broken.service"].state_label == "Failed"
    assert merged["broken.service"].state_category == "failed"

    assert merged["starting.service"].state_label == "Activating (auto-restart)"
    assert merged["starting.service"].enablement_label == "Enabled (runtime)"
    assert merged["starting.service"].state_category == "transitioning"

    assert merged["stopping.service"].state_label == "Deactivating"
    assert merged["stopping.service"].enablement_label == "Disabled"
    assert merged["stopping.service"].state_category == "transitioning"

    assert merged["ephemeral.service"].enablement_label == "Transient"
    assert merged["ephemeral.service"].state_category == "running"

    # Unknown active state and unavailable enablement must not masquerade as failed or disabled.
    assert merged["mystery.service"].state_label == "Unknown (custom-phase)"
    assert merged["mystery.service"].state_category == "unknown"
    assert merged["mystery.service"].enablement_label == "Unavailable"

    assert merged["missing.service"].state_label == "Inactive (not found)"
    assert merged["missing.service"].enablement_label == "Unavailable"
    assert merged["missing.service"].state_category == "inactive"

    assert merged["masked-only.service"].loaded is False
    assert merged["masked-only.service"].state_label == "Inactive (masked)"
    assert merged["masked-only.service"].enablement_label == "Masked"
    assert merged["masked-only.service"].load_state_label == "Masked (not loaded)"
    assert merged["masked-only.service"].state_category == "inactive"

    assert merged["disabled-only.service"].state_label == "Inactive (not loaded)"
    assert merged["disabled-only.service"].enablement_label == "Disabled"
    assert merged["disabled-only.service"].state_category == "inactive"

    assert merged["generated-only.service"].enablement_label == "Generated"

    # Template and alias unit files remain distinct and are not falsely classified as stopped or failed.
    assert merged["getty@.service"].state_label == "Template"
    assert merged["getty@.service"].state_category == "other"
    assert merged["display-manager.service"].state_label == "Alias"
    assert merged["display-manager.service"].state_category == "other"


def test_discover_services_keeps_system_and_user_scopes_distinct_and_handles_unavailable_user() -> None:
    sys_show = "\n".join(
        [
            "Id=dbus.service",
            "Description=System D-Bus",
            "LoadState=loaded",
            "ActiveState=active",
            "SubState=running",
            "UnitFileState=static",
        ]
    )
    user_show = "\n".join(
        [
            "Id=dbus.service",
            "Description=User D-Bus",
            "LoadState=loaded",
            "ActiveState=active",
            "SubState=running",
            "UnitFileState=static",
        ]
    )

    def both_ok(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        is_user = "--user" in args
        if "show" in args:
            return CommandResult(0, user_show if is_user else sys_show, "")
        return CommandResult(0, "[]", "")

    snapshot = discover_services(runner=both_ok)
    assert snapshot.system.available and snapshot.user.available
    assert [record.identity for record in snapshot.services] == [
        ServiceIdentity("system", "dbus.service"),
        ServiceIdentity("user", "dbus.service"),
    ]
    assert snapshot.services[0].description == "System D-Bus"
    assert snapshot.services[1].description == "User D-Bus"

    def user_unavailable(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "--user" in args:
            return CommandResult(1, "", "Failed to connect to bus: No such file or directory")
        if "show" in args:
            return CommandResult(0, sys_show, "")
        return CommandResult(0, "[]", "")

    degraded = discover_services(runner=user_unavailable)
    assert degraded.system.available is True
    assert degraded.user.available is False
    assert degraded.user.error is not None and "User systemd manager unavailable" in degraded.user.error
    assert [record.identity for record in degraded.services] == [ServiceIdentity("system", "dbus.service")]


def test_discover_scope_handles_timeout_permission_malformed_and_partial_unit_file_failure() -> None:
    def timed_out(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        return CommandResult(-1, "", "", timed_out=True)

    records, status = discover_scope("system", runner=timed_out)
    assert records == () and not status.available
    assert status.error is not None and "timed out" in status.error.casefold()

    def denied(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        return CommandResult(1, "", "Access denied")

    records, status = discover_scope("system", runner=denied)
    assert records == () and not status.available
    assert status.error is not None and "permission denied" in status.error.casefold()

    def bad_show(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        return CommandResult(0, "corrupted non key-value output", "")

    records, status = discover_scope("system", runner=bad_show)
    assert records == () and not status.available
    assert status.error is not None and "malformed" in status.error.casefold()

    def partial_bad_unit_files(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "show" in args:
            return CommandResult(
                0,
                "Id=ssh.service\nDescription=OpenSSH\nLoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n",
                "",
            )
        return CommandResult(0, "{broken json", "")

    records, status = discover_scope("system", runner=partial_bad_unit_files)
    assert len(records) == 1 and records[0].unit == "ssh.service"
    assert status.available is True and status.unit_files_available is False
    assert status.error is not None and "malformed" in status.error.casefold()


def test_matches_filters_search_state_and_scope() -> None:
    running = ServiceRecord(
        ServiceIdentity("system", "ssh.service"), "OpenSSH server daemon", True,
        "loaded", "active", "running", "enabled",
    )
    exited = ServiceRecord(
        ServiceIdentity("system", "apparmor.service"), "Load AppArmor profiles", True,
        "loaded", "active", "exited", "enabled",
    )
    stopped = ServiceRecord(
        ServiceIdentity("user", "backup.service"), "Personal backup", True,
        "loaded", "inactive", "dead", "disabled",
    )
    failed = ServiceRecord(
        ServiceIdentity("system", "broken.service"), "Broken helper", True,
        "loaded", "failed", "failed", "enabled",
    )
    unknown = ServiceRecord(
        ServiceIdentity("system", "weird.service"), "Custom unit", True,
        "loaded", "mystery", None, None,
    )
    sample = (running, exited, stopped, failed, unknown)

    assert [r.unit for r in sample if matches_filters(r, state_filter="running")] == ["ssh.service"]
    assert [r.unit for r in sample if matches_filters(r, state_filter="active_other")] == ["apparmor.service"]
    assert [r.unit for r in sample if matches_filters(r, state_filter="inactive")] == ["backup.service"]
    assert [r.unit for r in sample if matches_filters(r, state_filter="failed")] == ["broken.service"]
    assert [r.unit for r in sample if matches_filters(r, scope_filter="user")] == ["backup.service"]
    assert [r.unit for r in sample if matches_filters(r, query="apparmor profiles")] == ["apparmor.service"]
    assert [r.unit for r in sample if matches_filters(r, query="ssh", scope_filter="user")] == []


def test_run_systemctl_enforces_timeout_and_stop_cancellation() -> None:
    start = time.monotonic()
    timed_out = run_systemctl([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.15)
    assert timed_out.timed_out is True
    assert time.monotonic() - start < 2.0

    stop = Event()
    start = time.monotonic()

    def trigger_stop() -> None:
        time.sleep(0.1)
        stop.set()

    import threading

    timer = threading.Thread(target=trigger_stop, daemon=True)
    timer.start()
    cancelled = run_systemctl([sys.executable, "-c", "import time; time.sleep(10)"], timeout=5.0, stop=stop)
    timer.join(timeout=1.0)
    assert cancelled.cancelled is True
    assert time.monotonic() - start < 2.0
