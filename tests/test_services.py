from collections.abc import Sequence
import json
import sys
import threading
from threading import Event
import time

import pytest

from taskpup.services import (
    SHOW_BATCH_SIZE,
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
    parse_list_units_json,
    parse_show_output,
    parse_unit_files_json,
    run_systemctl,
)


def _explicit_show_units(args: Sequence[str]) -> tuple[str, ...]:
    """Return explicit unit arguments passed after `--` to `systemctl show`."""
    if "--" not in args:
        return ()
    marker = args.index("--")
    return tuple(args[marker + 1 :])


def test_parse_list_units_json_filters_services_and_rejects_empty_or_malformed() -> None:
    payload = json.dumps(
        [
            {
                "unit": "accounts-daemon.service",
                "load": "loaded",
                "active": "active",
                "sub": "running",
                "description": "Accounts Service",
            },
            {
                "unit": "casper-md5check.service",
                "load": "loaded",
                "active": "failed",
                "sub": "failed",
                "description": "Verify checksums",
            },
            {
                "unit": "basic.target",
                "load": "loaded",
                "active": "active",
                "sub": "active",
                "description": "Basic System",
            },
        ]
    )
    entries = parse_list_units_json(payload)
    assert len(entries) == 2
    assert entries[0].unit == "accounts-daemon.service"
    assert (entries[0].load_state, entries[0].active_state, entries[0].sub_state) == ("loaded", "active", "running")
    assert entries[1].unit == "casper-md5check.service"
    assert (entries[1].active_state, entries[1].sub_state) == ("failed", "failed")

    # Genuine empty inventory is JSON `[]`, whereas empty/truncated stdout is malformed.
    assert parse_list_units_json("[]\n") == []
    with pytest.raises(MalformedOutputError):
        parse_list_units_json("")
    with pytest.raises(MalformedOutputError):
        parse_list_units_json("{not json")
    with pytest.raises(MalformedOutputError):
        parse_list_units_json(json.dumps({"unit": "ssh.service"}))
    with pytest.raises(MalformedOutputError):
        parse_list_units_json(json.dumps([{"load": "loaded"}]))


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
    assert parse_unit_files_json("[]") == []
    with pytest.raises(MalformedOutputError):
        parse_unit_files_json("")
    with pytest.raises(MalformedOutputError):
        parse_unit_files_json("{not json")
    with pytest.raises(MalformedOutputError):
        parse_unit_files_json(json.dumps({"unit_file": "ssh.service"}))
    with pytest.raises(MalformedOutputError):
        parse_unit_files_json(json.dumps([{"state": "enabled"}]))


def test_parse_show_output_rejects_empty_manager_or_malformed_blocks() -> None:
    with pytest.raises(MalformedOutputError):
        parse_show_output("   \n")
    with pytest.raises(MalformedOutputError):
        parse_show_output("not a key value line\n")
    # Manager properties returned by unit-less `systemctl show` have no Id field.
    with pytest.raises(MalformedOutputError):
        parse_show_output("Version=255\nArchitecture=x86-64\n")


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


def test_discover_scope_enumerates_via_list_units_and_uses_explicit_batched_show() -> None:
    """Regression test for P1: never rely on unit-less `systemctl show` for enumeration."""
    recorded_commands: list[tuple[str, ...]] = []
    loaded_units = [
        {
            "unit": "ssh.service",
            "load": "loaded",
            "active": "active",
            "sub": "running",
            "description": "OpenBSD Secure Shell server",
        },
        {
            "unit": "casper-md5check.service",
            "load": "loaded",
            "active": "failed",
            "sub": "failed",
            "description": "Verify Live ISO checksums",
        },
        {
            "unit": "apparmor.service",
            "load": "loaded",
            "active": "active",
            "sub": "exited",
            "description": "Load AppArmor profiles",
        },
    ]
    unit_files = [
        {"unit_file": "ssh.service", "state": "enabled", "preset": "enabled"},
        {"unit_file": "casper-md5check.service", "state": "enabled", "preset": "enabled"},
        {"unit_file": "apparmor.service", "state": "enabled", "preset": "enabled"},
        {"unit_file": "brltty.service", "state": "disabled", "preset": "enabled"},
        {"unit_file": "alsa-utils.service", "state": "masked", "preset": "enabled"},
    ]
    show_blocks = {
        "ssh.service": (
            "Id=ssh.service\nDescription=OpenBSD Secure Shell server\nLoadState=loaded\n"
            "ActiveState=active\nSubState=running\nUnitFileState=enabled\nUnitFilePreset=enabled\n"
            "FragmentPath=/usr/lib/systemd/system/ssh.service\nMainPID=900\nType=notify\nTransient=no\nResult=success"
        ),
        "casper-md5check.service": (
            "Id=casper-md5check.service\nDescription=Verify Live ISO checksums\nLoadState=loaded\n"
            "ActiveState=failed\nSubState=failed\nUnitFileState=enabled\nUnitFilePreset=enabled\n"
            "FragmentPath=/usr/lib/systemd/system/casper-md5check.service\nMainPID=0\nType=oneshot\n"
            "Transient=no\nResult=exit-code"
        ),
        "apparmor.service": (
            "Id=apparmor.service\nDescription=Load AppArmor profiles\nLoadState=loaded\n"
            "ActiveState=active\nSubState=exited\nUnitFileState=enabled\nUnitFilePreset=enabled\n"
            "FragmentPath=/usr/lib/systemd/system/apparmor.service\nMainPID=0\nType=oneshot\n"
            "Transient=no\nResult=success"
        ),
    }

    def realistic_systemd(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        cmd = tuple(args)
        recorded_commands.append(cmd)
        if "list-units" in cmd:
            return CommandResult(0, json.dumps(loaded_units), "")
        if "show" in cmd:
            explicit_units = _explicit_show_units(cmd)
            if not explicit_units:
                # Realistic systemd behavior when `systemctl show` is called without unit names:
                # returns manager properties (or empty output when filtered to unit-only properties).
                return CommandResult(0, "Version=252\nArchitecture=x86-64\n", "")
            return CommandResult(0, "\n\n".join(show_blocks[u] for u in explicit_units) + "\n", "")
        if "list-unit-files" in cmd:
            return CommandResult(0, json.dumps(unit_files), "")
        raise AssertionError(f"Unexpected systemctl command: {cmd}")

    records, status = discover_scope("system", runner=realistic_systemd)
    assert status.available is True and status.unit_files_available is True and status.error is None

    # Verify exact command structure: list-units first, explicit batched show second, list-unit-files third.
    assert recorded_commands[0] == (
        "systemctl", "list-units", "--type=service", "--all", "--output=json", "--no-pager", "--no-legend",
    )
    show_commands = [cmd for cmd in recorded_commands if "show" in cmd]
    assert len(show_commands) == 1
    assert "--type=service" not in show_commands[0]
    assert "--all" not in show_commands[0]
    assert _explicit_show_units(show_commands[0]) == ("ssh.service", "casper-md5check.service", "apparmor.service")
    assert recorded_commands[-1] == (
        "systemctl", "list-unit-files", "--type=service", "--output=json", "--no-pager", "--no-legend",
    )

    by_unit = {record.unit: record for record in records}
    assert by_unit["ssh.service"].loaded is True
    assert by_unit["ssh.service"].state_label == "Running"
    assert by_unit["ssh.service"].enablement_label == "Enabled"
    assert by_unit["ssh.service"].main_pid == 900
    assert by_unit["ssh.service"].fragment_path == "/usr/lib/systemd/system/ssh.service"

    assert by_unit["casper-md5check.service"].loaded is True
    assert by_unit["casper-md5check.service"].state_label == "Failed"
    assert by_unit["casper-md5check.service"].result == "exit-code"

    assert by_unit["apparmor.service"].loaded is True
    assert by_unit["apparmor.service"].state_label == "Active (exited)"

    # Genuinely unloaded installed services remain distinct from loaded services.
    assert by_unit["brltty.service"].loaded is False
    assert by_unit["brltty.service"].state_label == "Inactive (not loaded)"
    assert by_unit["brltty.service"].enablement_label == "Disabled"
    assert by_unit["alsa-utils.service"].loaded is False
    assert by_unit["alsa-utils.service"].state_label == "Inactive (masked)"
    assert by_unit["alsa-utils.service"].enablement_label == "Masked"


def test_discover_scope_batches_show_for_large_inventory_and_skips_show_when_empty() -> None:
    total = SHOW_BATCH_SIZE + 5
    loaded_units = [
        {
            "unit": f"svc-{idx:03d}.service",
            "load": "loaded",
            "active": "active",
            "sub": "running",
            "description": f"Service {idx}",
        }
        for idx in range(total)
    ]
    show_batches: list[tuple[str, ...]] = []

    def large_runner(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "list-units" in args:
            return CommandResult(0, json.dumps(loaded_units), "")
        if "show" in args:
            units = _explicit_show_units(args)
            assert 0 < len(units) <= SHOW_BATCH_SIZE
            show_batches.append(units)
            blocks = [f"Id={u}\nMainPID={1000 + i}\nFragmentPath=/usr/lib/systemd/system/{u}" for i, u in enumerate(units)]
            return CommandResult(0, "\n\n".join(blocks) + "\n", "")
        return CommandResult(0, "[]", "")

    records, status = discover_scope("system", runner=large_runner)
    assert status.available is True and status.error is None
    assert len(records) == total
    assert [len(batch) for batch in show_batches] == [SHOW_BATCH_SIZE, 5]

    # Genuine empty inventory: `list-units` returns `[]`, `show` is NOT called at all.
    empty_commands: list[tuple[str, ...]] = []

    def empty_runner(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        empty_commands.append(tuple(args))
        return CommandResult(0, "[]\n", "")

    empty_records, empty_status = discover_scope("user", runner=empty_runner)
    assert empty_records == ()
    assert empty_status.available is True and empty_status.unit_files_available is True and empty_status.error is None
    assert not any("show" in cmd for cmd in empty_commands)


def test_discover_services_keeps_system_and_user_scopes_distinct_and_handles_unavailable_user() -> None:
    sys_units = json.dumps(
        [{"unit": "dbus.service", "load": "loaded", "active": "active", "sub": "running", "description": "System D-Bus"}]
    )
    user_units = json.dumps(
        [{"unit": "dbus.service", "load": "loaded", "active": "active", "sub": "running", "description": "User D-Bus"}]
    )
    sys_show = (
        "Id=dbus.service\nDescription=System D-Bus\nLoadState=loaded\n"
        "ActiveState=active\nSubState=running\nUnitFileState=static\n"
    )
    user_show = (
        "Id=dbus.service\nDescription=User D-Bus\nLoadState=loaded\n"
        "ActiveState=active\nSubState=running\nUnitFileState=static\n"
    )

    def both_ok(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        is_user = "--user" in args
        if "list-units" in args:
            return CommandResult(0, user_units if is_user else sys_units, "")
        if "show" in args:
            assert _explicit_show_units(args) == ("dbus.service",)
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
        if "list-units" in args:
            return CommandResult(0, sys_units, "")
        if "show" in args:
            assert _explicit_show_units(args) == ("dbus.service",)
            return CommandResult(0, sys_show, "")
        return CommandResult(0, "[]", "")

    degraded = discover_services(runner=user_unavailable)
    assert degraded.system.available is True
    assert degraded.user.available is False
    assert degraded.user.error is not None and "User systemd manager unavailable" in degraded.user.error
    assert [record.identity for record in degraded.services] == [ServiceIdentity("system", "dbus.service")]


def test_discover_scope_handles_failures_empty_stdout_and_partial_metadata_or_unit_file_errors() -> None:
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

    # Empty stdout from list-units must never be silently treated as an empty inventory.
    def empty_stdout(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        return CommandResult(0, "", "")

    records, status = discover_scope("system", runner=empty_stdout)
    assert records == () and not status.available
    assert status.error is not None and "malformed" in status.error.casefold()

    # If batched `show` fails, runtime states from `list-units` and enablement from `list-unit-files` survive.
    def show_fails_list_units_ok(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "list-units" in args:
            return CommandResult(
                0,
                json.dumps(
                    [
                        {"unit": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": "OpenSSH"},
                        {"unit": "bad.service", "load": "loaded", "active": "failed", "sub": "failed", "description": "Bad"},
                    ]
                ),
                "",
            )
        if "show" in args:
            return CommandResult(0, "Version=252\n", "")
        return CommandResult(
            0,
            json.dumps([{"unit_file": "ssh.service", "state": "enabled", "preset": "enabled"}]),
            "",
        )

    records, status = discover_scope("system", runner=show_fails_list_units_ok)
    by_unit = {r.unit: r for r in records}
    assert status.available is True and status.unit_files_available is True
    assert status.error is not None and "metadata" in status.error.casefold()
    assert by_unit["ssh.service"].state_label == "Running"
    assert by_unit["ssh.service"].enablement_label == "Enabled"
    assert by_unit["ssh.service"].fragment_path is None
    assert by_unit["bad.service"].state_label == "Failed"
    assert by_unit["bad.service"].enablement_label == "Unavailable"

    # Partial failure on list-unit-files preserves loaded services and surfaces a warning.
    def partial_bad_unit_files(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "list-units" in args:
            return CommandResult(
                0,
                json.dumps([{"unit": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": "OpenSSH"}]),
                "",
            )
        if "show" in args:
            return CommandResult(
                0,
                "Id=ssh.service\nDescription=OpenSSH\nLoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n",
                "",
            )
        return CommandResult(0, "{broken json", "")

    records, status = discover_scope("system", runner=partial_bad_unit_files)
    assert len(records) == 1 and records[0].unit == "ssh.service"
    assert records[0].state_label == "Running" and records[0].enablement_label == "Enabled"
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

    timer = threading.Thread(target=trigger_stop, daemon=True)
    timer.start()
    cancelled = run_systemctl([sys.executable, "-c", "import time; time.sleep(10)"], timeout=5.0, stop=stop)
    timer.join(timeout=1.0)
    assert cancelled.cancelled is True
    assert time.monotonic() - start < 2.0
