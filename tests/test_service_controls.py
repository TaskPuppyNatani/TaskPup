from collections.abc import Sequence
from threading import Event

import pytest

from taskpup.service_controls import (
    SERVICE_ACTIONS,
    ServiceValidationError,
    assess_service_risk,
    build_control_command,
    evaluate_service_actions,
    execute_service_action,
    validate_service_unit,
)
from taskpup.services import (
    CommandResult,
    ServiceIdentity,
    ServiceRecord,
    ServiceScope,
    parse_show_output,
)


def make_record(
    unit: str,
    *,
    scope: ServiceScope = "system",
    loaded: bool = True,
    load_state: str | None = "loaded",
    active_state: str | None = "active",
    sub_state: str | None = "running",
    unit_file_state: str | None = "enabled",
    transient: bool | None = False,
    can_start: bool | None = True,
    can_stop: bool | None = True,
    refuse_manual_start: bool | None = False,
    refuse_manual_stop: bool | None = False,
    triggered_by: tuple[str, ...] | None = (),
    required_by: tuple[str, ...] | None = (),
    part_of: tuple[str, ...] | None = (),
) -> ServiceRecord:
    return ServiceRecord(
        identity=ServiceIdentity(scope, unit),
        description=f"Test {unit}",
        loaded=loaded,
        load_state=load_state,
        active_state=active_state,
        sub_state=sub_state,
        unit_file_state=unit_file_state,
        transient=transient,
        can_start=can_start,
        can_stop=can_stop,
        refuse_manual_start=refuse_manual_start,
        refuse_manual_stop=refuse_manual_stop,
        triggered_by=triggered_by,
        required_by=required_by,
        part_of=part_of,
    )


@pytest.mark.parametrize(
    "valid_unit",
    [
        "cups.service",
        "getty@tty1.service",
        "user@1000.service",
        r"app-at\x2dspi\x2ddbus\x2dbus@autostart.service",
        "foo_bar:1.2-test.service",
    ],
)
def test_validate_service_unit_accepts_valid_concrete_units(valid_unit: str) -> None:
    assert validate_service_unit(valid_unit) == valid_unit


@pytest.mark.parametrize(
    "invalid_unit",
    [
        "",
        " ",
        " cups.service",
        "cups.service ",
        "cups.timer",
        "basic.target",
        ".service",
        "getty@.service",
        "foo@a@b.service",
        "cups*.service",
        "cups?.service",
        "cups[0].service",
        "/usr/lib/systemd/system/cups.service",
        "../cups.service",
        "-cups.service",
        ".hidden.service",
        "@leading.service",
        "cups.service;rm",
        "cups.service\nssh.service",
        r"bad\escape.service",
        "a" * 250 + ".service",
    ],
)
def test_validate_service_unit_rejects_invalid_or_dangerous_inputs(invalid_unit: str) -> None:
    with pytest.raises(ServiceValidationError):
        validate_service_unit(invalid_unit)


def test_build_control_command_uses_strict_args_and_separate_scopes() -> None:
    for action in SERVICE_ACTIONS:
        sys_cmd = build_control_command(ServiceIdentity("system", "cups.service"), action)
        assert sys_cmd == ("systemctl", "--system", action, "--", "cups.service")
        assert "--now" not in sys_cmd
        assert "--no-ask-password" not in sys_cmd
        assert "--force" not in sys_cmd

        user_cmd = build_control_command(ServiceIdentity("user", "pipewire.service"), action)
        assert user_cmd == ("systemctl", "--user", action, "--", "pipewire.service")

    with pytest.raises(ServiceValidationError):
        build_control_command(ServiceIdentity("system", "cups*.service"), "stop")
    with pytest.raises(ServiceValidationError):
        build_control_command(ServiceIdentity("system", "cups.service"), "mask")  # type: ignore[arg-type]


def test_parse_show_output_captures_capability_and_dependency_properties() -> None:
    raw = "\n".join(
        [
            "Id=pk-debconf-helper.service",
            "Description=Debconf helper",
            "LoadState=loaded",
            "ActiveState=inactive",
            "SubState=dead",
            "UnitFileState=static",
            "CanStart=no",
            "CanStop=yes",
            "RefuseManualStart=yes",
            "RefuseManualStop=no",
            "TriggeredBy=pk-debconf-helper.socket",
            "RequiredBy=multi-user.target",
            "PartOf=graphical-session.target",
        ]
    )
    entries = parse_show_output(raw)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.can_start is False
    assert entry.can_stop is True
    assert entry.refuse_manual_start is True
    assert entry.refuse_manual_stop is False
    assert entry.triggered_by == ("pk-debconf-helper.socket",)
    assert entry.required_by == ("multi-user.target",)
    assert entry.part_of == ("graphical-session.target",)


def test_evaluate_service_actions_honors_systemd_semantics_and_protections() -> None:
    # Active + enabled ordinary service -> Stop, Restart, Disable allowed; Start, Enable blocked.
    running_enabled = make_record("cups.service", active_state="active", sub_state="running", unit_file_state="enabled")
    avail = evaluate_service_actions(running_enabled, current_uid=1000)
    assert not avail["start"].allowed
    assert avail["stop"].allowed
    assert avail["restart"].allowed
    assert not avail["enable"].allowed
    assert avail["disable"].allowed

    # Inactive + disabled unloaded service -> Start and Enable allowed; Stop, Restart, Disable blocked.
    unloaded_disabled = make_record(
        "brltty.service", loaded=False, load_state=None, active_state=None, sub_state=None, unit_file_state="disabled",
        can_start=None, can_stop=None, refuse_manual_start=None, refuse_manual_stop=None,
    )
    avail = evaluate_service_actions(unloaded_disabled, current_uid=1000)
    assert avail["start"].allowed
    assert not avail["stop"].allowed
    assert not avail["restart"].allowed
    assert avail["enable"].allowed
    assert not avail["disable"].allowed

    # Failed + enabled service -> Start and Disable allowed; Stop and Restart blocked.
    failed_enabled = make_record("casper-md5check.service", active_state="failed", sub_state="failed", unit_file_state="enabled")
    avail = evaluate_service_actions(failed_enabled, current_uid=1000)
    assert avail["start"].allowed and not avail["stop"].allowed and not avail["restart"].allowed
    assert not avail["enable"].allowed and avail["disable"].allowed

    # Static, generated, transient, indirect, enabled-runtime, unavailable enablement -> Enable & Disable blocked.
    for uf_state in ("static", "generated", "transient", "indirect", "enabled-runtime", "linked", None):
        rec = make_record("helper.service", active_state="inactive", sub_state="dead", unit_file_state=uf_state)
        avail = evaluate_service_actions(rec, current_uid=1000)
        assert not avail["enable"].allowed, f"enable should be blocked for {uf_state}"
        assert not avail["disable"].allowed, f"disable should be blocked for {uf_state}"

    # RefuseManualStart / CanStart=no blocks Start and Restart.
    no_manual_start = make_record(
        "pk-debconf-helper.service", scope="user", active_state="inactive", sub_state="dead",
        unit_file_state="static", can_start=False, refuse_manual_start=True,
    )
    avail = evaluate_service_actions(no_manual_start, current_uid=1000)
    assert not avail["start"].allowed and "prohibits" in (avail["start"].reason or "").casefold()
    assert not avail["restart"].allowed

    # RefuseManualStop / CanStop=no blocks Stop and Restart on active service.
    no_manual_stop = make_record("immutable.service", active_state="active", can_stop=False, refuse_manual_stop=True)
    avail = evaluate_service_actions(no_manual_stop, current_uid=1000)
    assert not avail["stop"].allowed and not avail["restart"].allowed

    # Masked, template, alias, not-found, transitioning, unknown runtime -> properly blocked.
    for blocked_rec in (
        make_record("alsa-utils.service", loaded=False, load_state=None, active_state=None, sub_state=None, unit_file_state="masked"),
        make_record("getty@.service", loaded=False, load_state=None, active_state=None, sub_state=None, unit_file_state="enabled"),
        make_record("display-manager.service", loaded=False, load_state=None, active_state=None, sub_state=None, unit_file_state="alias"),
        make_record("auditd.service", load_state="not-found", active_state="inactive", sub_state="dead", unit_file_state=None),
    ):
        avail = evaluate_service_actions(blocked_rec, current_uid=1000)
        assert all(not state.allowed for state in avail.values())

    unknown_runtime = make_record("weird.service", active_state="mystery", sub_state=None, unit_file_state="disabled")
    avail = evaluate_service_actions(unknown_runtime, current_uid=1000)
    assert not avail["start"].allowed and not avail["stop"].allowed and not avail["restart"].allowed

    transitioning = make_record("restarting.service", active_state="activating", sub_state="auto-restart", unit_file_state="enabled")
    avail = evaluate_service_actions(transitioning, current_uid=1000)
    assert not avail["start"].allowed and not avail["stop"].allowed and not avail["restart"].allowed

    # Protected core system infrastructure: dbus.service, polkit.service, active user@1000.service.
    sys_dbus = make_record("dbus.service", scope="system", active_state="active", unit_file_state="static")
    avail = evaluate_service_actions(sys_dbus, current_uid=1000)
    assert not avail["stop"].allowed and not avail["restart"].allowed

    user_mgr = make_record("user@1000.service", scope="system", active_state="active", unit_file_state="static")
    avail = evaluate_service_actions(user_mgr, current_uid=1000)
    assert not avail["stop"].allowed and not avail["restart"].allowed


def test_assess_service_risk_classifies_critical_dependencies_and_triggers() -> None:
    nm = make_record("NetworkManager.service", active_state="active", unit_file_state="enabled")
    nm_risk = assess_service_risk(nm, "stop", current_uid=1000)
    assert nm_risk.level == "high" and nm_risk.category == "Network Management"

    dm = make_record("lightdm.service", active_state="active", unit_file_state="indirect")
    dm_risk = assess_service_risk(dm, "restart", current_uid=1000)
    assert dm_risk.level == "high" and dm_risk.category == "Display & Desktop Session"

    # Authoritative RequiredBy escalates even an otherwise ordinary service, and TriggeredBy adds activation note.
    cups = make_record(
        "cups.service",
        active_state="active",
        unit_file_state="enabled",
        triggered_by=("cups.socket",),
        required_by=("cups-browsed.service",),
    )
    cups_risk = assess_service_risk(cups, "stop", current_uid=1000)
    assert cups_risk.level == "high"
    assert any("cups-browsed.service" in w for w in cups_risk.warnings)
    assert any("cups.socket" in n and "automatically" in n for n in cups_risk.notes)

    # Ordinary non-disruptive start has normal risk.
    brltty = make_record("brltty.service", active_state="inactive", sub_state="dead", unit_file_state="disabled")
    assert assess_service_risk(brltty, "start", current_uid=1000).level == "normal"


def _show_block(
    unit: str,
    *,
    load: str = "loaded",
    active: str = "inactive",
    sub: str = "dead",
    unit_file: str = "disabled",
    can_start: str = "yes",
    can_stop: str = "yes",
    refuse_start: str = "no",
    refuse_stop: str = "no",
    required_by: str | None = "",
    part_of: str | None = "",
) -> str:
    lines = [
        f"Id={unit}",
        f"LoadState={load}",
        f"ActiveState={active}",
        f"SubState={sub}",
        f"UnitFileState={unit_file}",
    ]
    if can_start:
        lines.append(f"CanStart={can_start}")
    if can_stop:
        lines.append(f"CanStop={can_stop}")
    if refuse_start:
        lines.append(f"RefuseManualStart={refuse_start}")
    if refuse_stop:
        lines.append(f"RefuseManualStop={refuse_stop}")
    if required_by is not None:
        lines.append(f"RequiredBy={required_by}")
    if part_of is not None:
        lines.append(f"PartOf={part_of}")
    return "\n".join(lines) + "\n"


def test_p1_protected_services_blocked_at_execution_boundary_without_invoking_runner() -> None:
    """Reproduces P1: direct execution against protected services must never invoke the runner."""
    invoked: list[tuple[str, ...]] = []

    def fake_runner(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        invoked.append(tuple(args))
        return CommandResult(0, "", "")

    for identity, action in (
        (ServiceIdentity("system", "dbus.service"), "stop"),
        (ServiceIdentity("system", "dbus.service"), "restart"),
        (ServiceIdentity("system", "polkit.service"), "stop"),
        (ServiceIdentity("system", "systemd-logind.service"), "disable"),
        (ServiceIdentity("system", "user@1000.service"), "stop"),
    ):
        for acknowledged in (False, True):
            res = execute_service_action(
                identity,
                action,  # type: ignore[arg-type]
                high_risk_acknowledged=acknowledged,
                runner=fake_runner,
                current_uid=1000,
            )
            assert res.outcome == "failed"
            assert "blocked" in res.summary.casefold()
    assert invoked == []


def test_p1_execution_boundary_enforces_high_risk_eligibility_capabilities_and_metadata() -> None:
    mutating_calls: list[tuple[str, ...]] = []

    # 1. High-risk system service requires explicit high_risk_acknowledged=True.
    def nm_runner(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "show" in args:
            if mutating_calls:
                return CommandResult(0, _show_block("NetworkManager.service", active="inactive", sub="dead", unit_file="enabled"), "")
            return CommandResult(0, _show_block("NetworkManager.service", active="active", sub="running", unit_file="enabled"), "")
        mutating_calls.append(tuple(args))
        return CommandResult(0, "", "")

    blocked = execute_service_action(
        ServiceIdentity("system", "NetworkManager.service"),
        "stop",
        high_risk_acknowledged=False,
        runner=nm_runner,
    )
    assert blocked.outcome == "failed" and "high-risk" in blocked.summary.casefold()
    assert mutating_calls == []

    allowed = execute_service_action(
        ServiceIdentity("system", "NetworkManager.service"),
        "stop",
        high_risk_acknowledged=True,
        runner=nm_runner,
    )
    assert allowed.outcome == "succeeded"
    assert mutating_calls == [("systemctl", "--system", "stop", "--", "NetworkManager.service")]

    # 2. User-scope dbus.service preserves scope separation: high-risk (not system-protected).
    mutating_calls.clear()

    def user_dbus_runner(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "show" in args:
            assert "--user" in args
            if mutating_calls:
                return CommandResult(0, _show_block("dbus.service", active="inactive", sub="dead", unit_file="static"), "")
            return CommandResult(0, _show_block("dbus.service", active="active", sub="running", unit_file="static"), "")
        mutating_calls.append(tuple(args))
        return CommandResult(0, "", "")

    assert execute_service_action(ServiceIdentity("user", "dbus.service"), "stop", runner=user_dbus_runner).outcome == "failed"
    assert mutating_calls == []
    res = execute_service_action(
        ServiceIdentity("user", "dbus.service"), "stop", high_risk_acknowledged=True, runner=user_dbus_runner,
    )
    assert res.outcome == "succeeded"
    assert mutating_calls == [("systemctl", "--user", "stop", "--", "dbus.service")]

    # 3. Dynamic RequiredBy escalates to high-risk at execution time even for ordinary unit names.
    mutating_calls.clear()

    def required_by_runner(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "show" in args:
            return CommandResult(
                0,
                _show_block("cups.service", active="active", sub="running", unit_file="enabled", required_by="cups-browsed.service"),
                "",
            )
        mutating_calls.append(tuple(args))
        return CommandResult(0, "", "")

    res = execute_service_action(ServiceIdentity("system", "cups.service"), "stop", runner=required_by_runner)
    assert res.outcome == "failed" and "high-risk" in res.summary.casefold()
    assert mutating_calls == []

    # 4. Caller bypassing GUI eligibility (already active start, restricted CanStart/CanStop, static enable).
    for unit, action, show_text in (
        ("cups.service", "start", _show_block("cups.service", active="active", sub="running", unit_file="enabled")),
        ("pk-debconf-helper.service", "start", _show_block("pk-debconf-helper.service", can_start="no", refuse_start="yes")),
        ("immutable.service", "stop", _show_block("immutable.service", active="active", sub="running", can_stop="no", refuse_stop="yes")),
        ("alsa-restore.service", "enable", _show_block("alsa-restore.service", unit_file="static")),
        ("alsa-utils.service", "start", _show_block("alsa-utils.service", load="masked", unit_file="masked", can_start="no")),
    ):
        mutating_calls.clear()

        def bypass_runner(args: Sequence[str], timeout: float, stop: Event | None, payload: str = show_text) -> CommandResult:
            if "show" in args:
                return CommandResult(0, payload, "")
            mutating_calls.append(tuple(args))
            return CommandResult(0, "", "")

        res = execute_service_action(
            ServiceIdentity("system", unit),
            action,  # type: ignore[arg-type]
            high_risk_acknowledged=True,
            runner=bypass_runner,
        )
        assert res.outcome == "failed", f"Expected {action} on {unit} to be rejected"
        assert mutating_calls == []

    # 5. Missing, malformed, insufficient capability metadata, or alias Id mismatch rejects safely.
    for unit, action, pre_result in (
        ("cups.service", "start", CommandResult(1, "", "Failed to connect to bus")),
        ("cups.service", "start", CommandResult(0, "corrupted output without equals", "")),
        ("cups.service", "start", CommandResult(0, _show_block("cups.service", can_start="", refuse_start=""), "")),
        ("cups.service", "stop", CommandResult(0, _show_block("cups.service", active="active", sub="running", can_stop="", refuse_stop=""), "")),
        ("display-manager.service", "stop", CommandResult(0, _show_block("lightdm.service", active="active", sub="running"), "")),
    ):
        mutating_calls.clear()

        def bad_meta_runner(args: Sequence[str], timeout: float, stop: Event | None, res_obj: CommandResult = pre_result) -> CommandResult:
            if "show" in args:
                return res_obj
            mutating_calls.append(tuple(args))
            return CommandResult(0, "", "")

        res = execute_service_action(
            ServiceIdentity("system", unit),
            action,  # type: ignore[arg-type]
            high_risk_acknowledged=True,
            runner=bad_meta_runner,
        )
        assert res.outcome == "failed"
        assert mutating_calls == []


def test_p2_missing_dependency_metadata_rejects_disruptive_actions_and_preserves_three_way_semantics() -> None:
    """Reproduces P2: incomplete systemctl show omitting RequiredBy/PartOf must never allow dispatch."""
    # Parser preserves the 3-way distinction: populated tuple vs explicit empty tuple vs None (missing / n/a).
    parsed = parse_show_output(
        "\n".join(
            [
                "Id=explicit-empty.service",
                "LoadState=loaded",
                "ActiveState=active",
                "RequiredBy=",
                "PartOf=   ",
                "",
                "Id=populated.service",
                "LoadState=loaded",
                "ActiveState=active",
                "RequiredBy=cups-browsed.service",
                "PartOf=printing.target",
                "",
                "Id=missing.service",
                "LoadState=loaded",
                "ActiveState=active",
                "",
                "Id=unavailable.service",
                "LoadState=loaded",
                "ActiveState=active",
                "RequiredBy=n/a",
                "PartOf=n/a",
            ]
        )
    )
    by_unit = {entry.unit: entry for entry in parsed}
    assert by_unit["explicit-empty.service"].required_by == ()
    assert by_unit["explicit-empty.service"].part_of == ()
    assert by_unit["populated.service"].required_by == ("cups-browsed.service",)
    assert by_unit["populated.service"].part_of == ("printing.target",)
    assert by_unit["missing.service"].required_by is None
    assert by_unit["missing.service"].part_of is None
    assert by_unit["unavailable.service"].required_by is None
    assert by_unit["unavailable.service"].part_of is None

    # 1. Principal reproduction: successful but incomplete read-only `systemctl show` omitting RequiredBy
    # must NOT permit an unacknowledged Stop to reach the mutating command runner.
    mutating_calls: list[tuple[str, ...]] = []
    incomplete_stop_show = _show_block(
        "cups.service",
        active="active",
        sub="running",
        unit_file="enabled",
        required_by=None,
        part_of="",
    )

    def omitted_required_by_runner(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "show" in args:
            return CommandResult(0, incomplete_stop_show, "")
        mutating_calls.append(tuple(args))
        return CommandResult(0, "", "")

    repro = execute_service_action(
        ServiceIdentity("system", "cups.service"),
        "stop",
        high_risk_acknowledged=False,
        runner=omitted_required_by_runner,
    )
    assert repro.outcome == "failed"
    assert "RequiredBy" in repro.summary and "safely evaluated" in repro.summary.casefold()
    assert mutating_calls == []

    # 2. Missing RequiredBy only, missing PartOf only, both missing, or n/a -> blocked for stop/restart/disable,
    # and high_risk_acknowledged=True MUST NOT override missing mandatory metadata.
    for action in ("stop", "restart", "disable"):
        for required_by_val, part_of_val, expected_tokens in (
            (None, "", ("RequiredBy",)),
            ("", None, ("PartOf",)),
            ("cups-browsed.service", None, ("PartOf",)),
            (None, "printing.target", ("RequiredBy",)),
            (None, None, ("RequiredBy", "PartOf")),
            ("n/a", "", ("RequiredBy",)),
            ("", "n/a", ("PartOf",)),
        ):
            payload = _show_block(
                "cups.service",
                active="active",
                sub="running",
                unit_file="enabled",
                required_by=required_by_val,
                part_of=part_of_val,
            )
            for acknowledged in (False, True):
                mutating_calls.clear()

                def incomplete_runner(
                    args: Sequence[str],
                    timeout: float,
                    stop: Event | None,
                    text: str = payload,
                ) -> CommandResult:
                    if "show" in args:
                        return CommandResult(0, text, "")
                    mutating_calls.append(tuple(args))
                    return CommandResult(0, "", "")

                res = execute_service_action(
                    ServiceIdentity("system", "cups.service"),
                    action,  # type: ignore[arg-type]
                    high_risk_acknowledged=acknowledged,
                    runner=incomplete_runner,
                )
                assert res.outcome == "failed", f"Expected failure for {action} (req={required_by_val!r}, part={part_of_val!r}, ack={acknowledged})"
                for token in expected_tokens:
                    assert token in res.summary
                assert "safely evaluated" in res.summary.casefold()
                assert mutating_calls == []

    # High-risk acknowledgement also cannot override missing dependency metadata for named high-risk units.
    mutating_calls.clear()
    nm_missing_deps = _show_block(
        "NetworkManager.service",
        active="active",
        sub="running",
        unit_file="enabled",
        required_by=None,
        part_of=None,
    )

    def nm_incomplete_runner(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "show" in args:
            return CommandResult(0, nm_missing_deps, "")
        mutating_calls.append(tuple(args))
        return CommandResult(0, "", "")

    nm_res = execute_service_action(
        ServiceIdentity("system", "NetworkManager.service"),
        "stop",
        high_risk_acknowledged=True,
        runner=nm_incomplete_runner,
    )
    assert nm_res.outcome == "failed" and "RequiredBy" in nm_res.summary and "PartOf" in nm_res.summary
    assert mutating_calls == []

    # 3. Both RequiredBy= and PartOf= explicitly present and empty -> valid operations proceed normally.
    for action, post_active, post_sub, post_uf in (
        ("stop", "inactive", "dead", "enabled"),
        ("restart", "active", "running", "enabled"),
        ("disable", "active", "running", "disabled"),
    ):
        mutating_calls.clear()

        def explicit_empty_runner(
            args: Sequence[str],
            timeout: float,
            stop: Event | None,
            pa: str = post_active,
            ps: str = post_sub,
            puf: str = post_uf,
        ) -> CommandResult:
            if "show" in args:
                if mutating_calls:
                    return CommandResult(
                        0,
                        _show_block("cups.service", active=pa, sub=ps, unit_file=puf, required_by="", part_of=""),
                        "",
                    )
                return CommandResult(
                    0,
                    _show_block("cups.service", active="active", sub="running", unit_file="enabled", required_by="", part_of=""),
                    "",
                )
            mutating_calls.append(tuple(args))
            return CommandResult(0, "", "")

        ok_res = execute_service_action(
            ServiceIdentity("system", "cups.service"),
            action,  # type: ignore[arg-type]
            high_risk_acknowledged=False,
            runner=explicit_empty_runner,
        )
        assert ok_res.outcome == "succeeded"
        assert mutating_calls == [("systemctl", "--system", action, "--", "cups.service")]

    # 4. Populated RequiredBy or PartOf triggers high-risk policy: blocked without ack, permitted with ack.
    for required_by_val, part_of_val in (
        ("cups-browsed.service", ""),
        ("", "printing.target"),
        ("cups-browsed.service", "printing.target"),
    ):
        mutating_calls.clear()

        def populated_dep_runner(
            args: Sequence[str],
            timeout: float,
            stop: Event | None,
            req: str = required_by_val,
            part: str = part_of_val,
        ) -> CommandResult:
            if "show" in args:
                if mutating_calls:
                    return CommandResult(
                        0,
                        _show_block("cups.service", active="inactive", sub="dead", unit_file="enabled", required_by=req, part_of=part),
                        "",
                    )
                return CommandResult(
                    0,
                    _show_block("cups.service", active="active", sub="running", unit_file="enabled", required_by=req, part_of=part),
                    "",
                )
            mutating_calls.append(tuple(args))
            return CommandResult(0, "", "")

        unacked = execute_service_action(
            ServiceIdentity("system", "cups.service"),
            "stop",
            high_risk_acknowledged=False,
            runner=populated_dep_runner,
        )
        assert unacked.outcome == "failed" and "high-risk" in unacked.summary.casefold()
        assert mutating_calls == []

        acked = execute_service_action(
            ServiceIdentity("system", "cups.service"),
            "stop",
            high_risk_acknowledged=True,
            runner=populated_dep_runner,
        )
        assert acked.outcome == "succeeded"
        assert mutating_calls == [("systemctl", "--system", "stop", "--", "cups.service")]

    # 5. Hard-protected services remain unconditionally blocked with zero runner invocations.
    protected_calls: list[tuple[str, ...]] = []

    def never_called(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        protected_calls.append(tuple(args))
        return CommandResult(0, "", "")

    prot_res = execute_service_action(
        ServiceIdentity("system", "dbus.service"),
        "stop",
        high_risk_acknowledged=True,
        runner=never_called,
    )
    assert prot_res.outcome == "failed" and "blocked" in prot_res.summary.casefold()
    assert protected_calls == []


def test_execute_service_action_reconciles_state_and_separates_runtime_and_enablement() -> None:
    commands: list[tuple[str, ...]] = []

    def ok_start(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        commands.append(tuple(args))
        if "show" in args:
            if any("start" in c for c in commands):
                return CommandResult(0, _show_block("cups.service", active="active", sub="running", unit_file="disabled"), "")
            return CommandResult(0, _show_block("cups.service", active="inactive", sub="dead", unit_file="disabled"), "")
        return CommandResult(0, "", "")

    res = execute_service_action(ServiceIdentity("system", "cups.service"), "start", runner=ok_start)
    assert res.outcome == "succeeded"
    assert res.verified_record is not None and res.verified_record.state_label == "Running"
    assert res.verified_record.enablement_label == "Disabled"
    assert len(commands) == 3
    assert commands[0][2] == "show"
    assert commands[1] == ("systemctl", "--system", "start", "--", "cups.service")
    assert commands[2][2] == "show"

    # Enable succeeds only when authoritative UnitFileState confirms enabled (and does not pass --now).
    commands.clear()

    def ok_enable(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        commands.append(tuple(args))
        if "show" in args:
            if any("enable" in c for c in commands):
                return CommandResult(0, _show_block("brltty.service", active="inactive", sub="dead", unit_file="enabled"), "")
            return CommandResult(0, _show_block("brltty.service", active="inactive", sub="dead", unit_file="disabled"), "")
        return CommandResult(0, "", "")

    res = execute_service_action(ServiceIdentity("user", "brltty.service"), "enable", runner=ok_enable)
    assert res.outcome == "succeeded"
    assert commands[1] == ("systemctl", "--user", "enable", "--", "brltty.service")
    assert res.verified_record is not None and res.verified_record.active_state == "inactive"

    # If start exits 0 but systemd reports the service is still failed, do not falsely report succeeded.
    seen_mut = False

    def start_ended_failed(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        nonlocal seen_mut
        if "show" in args:
            if seen_mut:
                return CommandResult(0, _show_block("broken.service", active="failed", sub="failed", unit_file="enabled"), "")
            return CommandResult(0, _show_block("broken.service", active="inactive", sub="dead", unit_file="enabled"), "")
        seen_mut = True
        return CommandResult(0, "", "")

    res = execute_service_action(ServiceIdentity("system", "broken.service"), "start", runner=start_ended_failed)
    assert res.outcome == "warning" and "Failed" in res.summary

    # If stop exits 0 but socket activation restarted the service immediately, warn honestly.
    def stop_reactivated(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "show" in args:
            return CommandResult(0, _show_block("cups.service", active="active", sub="running", unit_file="enabled"), "")
        return CommandResult(0, "", "")

    res = execute_service_action(ServiceIdentity("system", "cups.service"), "stop", runner=stop_reactivated)
    assert res.outcome == "warning" and "reactivated" in res.summary.casefold()


def test_execute_service_action_classifies_auth_timeout_interrupted_failure_and_invalid_unit() -> None:
    invoked: list[tuple[str, ...]] = []

    def never_run(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        invoked.append(tuple(args))
        return CommandResult(0, "", "")

    bad = execute_service_action(ServiceIdentity("system", "bad*.service"), "stop", runner=never_run)
    assert bad.outcome == "failed" and not invoked

    def missing_agent(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "show" in args:
            return CommandResult(0, _show_block("cups.service", active="inactive", sub="dead", unit_file="disabled"), "")
        return CommandResult(1, "", "Failed to start cups.service: Interactive authentication required.")

    res = execute_service_action(ServiceIdentity("system", "cups.service"), "start", runner=missing_agent)
    assert res.outcome == "auth_unavailable" and "Polkit" in res.summary

    def auth_denied(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "show" in args:
            return CommandResult(0, _show_block("cups.service", active="active", sub="running", unit_file="enabled"), "")
        return CommandResult(1, "", "Failed to stop cups.service: Access denied")

    res = execute_service_action(ServiceIdentity("system", "cups.service"), "stop", runner=auth_denied)
    assert res.outcome == "auth_cancelled"

    saw_restart = False

    def timed_out(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        nonlocal saw_restart
        if "show" in args:
            if saw_restart:
                return CommandResult(0, _show_block("slow.service", active="activating", sub="start", unit_file="enabled"), "")
            return CommandResult(0, _show_block("slow.service", active="active", sub="running", unit_file="enabled"), "")
        saw_restart = True
        return CommandResult(-1, "", "", timed_out=True)

    res = execute_service_action(ServiceIdentity("system", "slow.service"), "restart", runner=timed_out)
    assert res.outcome == "timed_out"
    assert "background" in res.summary.casefold()
    assert "Activating" in res.summary

    # Interruption after launching systemctl must report unknown/interrupted outcome, not false success or cancellation.
    def interrupted_mid_flight(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "show" in args:
            return CommandResult(0, _show_block("slow.service", active="active", sub="running", unit_file="enabled"), "")
        return CommandResult(-1, "", "", cancelled=True)

    res = execute_service_action(ServiceIdentity("system", "slow.service"), "stop", runner=interrupted_mid_flight)
    assert res.outcome == "interrupted"
    assert "unknown" in res.summary.casefold()

    def cmd_failed(args: Sequence[str], timeout: float, stop: Event | None) -> CommandResult:
        if "show" in args:
            return CommandResult(0, _show_block("custom.service", active="inactive", sub="dead", unit_file="enabled"), "")
        return CommandResult(1, "", "Failed to disable custom.service: Unit file is read-only")

    res = execute_service_action(ServiceIdentity("system", "custom.service"), "disable", runner=cmd_failed)
    assert res.outcome == "failed" and res.detail is not None and "read-only" in res.detail.casefold()
