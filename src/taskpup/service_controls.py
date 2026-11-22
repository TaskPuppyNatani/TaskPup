"""Safe systemd service control command construction, safeguards, and execution."""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
from threading import Event
from typing import Literal

from taskpup.services import (
    DEFAULT_TIMEOUT,
    SCOPE_LABELS,
    SHOW_PROPERTIES,
    CommandResult,
    CommandRunner,
    MalformedOutputError,
    ServiceIdentity,
    ServiceRecord,
    ServiceScope,
    parse_show_output,
    run_systemctl,
)

ServiceAction = Literal["start", "stop", "restart", "enable", "disable"]
RiskLevel = Literal["normal", "high", "protected"]
OperationOutcome = Literal[
    "succeeded",
    "warning",
    "auth_cancelled",
    "auth_unavailable",
    "timed_out",
    "cancelled",
    "interrupted",
    "failed",
]

SERVICE_ACTIONS: tuple[ServiceAction, ...] = ("start", "stop", "restart", "enable", "disable")
OPERATION_TIMEOUT = 60.0

ACTION_LABELS: dict[ServiceAction, str] = {
    "start": "Start",
    "stop": "Stop",
    "restart": "Restart",
    "enable": "Enable at Startup",
    "disable": "Disable at Startup",
}

ACTION_PRESENT_PARTICIPLES: dict[ServiceAction, str] = {
    "start": "Starting",
    "stop": "Stopping",
    "restart": "Restarting",
    "enable": "Enabling",
    "disable": "Disabling",
}

ACTION_EFFECTS: dict[ServiceAction, str] = {
    "start": "Starts this service now without changing its startup enablement.",
    "stop": "Stops this service now without changing its startup enablement.",
    "restart": "Stops and starts this service now without changing its startup enablement.",
    "enable": "Enables this service to start automatically at startup. It will not start the service immediately.",
    "disable": "Disables automatic startup for this service. It will not stop a currently running instance.",
}

_UNIT_CHARS_RE = re.compile(r"^(?:[A-Za-z0-9:_@.-]|\\x[0-9a-fA-F]{2})+$")
_GLOB_CHARS = frozenset("*?[]")

# Core system-management backbone units where stopping or disabling from a desktop GUI
# directly breaks IPC, Polkit authorization, login sessions, or device management.
_PROTECTED_SYSTEM_STOP_DISABLE: dict[str, str] = {
    "dbus.service": "Stopping or disabling the system D-Bus broker breaks systemd, Polkit, and desktop IPC.",
    "dbus-broker.service": "Stopping or disabling the system D-Bus broker breaks systemd, Polkit, and desktop IPC.",
    "systemd-logind.service": "Stopping or disabling systemd-logind terminates login session management.",
    "systemd-journald.service": "Stopping or disabling systemd-journald disrupts core system logging.",
    "systemd-udevd.service": "Stopping or disabling systemd-udevd disrupts kernel device management.",
    "polkit.service": "Stopping or disabling Polkit prevents privilege authorization across the desktop.",
}

_PROTECTED_SYSTEM_RESTART: dict[str, str] = {
    "dbus.service": "Restarting the system D-Bus broker breaks active desktop IPC and Polkit sessions.",
    "dbus-broker.service": "Restarting the system D-Bus broker breaks active desktop IPC and Polkit sessions.",
    "systemd-logind.service": "Restarting systemd-logind can terminate active graphical sessions.",
    "polkit.service": "Restarting Polkit while authorizing can disrupt desktop privilege dialogs.",
}

_HIGH_RISK_SYSTEM_UNITS: dict[str, tuple[str, str]] = {
    # Display and desktop session managers
    "display-manager.service": ("Display & Desktop Session", "Stopping or restarting the display manager will immediately close your graphical desktop session and open applications."),
    "lightdm.service": ("Display & Desktop Session", "Stopping or restarting LightDM will immediately close your graphical desktop session and open applications."),
    "gdm.service": ("Display & Desktop Session", "Stopping or restarting GDM will immediately close your graphical desktop session and open applications."),
    "gdm3.service": ("Display & Desktop Session", "Stopping or restarting GDM will immediately close your graphical desktop session and open applications."),
    "sddm.service": ("Display & Desktop Session", "Stopping or restarting SDDM will immediately close your graphical desktop session and open applications."),
    "xdm.service": ("Display & Desktop Session", "Stopping or restarting the display manager will immediately close your graphical desktop session."),
    "lxdm.service": ("Display & Desktop Session", "Stopping or restarting the display manager will immediately close your graphical desktop session."),
    "slim.service": ("Display & Desktop Session", "Stopping or restarting the display manager will immediately close your graphical desktop session."),
    "ly.service": ("Display & Desktop Session", "Stopping or restarting the display manager will immediately close your graphical desktop session."),
    # Network management and remote access
    "NetworkManager.service": ("Network Management", "Stopping, restarting, or disabling NetworkManager can drop active Wi-Fi, Ethernet, and VPN connections."),
    "systemd-networkd.service": ("Network Management", "Stopping, restarting, or disabling systemd-networkd can disconnect active network interfaces."),
    "systemd-resolved.service": ("Network Management", "Stopping or disabling systemd-resolved can break DNS name resolution."),
    "wpa_supplicant.service": ("Network Management", "Stopping or restarting wpa_supplicant can disconnect active Wi-Fi links."),
    "iwd.service": ("Network Management", "Stopping or restarting iwd can disconnect active Wi-Fi links."),
    "networking.service": ("Network Management", "Stopping or restarting networking can drop active network connections."),
    "connman.service": ("Network Management", "Stopping or restarting ConnMan can drop active network connections."),
    "dhclient.service": ("Network Management", "Disrupting DHCP client services can cause network leases to fail."),
    "dhcpcd.service": ("Network Management", "Disrupting DHCP client services can cause network leases to fail."),
    "ssh.service": ("Network Management", "Stopping, restarting, or disabling SSH can interrupt or prevent remote shell access."),
    "sshd.service": ("Network Management", "Stopping, restarting, or disabling SSH can interrupt or prevent remote shell access."),
    # Authentication and login
    "accounts-daemon.service": ("Authentication & Login", "Disrupting AccountsService can affect user profile and desktop login queries."),
    "sssd.service": ("Authentication & Login", "Stopping or disabling SSSD can prevent domain authentication and user lookups."),
    "winbind.service": ("Authentication & Login", "Stopping or disabling Winbind can prevent directory authentication."),
    "systemd-homed.service": ("Authentication & Login", "Stopping or disabling systemd-homed can disrupt home-directory logins."),
    # Storage infrastructure
    "udisks2.service": ("Storage Infrastructure", "Stopping or disabling UDisks2 can disrupt removable-drive mounting and disk management."),
    "lvm2-lvmetad.service": ("Storage Infrastructure", "Disrupting LVM services can affect logical-volume management."),
    "lvm2-monitor.service": ("Storage Infrastructure", "Disrupting LVM monitoring can affect storage pool health tracking."),
    "dm-event.service": ("Storage Infrastructure", "Disrupting device-mapper event monitoring can affect RAID or LVM volumes."),
    "multipathd.service": ("Storage Infrastructure", "Stopping multipathd can disrupt multipath storage access."),
    "mdmonitor.service": ("Storage Infrastructure", "Stopping mdmonitor disables software RAID monitoring alerts."),
    "zfs-mount.service": ("Storage Infrastructure", "Disrupting ZFS mount services can affect ZFS dataset availability."),
    "zfs-zed.service": ("Storage Infrastructure", "Stopping ZFS Event Daemon disables ZFS pool event handling."),
    "blk-availability.service": ("Storage Infrastructure", "Disrupting block availability services can affect storage shutdown ordering."),
    # Security and firewall
    "apparmor.service": ("Security & Firewall", "Stopping or disabling AppArmor reduces mandatory access control confinement."),
    "ufw.service": ("Security & Firewall", "Stopping or disabling UFW can disable host firewall rules."),
    "firewalld.service": ("Security & Firewall", "Stopping or disabling firewalld can disable host firewall rules."),
    "nftables.service": ("Security & Firewall", "Stopping or disabling nftables can disable host firewall rules."),
    "iptables.service": ("Security & Firewall", "Stopping or disabling iptables can disable host firewall rules."),
    "auditd.service": ("Security & Firewall", "Stopping or disabling auditd halts kernel security audit logging."),
    "fail2ban.service": ("Security & Firewall", "Stopping or disabling Fail2Ban halts automated intrusion blocking."),
    # System-management services where restart is high-risk (stop/disable are protected above)
    "systemd-journald.service": ("System Infrastructure", "Restarting systemd-journald temporarily interrupts system log collection."),
    "systemd-udevd.service": ("System Infrastructure", "Restarting systemd-udevd temporarily interrupts hotplug device event handling."),
}

_HIGH_RISK_USER_UNITS: dict[str, tuple[str, str]] = {
    "dbus.service": ("Desktop Session Infrastructure", "Stopping or restarting your user D-Bus session service can break running desktop applications and notifications."),
    "dbus-broker.service": ("Desktop Session Infrastructure", "Stopping or restarting your user D-Bus session service can break running desktop applications and notifications."),
}

_HIGH_RISK_TEMPLATE_PREFIXES: tuple[tuple[str, str, str], ...] = (
    ("getty@", "Authentication & Login", "Stopping or disabling a virtual console getty removes local terminal login on that TTY."),
    ("serial-getty@", "Authentication & Login", "Stopping or disabling a serial getty removes login access on that serial console."),
    ("systemd-cryptsetup@", "Storage Infrastructure", "Changing a cryptsetup service can affect encrypted volume unlocking."),
)


class ServiceValidationError(ValueError):
    """Raised when a service identity, scope, or action is invalid."""


@dataclass(frozen=True, slots=True)
class ActionAvailability:
    allowed: bool
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    level: RiskLevel
    category: str | None = None
    warnings: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ServiceOperationResult:
    identity: ServiceIdentity
    action: ServiceAction
    outcome: OperationOutcome
    summary: str
    detail: str | None = None
    verified_record: ServiceRecord | None = None


def validate_scope(scope: str) -> ServiceScope:
    if scope == "system":
        return "system"
    if scope == "user":
        return "user"
    raise ServiceValidationError(f"Unsupported service scope: {scope!r}")


def validate_action(action: str) -> ServiceAction:
    if action in SERVICE_ACTIONS:
        return action  # type: ignore[return-value]
    raise ServiceValidationError(f"Unsupported service action: {action!r}")


def validate_service_unit(unit: str) -> str:
    """Validate a single concrete systemd .service unit name (no globs, paths, or templates)."""
    if not isinstance(unit, str) or not unit or unit != unit.strip():
        raise ServiceValidationError("Service unit name must be a non-empty string without surrounding whitespace.")
    if len(unit.encode("utf-8")) > 255:
        raise ServiceValidationError("Service unit name exceeds systemd's 255-byte limit.")
    if not unit.endswith(".service"):
        raise ServiceValidationError("Only .service units are supported.")
    stem = unit[: -len(".service")]
    if not stem:
        raise ServiceValidationError("Service unit name is missing a stem before .service.")
    if stem.endswith("@") or "@." in unit or unit.count("@") > 1:
        raise ServiceValidationError("Template or malformed instantiated service units cannot be controlled directly.")
    if any(char in _GLOB_CHARS for char in unit):
        raise ServiceValidationError("Wildcard patterns are not permitted in service unit names.")
    if "/" in unit or ".." in unit or unit[0] in {"-", ".", "@"}:
        raise ServiceValidationError("Paths, traversal sequences, and leading dashes or dots are not permitted.")
    if not _UNIT_CHARS_RE.fullmatch(unit):
        raise ServiceValidationError("Service unit name contains unsupported characters.")
    return unit


def build_control_command(identity: ServiceIdentity, action: ServiceAction) -> tuple[str, ...]:
    """Build a strictly structured, single-unit systemctl control command."""
    scope = validate_scope(identity.scope)
    validated_action = validate_action(action)
    unit = validate_service_unit(identity.unit)
    scope_flag = "--system" if scope == "system" else "--user"
    return ("systemctl", scope_flag, validated_action, "--", unit)


def _static_protected_reason(
    identity: ServiceIdentity,
    action: ServiceAction,
    *,
    current_uid: int | None = None,
) -> tuple[str, str] | None:
    """Return (category, reason) when (scope, unit, action) targets hard-protected core infrastructure."""
    if identity.scope != "system" or action not in {"stop", "restart", "disable"}:
        return None
    uid = os.getuid() if current_uid is None else current_uid
    unit = identity.unit
    if unit == f"user@{uid}.service":
        return (
            "Active User Session",
            f"Protected session infrastructure: changing {unit} would terminate your active user service manager and desktop session.",
        )
    if action in {"stop", "disable"} and unit in _PROTECTED_SYSTEM_STOP_DISABLE:
        return ("Core System Infrastructure", _PROTECTED_SYSTEM_STOP_DISABLE[unit])
    if action == "restart" and unit in _PROTECTED_SYSTEM_RESTART:
        return ("Core System Infrastructure", _PROTECTED_SYSTEM_RESTART[unit])
    return None


def assess_service_risk(
    record: ServiceRecord,
    action: ServiceAction,
    *,
    current_uid: int | None = None,
) -> RiskAssessment:
    """Classify risk level and generate concrete consequence warnings from metadata and safeguards."""
    unit = record.unit
    scope = record.scope
    disruptive = action in {"stop", "restart", "disable"}
    warnings: list[str] = []
    notes: list[str] = []
    category: str | None = None

    if action == "stop" and record.triggered_by:
        triggers = ", ".join(record.triggered_by)
        notes.append(
            f"Triggered by {triggers}. Stopping this service now does not prevent systemd from "
            "automatically starting it again on demand."
        )

    protected = _static_protected_reason(record.identity, action, current_uid=current_uid)
    if protected is not None:
        return RiskAssessment(
            level="protected",
            category=protected[0],
            warnings=(protected[1],),
            notes=tuple(notes),
        )

    if disruptive:
        if scope == "system":
            if unit in _HIGH_RISK_SYSTEM_UNITS:
                category, warning = _HIGH_RISK_SYSTEM_UNITS[unit]
                warnings.append(warning)
            else:
                for prefix, prefix_category, prefix_warning in _HIGH_RISK_TEMPLATE_PREFIXES:
                    if unit.startswith(prefix):
                        category = prefix_category
                        warnings.append(prefix_warning)
                        break
        elif scope == "user" and unit in _HIGH_RISK_USER_UNITS:
            category, warning = _HIGH_RISK_USER_UNITS[unit]
            warnings.append(warning)

        if record.required_by:
            dependents = ", ".join(record.required_by)
            warnings.append(f"Required by other systemd units: {dependents}.")
            if category is None:
                category = "Dependent System Units"
        if record.part_of:
            parents = ", ".join(record.part_of)
            warnings.append(f"Part of unit group: {parents}.")
            if category is None:
                category = "Dependent System Units"

    level: RiskLevel = "high" if warnings else "normal"
    return RiskAssessment(
        level=level,
        category=category,
        warnings=tuple(warnings),
        notes=tuple(notes),
    )


def evaluate_service_actions(
    record: ServiceRecord,
    *,
    current_uid: int | None = None,
) -> dict[ServiceAction, ActionAvailability]:
    """Determine which of the five control actions are permitted for a service record."""
    try:
        validate_scope(record.scope)
        validate_service_unit(record.unit)
    except ServiceValidationError as error:
        blocked = ActionAvailability(False, str(error))
        return {action: blocked for action in SERVICE_ACTIONS}

    if record.is_template:
        blocked = ActionAvailability(False, "Template unit files cannot be controlled directly; select a concrete instance.")
        return {action: blocked for action in SERVICE_ACTIONS}

    if record.is_alias or record.unit_file_state == "alias":
        blocked = ActionAvailability(False, "Alias unit files point to another unit; control the target service instead.")
        return {action: blocked for action in SERVICE_ACTIONS}

    if record.load_state == "masked" or record.unit_file_state in {"masked", "masked-runtime"}:
        blocked = ActionAvailability(False, "Masked services cannot be started, stopped, restarted, enabled, or disabled.")
        return {action: blocked for action in SERVICE_ACTIONS}

    if record.load_state in {"not-found", "error", "bad-setting"} or record.unit_file_state == "bad":
        blocked = ActionAvailability(False, "Service unit file is missing or invalid.")
        return {action: blocked for action in SERVICE_ACTIONS}

    def check_protection(action: ServiceAction, base: ActionAvailability) -> ActionAvailability:
        if not base.allowed:
            return base
        risk = assess_service_risk(record, action, current_uid=current_uid)
        if risk.level == "protected":
            return ActionAvailability(False, risk.warnings[0] if risk.warnings else "Protected system infrastructure.")
        return base

    # Runtime actions: start, stop, restart
    transitioning = record.loaded and record.active_state in {"activating", "deactivating", "reloading", "refreshing"}
    unknown_runtime = record.loaded and record.state_category == "unknown"

    if transitioning:
        reason = f"Service is currently {record.state_label}; wait for it to settle and refresh."
        start_avail = stop_avail = restart_avail = ActionAvailability(False, reason)
    elif unknown_runtime:
        reason = "Service runtime state is unknown; runtime controls are disabled for safety."
        start_avail = stop_avail = restart_avail = ActionAvailability(False, reason)
    else:
        # Start
        if record.can_start is False or record.refuse_manual_start is True:
            start_avail = ActionAvailability(False, "Systemd prohibits manually starting this service.")
        elif record.loaded and record.active_state == "active":
            start_avail = ActionAvailability(False, "Service is already active.")
        elif (record.loaded and record.active_state in {"inactive", "failed"}) or not record.loaded:
            start_avail = ActionAvailability(True)
        else:
            start_avail = ActionAvailability(False, "Start is not supported for this service's current state.")

        # Stop
        if record.can_stop is False or record.refuse_manual_stop is True:
            stop_avail = ActionAvailability(False, "Systemd prohibits manually stopping this service.")
        elif not record.loaded or record.active_state != "active":
            stop_avail = ActionAvailability(False, "Service is not currently active.")
        else:
            stop_avail = ActionAvailability(True)

        # Restart
        if record.can_start is False or record.refuse_manual_start is True:
            restart_avail = ActionAvailability(False, "Systemd prohibits manually starting or restarting this service.")
        elif record.can_stop is False or record.refuse_manual_stop is True:
            restart_avail = ActionAvailability(False, "Systemd prohibits manually stopping or restarting this service.")
        elif not record.loaded or record.active_state != "active":
            restart_avail = ActionAvailability(False, "Restart is available only when the service is active; use Start instead.")
        else:
            restart_avail = ActionAvailability(True)

    # Startup enablement actions: enable, disable
    uf = record.unit_file_state
    if uf == "disabled":
        enable_avail = ActionAvailability(True)
        disable_avail = ActionAvailability(False, "Service is already disabled at startup.")
    elif uf == "enabled":
        enable_avail = ActionAvailability(False, "Service is already enabled at startup.")
        disable_avail = ActionAvailability(True)
    elif uf == "enabled-runtime":
        enable_avail = ActionAvailability(False, "Service is enabled for the current boot (runtime-enabled).")
        disable_avail = ActionAvailability(False, "Runtime-enabled services expire on reboot and are not persistently disabled here.")
    elif uf == "static":
        enable_avail = ActionAvailability(False, "Static services have no [Install] section and cannot be enabled directly.")
        disable_avail = ActionAvailability(False, "Static services are started by other units and cannot be disabled.")
    elif uf == "generated":
        enable_avail = ActionAvailability(False, "Generated services cannot be enabled directly.")
        disable_avail = ActionAvailability(False, "Generated services cannot be disabled directly.")
    elif uf == "transient" or record.transient is True:
        enable_avail = ActionAvailability(False, "Transient services exist only at runtime and cannot be enabled.")
        disable_avail = ActionAvailability(False, "Transient services exist only at runtime and cannot be disabled.")
    elif uf == "indirect":
        enable_avail = ActionAvailability(False, "Indirect enablement is managed through another unit or alias.")
        disable_avail = ActionAvailability(False, "Indirect enablement is managed through another unit or alias.")
    elif uf in {"linked", "linked-runtime"}:
        enable_avail = ActionAvailability(False, "Linked unit files are not managed directly here.")
        disable_avail = ActionAvailability(False, "Linked unit files are not managed directly here.")
    else:
        enable_avail = ActionAvailability(False, "Startup enablement state is unavailable or unknown.")
        disable_avail = ActionAvailability(False, "Startup enablement state is unavailable or unknown.")

    return {
        "start": check_protection("start", start_avail),
        "stop": check_protection("stop", stop_avail),
        "restart": check_protection("restart", restart_avail),
        "enable": check_protection("enable", enable_avail),
        "disable": check_protection("disable", disable_avail),
    }


def _sanitize_error_detail(result: CommandResult) -> str | None:
    text = " ".join(line.strip() for line in result.stderr.splitlines() if line.strip())
    if not text:
        text = " ".join(line.strip() for line in result.stdout.splitlines() if line.strip())
    if not text:
        return None
    return text[:297] + "..." if len(text) > 300 else text


def query_service_state(
    identity: ServiceIdentity,
    *,
    runner: CommandRunner = run_systemctl,
    timeout: float = DEFAULT_TIMEOUT,
    stop: Event | None = None,
) -> ServiceRecord | None:
    """Query systemd for the authoritative current state of one validated service unit."""
    scope = validate_scope(identity.scope)
    unit = validate_service_unit(identity.unit)
    scope_flag = "--system" if scope == "system" else "--user"
    cmd = (
        "systemctl",
        scope_flag,
        "show",
        "--no-pager",
        "-p",
        ",".join(SHOW_PROPERTIES),
        "--",
        unit,
    )
    result = runner(cmd, timeout, stop)
    if result.cancelled or result.timed_out or result.os_error or result.returncode != 0:
        return None
    try:
        entries = parse_show_output(result.stdout)
    except MalformedOutputError:
        return None
    # Require exact canonical unit match so aliases cannot redirect control to another unit.
    match = next((entry for entry in entries if entry.unit == unit), None)
    if match is None:
        return None
    enablement = match.unit_file_state
    if enablement is None and match.transient is True:
        enablement = "transient"
    return ServiceRecord(
        identity=ServiceIdentity(scope=scope, unit=match.unit),
        description=match.description,
        loaded=True,
        load_state=match.load_state,
        active_state=match.active_state,
        sub_state=match.sub_state,
        unit_file_state=enablement,
        unit_file_preset=match.unit_file_preset,
        fragment_path=match.fragment_path,
        main_pid=match.main_pid,
        service_type=match.service_type,
        user=match.user,
        transient=match.transient,
        result=match.result,
        active_enter_timestamp=match.active_enter_timestamp,
        status_text=match.status_text,
        triggered_by=match.triggered_by,
        can_start=match.can_start,
        can_stop=match.can_stop,
        refuse_manual_start=match.refuse_manual_start,
        refuse_manual_stop=match.refuse_manual_stop,
        required_by=match.required_by,
        part_of=match.part_of,
    )


def _reconcile_success(
    identity: ServiceIdentity,
    action: ServiceAction,
    verified: ServiceRecord | None,
) -> ServiceOperationResult:
    unit = identity.unit
    if verified is None:
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="warning",
            summary=f"{ACTION_LABELS[action]} finished for {unit}, but current authoritative state could not be verified.",
        )

    if action == "start":
        if verified.active_state == "active":
            return ServiceOperationResult(identity, action, "succeeded", f"Started {unit} ({verified.state_label}).", verified_record=verified)
        if verified.active_state in {"activating", "reloading"}:
            return ServiceOperationResult(identity, action, "warning", f"Start submitted for {unit}; service is currently {verified.state_label}.", verified_record=verified)
        return ServiceOperationResult(identity, action, "warning", f"Start command finished for {unit}, but authoritative state is {verified.state_label}.", verified_record=verified)

    if action == "stop":
        if verified.active_state in {"inactive", "failed"} or not verified.loaded:
            return ServiceOperationResult(identity, action, "succeeded", f"Stopped {unit} ({verified.state_label}).", verified_record=verified)
        if verified.active_state == "deactivating":
            return ServiceOperationResult(identity, action, "warning", f"Stop submitted for {unit}; service is currently Deactivating.", verified_record=verified)
        if verified.active_state == "active":
            return ServiceOperationResult(
                identity,
                action,
                "warning",
                f"Stop command finished for {unit}, but service is currently {verified.state_label} (it may have been reactivated automatically).",
                verified_record=verified,
            )
        return ServiceOperationResult(identity, action, "warning", f"Stop command finished for {unit}, but authoritative state is {verified.state_label}.", verified_record=verified)

    if action == "restart":
        if verified.active_state == "active":
            return ServiceOperationResult(identity, action, "succeeded", f"Restarted {unit} ({verified.state_label}).", verified_record=verified)
        if verified.active_state in {"activating", "reloading"}:
            return ServiceOperationResult(identity, action, "warning", f"Restart submitted for {unit}; service is currently {verified.state_label}.", verified_record=verified)
        return ServiceOperationResult(identity, action, "warning", f"Restart command finished for {unit}, but authoritative state is {verified.state_label}.", verified_record=verified)

    if action == "enable":
        if verified.unit_file_state in {"enabled", "enabled-runtime", "indirect", "alias"}:
            return ServiceOperationResult(identity, action, "succeeded", f"Enabled {unit} at startup ({verified.enablement_label}).", verified_record=verified)
        return ServiceOperationResult(identity, action, "warning", f"Enable command finished for {unit}, but startup state is {verified.enablement_label}.", verified_record=verified)

    # disable
    if verified.unit_file_state == "disabled":
        return ServiceOperationResult(identity, action, "succeeded", f"Disabled {unit} at startup.", verified_record=verified)
    return ServiceOperationResult(identity, action, "warning", f"Disable command finished for {unit}, but startup state is {verified.enablement_label}.", verified_record=verified)


def _classify_failure(
    identity: ServiceIdentity,
    action: ServiceAction,
    result: CommandResult,
    verified: ServiceRecord | None = None,
) -> ServiceOperationResult:
    unit = identity.unit
    scope_label = SCOPE_LABELS[identity.scope]
    detail = _sanitize_error_detail(result)

    if result.cancelled:
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="interrupted",
            summary=(
                f"Stopped monitoring {action} on {unit}. "
                "Systemd may still continue processing the request, and its final outcome is unknown."
            ),
        )

    if result.timed_out:
        state_note = f" Current state: {verified.state_label}." if verified is not None else ""
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="timed_out",
            summary=(
                f"Timed out waiting for systemd to {action} {unit}. "
                f"The job may still be running in the background.{state_note}"
            ),
            detail=detail,
            verified_record=verified,
        )

    if result.os_error:
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="failed",
            summary=f"Unable to run systemctl to {action} {unit}.",
            detail=detail,
        )

    lowered = (detail or "").casefold()
    if "interactive authentication required" in lowered or "no authentication agent" in lowered:
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="auth_unavailable",
            summary=(
                f"Graphical authorization is unavailable to {action} {unit}. "
                "No Polkit authentication agent responded for this session."
            ),
            detail=detail,
            verified_record=verified,
        )

    if any(
        token in lowered
        for token in (
            "authentication cancelled",
            "authentication canceled",
            "dismissed",
            "cancelled by user",
            "canceled by user",
        )
    ):
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="auth_cancelled",
            summary=f"Authorization was cancelled for {action} on {unit}. No change was applied.",
            detail=detail,
            verified_record=verified,
        )

    if any(
        token in lowered
        for token in (
            "access denied",
            "not authorized",
            "permission denied",
            "authentication failed",
            "operation not permitted",
        )
    ):
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="auth_cancelled",
            summary=f"Authorization was denied or cancelled for {action} on {unit}.",
            detail=detail,
            verified_record=verified,
        )

    if any(
        token in lowered
        for token in (
            "failed to connect to bus",
            "not been booted with systemd",
            "no medium found",
            "transport endpoint",
        )
    ):
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="failed",
            summary=f"{scope_label} systemd manager is unavailable to {action} {unit}.",
            detail=detail,
        )

    return ServiceOperationResult(
        identity=identity,
        action=action,
        outcome="failed",
        summary=f"Failed to {action} {unit} (exit {result.returncode}).",
        detail=detail,
        verified_record=verified,
    )


def _has_sufficient_metadata(record: ServiceRecord, action: ServiceAction) -> tuple[bool, str | None]:
    """Verify authoritative systemd metadata is complete enough to evaluate safety."""
    if record.load_state is None or record.active_state is None:
        return False, "authoritative load or active state is unavailable, so the operation could not be safely evaluated."
    if action in {"start", "restart"} and (record.can_start is None or record.refuse_manual_start is None):
        return False, "authoritative systemd start capability properties are unavailable, so the operation could not be safely evaluated."
    if action in {"stop", "restart"} and (record.can_stop is None or record.refuse_manual_stop is None):
        return False, "authoritative systemd stop capability properties are unavailable, so the operation could not be safely evaluated."
    if action in {"stop", "restart", "disable"}:
        missing_deps: list[str] = []
        if record.required_by is None:
            missing_deps.append("RequiredBy")
        if record.part_of is None:
            missing_deps.append("PartOf")
        if missing_deps:
            joined = " and ".join(missing_deps)
            verb = "is" if len(missing_deps) == 1 else "are"
            return (
                False,
                f"authoritative dependency metadata ({joined}) {verb} unavailable, "
                "so the operation could not be safely evaluated. Refresh and try again.",
            )
    return True, None


def execute_service_action(
    identity: ServiceIdentity,
    action: ServiceAction,
    stop: Event | None = None,
    *,
    high_risk_acknowledged: bool = False,
    runner: CommandRunner = run_systemctl,
    timeout: float = OPERATION_TIMEOUT,
    verify_timeout: float = DEFAULT_TIMEOUT,
    current_uid: int | None = None,
) -> ServiceOperationResult:
    """Validate, enforce policy against authoritative metadata, execute, and reconcile one service action."""
    try:
        cmd = build_control_command(identity, action)
    except ServiceValidationError as error:
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="failed",
            summary=f"Rejected invalid service operation: {error}",
        )

    if stop is not None and stop.is_set():
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="cancelled",
            summary=f"Cancelled {action} on {identity.unit} before dispatch.",
        )

    # Reject hard-protected core system services unconditionally before invoking any subprocess.
    protected = _static_protected_reason(identity, action, current_uid=current_uid)
    if protected is not None:
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="failed",
            summary=f"Operation blocked for {identity.unit}: {protected[1]}",
        )

    # Fetch authoritative current metadata and re-evaluate eligibility and risk at the execution boundary.
    pre_record = query_service_state(identity, runner=runner, timeout=verify_timeout, stop=stop)
    if stop is not None and stop.is_set():
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="cancelled",
            summary=f"Cancelled {action} on {identity.unit} before dispatch.",
        )
    if pre_record is None:
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="failed",
            summary=(
                f"Refused to {action} {identity.unit}: authoritative service metadata "
                "could not be verified."
            ),
        )

    availability = evaluate_service_actions(pre_record, current_uid=current_uid)[action]
    if not availability.allowed:
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="failed",
            summary=f"Operation blocked for {identity.unit}: {availability.reason}",
            verified_record=pre_record,
        )

    metadata_ok, metadata_reason = _has_sufficient_metadata(pre_record, action)
    if not metadata_ok:
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="failed",
            summary=f"Refused to {action} {identity.unit}: {metadata_reason}",
            verified_record=pre_record,
        )

    risk = assess_service_risk(pre_record, action, current_uid=current_uid)
    if risk.level == "protected":
        reason = risk.warnings[0] if risk.warnings else "Protected system infrastructure."
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="failed",
            summary=f"Operation blocked for {identity.unit}: {reason}",
            verified_record=pre_record,
        )
    if risk.level == "high" and not high_risk_acknowledged:
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="failed",
            summary=(
                f"Refused to {action} {identity.unit}: explicit high-risk acknowledgement "
                f"is required ({risk.category or 'Critical Service'})."
            ),
            verified_record=pre_record,
        )

    result = runner(cmd, timeout, stop)
    if result.cancelled:
        return _classify_failure(identity, action, result)

    if result.timed_out:
        verified = None if (stop is not None and stop.is_set()) else query_service_state(
            identity, runner=runner, timeout=verify_timeout, stop=stop
        )
        return _classify_failure(identity, action, result, verified=verified)

    if result.os_error:
        return _classify_failure(identity, action, result)

    if result.returncode != 0:
        verified = None if (stop is not None and stop.is_set()) else query_service_state(
            identity, runner=runner, timeout=verify_timeout, stop=stop
        )
        return _classify_failure(identity, action, result, verified=verified)

    if stop is not None and stop.is_set():
        return ServiceOperationResult(
            identity=identity,
            action=action,
            outcome="interrupted",
            summary=(
                f"Stopped monitoring {action} on {identity.unit} before final verification. "
                "The final outcome is unknown."
            ),
        )

    verified = query_service_state(identity, runner=runner, timeout=verify_timeout, stop=stop)
    return _reconcile_success(identity, action, verified)
