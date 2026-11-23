"""Read-only systemd service discovery, parsing, and filtering."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import json
import os
import selectors
import subprocess
from threading import Event
import time
from typing import Literal

ServiceScope = Literal["system", "user"]
StateFilter = Literal["all", "running", "active_other", "inactive", "failed"]
ScopeFilter = Literal["all", "system", "user"]
StateCategory = Literal["running", "active_other", "inactive", "failed", "transitioning", "other", "unknown"]

DEFAULT_TIMEOUT = 8.0
SHOW_BATCH_SIZE = 100
UNAVAILABLE = "Unavailable"

SHOW_PROPERTIES = (
    "Id",
    "Description",
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "UnitFilePreset",
    "FragmentPath",
    "MainPID",
    "Type",
    "User",
    "Transient",
    "Result",
    "ActiveEnterTimestamp",
    "StatusText",
    "TriggeredBy",
    "CanStart",
    "CanStop",
    "RefuseManualStart",
    "RefuseManualStop",
    "RequiredBy",
    "PartOf",
    "ConsistsOf",
)

SCOPE_LABELS: dict[ServiceScope, str] = {
    "system": "System",
    "user": "User",
}

ENABLEMENT_LABELS: dict[str, str] = {
    "enabled": "Enabled",
    "enabled-runtime": "Enabled (runtime)",
    "disabled": "Disabled",
    "static": "Static",
    "masked": "Masked",
    "masked-runtime": "Masked (runtime)",
    "generated": "Generated",
    "transient": "Transient",
    "indirect": "Indirect",
    "alias": "Alias",
    "linked": "Linked",
    "linked-runtime": "Linked (runtime)",
    "bad": "Invalid (bad)",
}

LOAD_STATE_LABELS: dict[str, str] = {
    "loaded": "Loaded",
    "not-found": "Not found",
    "masked": "Masked",
    "bad-setting": "Bad setting",
    "error": "Error",
    "stub": "Stub",
    "merged": "Merged",
}

ACTIVE_STATE_LABELS: dict[str, str] = {
    "active": "Active",
    "inactive": "Inactive",
    "failed": "Failed",
    "activating": "Activating",
    "deactivating": "Deactivating",
    "reloading": "Reloading",
    "refreshing": "Refreshing",
    "maintenance": "Maintenance",
}

SUB_STATE_LABELS: dict[str, str] = {
    "running": "Running",
    "exited": "Exited",
    "dead": "Dead",
    "failed": "Failed",
    "waiting": "Waiting",
    "start-pre": "Starting (pre)",
    "start": "Starting",
    "start-post": "Starting (post)",
    "reload": "Reloading",
    "reload-signal": "Reloading (signal)",
    "reload-notify": "Reloading (notify)",
    "stop": "Stopping",
    "stop-watchdog": "Stopping (watchdog)",
    "stop-sigterm": "Stopping (SIGTERM)",
    "stop-sigkill": "Stopping (SIGKILL)",
    "stop-post": "Stopping (post)",
    "final-watchdog": "Final watchdog",
    "final-sigterm": "Final SIGTERM",
    "final-sigkill": "Final SIGKILL",
    "auto-restart": "Auto-restart",
    "auto-restart-queued": "Auto-restart queued",
    "condition": "Checking condition",
    "cleaning": "Cleaning",
    "mounted": "Mounted",
    "listening": "Listening",
}

PRESET_LABELS: dict[str, str] = {
    "enabled": "Enabled",
    "disabled": "Disabled",
    "ignore": "Ignore",
}


class MalformedOutputError(ValueError):
    """Raised when systemctl returns syntactically invalid or unexpected data."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    cancelled: bool = False
    os_error: bool = False


CommandRunner = Callable[[Sequence[str], float, Event | None], CommandResult]


@dataclass(frozen=True, slots=True)
class ServiceIdentity:
    scope: ServiceScope
    unit: str


@dataclass(frozen=True, slots=True)
class LoadedServiceEntry:
    unit: str
    description: str | None = None
    load_state: str | None = None
    active_state: str | None = None
    sub_state: str | None = None
    unit_file_state: str | None = None
    unit_file_preset: str | None = None
    fragment_path: str | None = None
    main_pid: int | None = None
    service_type: str | None = None
    user: str | None = None
    transient: bool | None = None
    result: str | None = None
    active_enter_timestamp: str | None = None
    status_text: str | None = None
    triggered_by: tuple[str, ...] | None = None
    can_start: bool | None = None
    can_stop: bool | None = None
    refuse_manual_start: bool | None = None
    refuse_manual_stop: bool | None = None
    required_by: tuple[str, ...] | None = None
    part_of: tuple[str, ...] | None = None
    consists_of: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class UnitFileEntry:
    unit: str
    state: str | None
    preset: str | None = None


@dataclass(frozen=True, slots=True)
class ServiceRecord:
    identity: ServiceIdentity
    description: str | None
    loaded: bool
    load_state: str | None
    active_state: str | None
    sub_state: str | None
    unit_file_state: str | None
    unit_file_preset: str | None = None
    fragment_path: str | None = None
    main_pid: int | None = None
    service_type: str | None = None
    user: str | None = None
    transient: bool | None = None
    result: str | None = None
    active_enter_timestamp: str | None = None
    status_text: str | None = None
    triggered_by: tuple[str, ...] | None = None
    can_start: bool | None = None
    can_stop: bool | None = None
    refuse_manual_start: bool | None = None
    refuse_manual_stop: bool | None = None
    required_by: tuple[str, ...] | None = None
    part_of: tuple[str, ...] | None = None
    consists_of: tuple[str, ...] | None = None

    @property
    def scope(self) -> ServiceScope:
        return self.identity.scope

    @property
    def unit(self) -> str:
        return self.identity.unit

    @property
    def is_template(self) -> bool:
        return "@." in self.unit

    @property
    def is_alias(self) -> bool:
        return not self.loaded and self.unit_file_state == "alias"

    @property
    def scope_label(self) -> str:
        return SCOPE_LABELS[self.scope]

    @property
    def state_category(self) -> StateCategory:
        if not self.loaded:
            if self.is_template or self.is_alias:
                return "other"
            return "inactive"
        active = self.active_state
        sub = self.sub_state
        if active == "failed" or sub == "failed":
            return "failed"
        if active == "active":
            return "running" if sub == "running" else "active_other"
        if active in {"activating", "deactivating", "reloading", "refreshing"}:
            return "transitioning"
        if active == "inactive":
            return "inactive"
        if active == "maintenance":
            return "other"
        return "unknown"

    @property
    def state_label(self) -> str:
        if not self.loaded:
            if self.is_template:
                return "Template"
            if self.is_alias:
                return "Alias"
            if self.unit_file_state in {"masked", "masked-runtime"}:
                return "Inactive (masked)"
            return "Inactive (not loaded)"
        active = self.active_state
        sub = self.sub_state
        if active == "failed" or sub == "failed":
            return "Failed"
        if active == "active":
            if sub == "running":
                return "Running"
            if sub == "exited":
                return "Active (exited)"
            if sub:
                return f"Active ({sub})"
            return "Active"
        if active == "inactive":
            if self.load_state == "not-found":
                return "Inactive (not found)"
            if self.load_state == "masked" or self.unit_file_state in {"masked", "masked-runtime"}:
                return "Inactive (masked)"
            return "Stopped"
        if active == "activating":
            if sub and sub not in {"start", "activating"}:
                return f"Activating ({sub})"
            return "Activating"
        if active == "deactivating":
            return "Deactivating"
        if active == "reloading":
            return "Reloading"
        if active == "refreshing":
            return "Refreshing"
        if active == "maintenance":
            return "Maintenance"
        if active is None:
            return UNAVAILABLE
        return f"Unknown ({active})"

    @property
    def enablement_label(self) -> str:
        state = self.unit_file_state
        if state:
            return ENABLEMENT_LABELS.get(state, f"Unknown ({state})")
        if self.transient is True:
            return "Transient"
        return UNAVAILABLE

    @property
    def load_state_label(self) -> str:
        if self.load_state:
            return LOAD_STATE_LABELS.get(self.load_state, f"Unknown ({self.load_state})")
        if not self.loaded:
            if self.is_template:
                return "Not loaded (template)"
            if self.is_alias:
                return "Not loaded (alias)"
            if self.unit_file_state in {"masked", "masked-runtime"}:
                return "Masked (not loaded)"
            return "Not loaded"
        return UNAVAILABLE

    @property
    def active_state_label(self) -> str:
        if self.active_state:
            return ACTIVE_STATE_LABELS.get(self.active_state, f"Unknown ({self.active_state})")
        if not self.loaded:
            if self.is_template:
                return "Not applicable (template)"
            if self.is_alias:
                return "Not applicable (alias)"
            return "Inactive (not loaded)"
        return UNAVAILABLE

    @property
    def sub_state_label(self) -> str:
        if self.sub_state:
            return SUB_STATE_LABELS.get(self.sub_state, self.sub_state)
        if not self.loaded:
            if self.is_template or self.is_alias:
                return "Not applicable"
            return "Not loaded"
        return UNAVAILABLE

    @property
    def preset_label(self) -> str:
        if self.unit_file_preset:
            return PRESET_LABELS.get(self.unit_file_preset, f"Unknown ({self.unit_file_preset})")
        return UNAVAILABLE


@dataclass(frozen=True, slots=True)
class ScopeStatus:
    scope: ServiceScope
    available: bool
    unit_files_available: bool = True
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ServicesSnapshot:
    services: tuple[ServiceRecord, ...]
    system: ScopeStatus
    user: ScopeStatus
    timestamp: float

    def warnings(self) -> tuple[str, ...]:
        messages: list[str] = []
        for status in (self.system, self.user):
            if status.error:
                messages.append(status.error)
        return tuple(messages)


def _clean_str(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped or stripped == "n/a":
        return None
    return stripped


def _parse_pid(value: str | None) -> int | None:
    text = _clean_str(value)
    if text is None:
        return None
    try:
        pid = int(text)
    except ValueError:
        return None
    return pid if pid > 0 else None


def _parse_bool(value: str | None) -> bool | None:
    text = _clean_str(value)
    if text is None:
        return None
    lowered = text.casefold()
    if lowered in {"yes", "true", "1"}:
        return True
    if lowered in {"no", "false", "0"}:
        return False
    return None


def _parse_list(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    stripped = value.strip()
    if stripped.casefold() == "n/a":
        return None
    if not stripped:
        return ()
    return tuple(stripped.split())


def parse_list_units_json(text: str) -> list[LoadedServiceEntry]:
    """Parse `systemctl list-units --type=service --all --output=json` output."""
    stripped = text.strip()
    if not stripped:
        raise MalformedOutputError("Empty output from list-units.")
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as error:
        raise MalformedOutputError(f"Invalid JSON from list-units: {error.msg}") from error
    if not isinstance(payload, list):
        raise MalformedOutputError("Expected a JSON list from list-units.")
    entries: list[LoadedServiceEntry] = []
    for item in payload:
        if not isinstance(item, dict):
            raise MalformedOutputError("Expected JSON objects inside list-units output.")
        raw_unit = item.get("unit")
        if not isinstance(raw_unit, str) or not raw_unit.strip():
            raise MalformedOutputError("Loaded unit entry is missing a valid unit name.")
        unit = raw_unit.strip()
        if not unit.endswith(".service"):
            continue
        parsed_fields: dict[str, str | None] = {}
        for key in ("load", "active", "sub", "description"):
            value = item.get(key)
            if value is not None and not isinstance(value, str):
                raise MalformedOutputError(f"Invalid {key} value for unit {unit}.")
            parsed_fields[key] = _clean_str(value)
        entries.append(
            LoadedServiceEntry(
                unit=unit,
                description=parsed_fields["description"],
                load_state=parsed_fields["load"],
                active_state=parsed_fields["active"],
                sub_state=parsed_fields["sub"],
            )
        )
    return entries


def parse_show_output(text: str) -> list[LoadedServiceEntry]:
    """Parse `systemctl show -- <unit...>` key=value output for explicit service units."""
    if not text.strip():
        raise MalformedOutputError("Empty output from systemctl show.")
    entries: list[LoadedServiceEntry] = []
    block: dict[str, str] = {}

    def flush() -> None:
        if not block:
            return
        unit = _clean_str(block.get("Id"))
        if unit is None:
            raise MalformedOutputError("Service property block is missing an Id field.")
        if unit.endswith(".service"):
            entries.append(
                LoadedServiceEntry(
                    unit=unit,
                    description=_clean_str(block.get("Description")),
                    load_state=_clean_str(block.get("LoadState")),
                    active_state=_clean_str(block.get("ActiveState")),
                    sub_state=_clean_str(block.get("SubState")),
                    unit_file_state=_clean_str(block.get("UnitFileState")),
                    unit_file_preset=_clean_str(block.get("UnitFilePreset")),
                    fragment_path=_clean_str(block.get("FragmentPath")),
                    main_pid=_parse_pid(block.get("MainPID")),
                    service_type=_clean_str(block.get("Type")),
                    user=_clean_str(block.get("User")),
                    transient=_parse_bool(block.get("Transient")),
                    result=_clean_str(block.get("Result")),
                    active_enter_timestamp=_clean_str(block.get("ActiveEnterTimestamp")),
                    status_text=_clean_str(block.get("StatusText")),
                    triggered_by=_parse_list(block.get("TriggeredBy")),
                    can_start=_parse_bool(block.get("CanStart")),
                    can_stop=_parse_bool(block.get("CanStop")),
                    refuse_manual_start=_parse_bool(block.get("RefuseManualStart")),
                    refuse_manual_stop=_parse_bool(block.get("RefuseManualStop")),
                    required_by=_parse_list(block.get("RequiredBy")),
                    part_of=_parse_list(block.get("PartOf")),
                    consists_of=_parse_list(block.get("ConsistsOf")),
                )
            )
        block.clear()

    for raw_line in text.splitlines():
        if not raw_line.strip():
            flush()
            continue
        if "=" not in raw_line:
            raise MalformedOutputError(f"Expected key=value line, got: {raw_line[:80]!r}")
        key, value = raw_line.split("=", 1)
        key = key.strip()
        if not key:
            raise MalformedOutputError("Encountered empty property name.")
        block[key] = value
    flush()
    return entries


def parse_unit_files_json(text: str) -> list[UnitFileEntry]:
    """Parse `systemctl list-unit-files --type=service --output=json` output."""
    stripped = text.strip()
    if not stripped:
        raise MalformedOutputError("Empty output from list-unit-files.")
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as error:
        raise MalformedOutputError(f"Invalid JSON from list-unit-files: {error.msg}") from error
    if not isinstance(payload, list):
        raise MalformedOutputError("Expected a JSON list from list-unit-files.")
    entries: list[UnitFileEntry] = []
    for item in payload:
        if not isinstance(item, dict):
            raise MalformedOutputError("Expected JSON objects inside list-unit-files output.")
        raw_unit = item.get("unit_file")
        if not isinstance(raw_unit, str) or not raw_unit.strip():
            raise MalformedOutputError("Unit file entry is missing a valid unit_file name.")
        unit = raw_unit.strip()
        if not unit.endswith(".service"):
            continue
        raw_state = item.get("state")
        if raw_state is not None and not isinstance(raw_state, str):
            raise MalformedOutputError(f"Invalid state value for unit {unit}.")
        raw_preset = item.get("preset")
        if raw_preset is not None and not isinstance(raw_preset, str):
            raise MalformedOutputError(f"Invalid preset value for unit {unit}.")
        entries.append(
            UnitFileEntry(
                unit=unit,
                state=_clean_str(raw_state),
                preset=_clean_str(raw_preset),
            )
        )
    return entries


def merge_scope_services(
    scope: ServiceScope,
    loaded: Sequence[LoadedServiceEntry],
    unit_files: Sequence[UnitFileEntry],
) -> tuple[ServiceRecord, ...]:
    """Merge loaded service state with installed unit-file state for one scope."""
    loaded_by_unit = {entry.unit: entry for entry in loaded}
    unit_files_by_unit = {entry.unit: entry for entry in unit_files}
    records: list[ServiceRecord] = []

    for unit in sorted(loaded_by_unit.keys() | unit_files_by_unit.keys(), key=str.casefold):
        live = loaded_by_unit.get(unit)
        installed = unit_files_by_unit.get(unit)
        identity = ServiceIdentity(scope=scope, unit=unit)
        if live is not None:
            enablement = installed.state if (installed is not None and installed.state) else live.unit_file_state
            if enablement is None and live.transient is True:
                enablement = "transient"
            preset = installed.preset if (installed is not None and installed.preset) else live.unit_file_preset
            records.append(
                ServiceRecord(
                    identity=identity,
                    description=live.description,
                    loaded=True,
                    load_state=live.load_state,
                    active_state=live.active_state,
                    sub_state=live.sub_state,
                    unit_file_state=enablement,
                    unit_file_preset=preset,
                    fragment_path=live.fragment_path,
                    main_pid=live.main_pid,
                    service_type=live.service_type,
                    user=live.user,
                    transient=live.transient,
                    result=live.result,
                    active_enter_timestamp=live.active_enter_timestamp,
                    status_text=live.status_text,
                    triggered_by=live.triggered_by,
                    can_start=live.can_start,
                    can_stop=live.can_stop,
                    refuse_manual_start=live.refuse_manual_start,
                    refuse_manual_stop=live.refuse_manual_stop,
                    required_by=live.required_by,
                    part_of=live.part_of,
                    consists_of=live.consists_of,
                )
            )
        elif installed is not None:
            records.append(
                ServiceRecord(
                    identity=identity,
                    description=None,
                    loaded=False,
                    load_state=None,
                    active_state=None,
                    sub_state=None,
                    unit_file_state=installed.state,
                    unit_file_preset=installed.preset,
                )
            )
    return tuple(records)


def matches_filters(
    record: ServiceRecord,
    *,
    query: str = "",
    state_filter: StateFilter = "all",
    scope_filter: ScopeFilter = "all",
) -> bool:
    """Evaluate search and filter predicates against an in-memory ServiceRecord."""
    if scope_filter != "all" and record.scope != scope_filter:
        return False
    if state_filter != "all":
        category = record.state_category
        if state_filter == "running" and category != "running":
            return False
        if state_filter == "active_other" and category != "active_other":
            return False
        if state_filter == "inactive" and category != "inactive":
            return False
        if state_filter == "failed" and category != "failed":
            return False
    terms = query.casefold().split()
    if terms:
        searchable = f"{record.unit} {record.description or ''}".casefold()
        if not all(term in searchable for term in terms):
            return False
    return True


def _terminate_process(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        return
    try:
        proc.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            pass


def run_systemctl(
    args: Sequence[str],
    timeout: float = DEFAULT_TIMEOUT,
    stop: Event | None = None,
) -> CommandResult:
    """Run a read-only systemctl command with bounded timeout and clean cancellation."""
    if stop is not None and stop.is_set():
        return CommandResult(returncode=-1, stdout="", stderr="", cancelled=True)
    try:
        proc = subprocess.Popen(
            list(args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        return CommandResult(returncode=-1, stdout="", stderr=str(error), os_error=True)

    assert proc.stdout is not None and proc.stderr is not None
    selector = selectors.DefaultSelector()
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_fd = proc.stdout.fileno()
    stderr_fd = proc.stderr.fileno()
    os.set_blocking(stdout_fd, False)
    os.set_blocking(stderr_fd, False)
    buffers: dict[int, list[bytes]] = {stdout_fd: stdout_chunks, stderr_fd: stderr_chunks}
    selector.register(proc.stdout, selectors.EVENT_READ)
    selector.register(proc.stderr, selectors.EVENT_READ)

    deadline = time.monotonic() + timeout
    timed_out = False
    cancelled = False
    try:
        while selector.get_map():
            if stop is not None and stop.is_set():
                cancelled = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(0.05, remaining)):
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if chunk:
                    buffers[key.fd].append(chunk)
                else:
                    selector.unregister(key.fileobj)
        if not cancelled and not timed_out:
            while proc.poll() is None:
                if stop is not None and stop.is_set():
                    cancelled = True
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                try:
                    proc.wait(timeout=min(0.05, remaining))
                except subprocess.TimeoutExpired:
                    pass
    finally:
        if cancelled or timed_out or proc.poll() is None:
            _terminate_process(proc)
        selector.close()
        proc.stdout.close()
        proc.stderr.close()

    return CommandResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=b"".join(stdout_chunks).decode("utf-8", errors="replace"),
        stderr=b"".join(stderr_chunks).decode("utf-8", errors="replace"),
        timed_out=timed_out,
        cancelled=cancelled,
    )


def _format_command_error(scope: ServiceScope, phase: str, result: CommandResult) -> str:
    label = SCOPE_LABELS[scope]
    if result.timed_out:
        return f"{label} {phase} timed out."
    detail = " ".join(line.strip() for line in result.stderr.splitlines() if line.strip())
    if not detail:
        detail = " ".join(line.strip() for line in result.stdout.splitlines() if line.strip())
    if result.os_error:
        return f"{label} services unavailable: unable to execute systemctl ({detail or 'OS error'})."
    lowered = detail.casefold()
    if any(token in lowered for token in ("permission denied", "access denied", "operation not permitted")):
        return f"{label} {phase} permission denied: {detail}"
    if any(
        token in lowered
        for token in (
            "failed to connect to bus",
            "not been booted with systemd",
            "no such file or directory",
            "no medium found",
            "transport endpoint",
        )
    ):
        return f"{label} systemd manager unavailable: {detail}"
    if detail:
        return f"{label} {phase} failed (exit {result.returncode}): {detail}"
    return f"{label} {phase} failed (exit {result.returncode})."


def _base_command(scope: ServiceScope) -> tuple[str, ...]:
    return ("systemctl",) if scope == "system" else ("systemctl", "--user")


def _merge_loaded_metadata(
    base_entry: LoadedServiceEntry,
    detail: LoadedServiceEntry | None,
) -> LoadedServiceEntry:
    if detail is None:
        return base_entry
    return LoadedServiceEntry(
        unit=base_entry.unit,
        description=detail.description or base_entry.description,
        load_state=base_entry.load_state or detail.load_state,
        active_state=base_entry.active_state or detail.active_state,
        sub_state=base_entry.sub_state or detail.sub_state,
        unit_file_state=detail.unit_file_state or base_entry.unit_file_state,
        unit_file_preset=detail.unit_file_preset or base_entry.unit_file_preset,
        fragment_path=detail.fragment_path,
        main_pid=detail.main_pid,
        service_type=detail.service_type,
        user=detail.user,
        transient=detail.transient,
        result=detail.result,
        active_enter_timestamp=detail.active_enter_timestamp,
        status_text=detail.status_text,
        triggered_by=detail.triggered_by,
        can_start=detail.can_start,
        can_stop=detail.can_stop,
        refuse_manual_start=detail.refuse_manual_start,
        refuse_manual_stop=detail.refuse_manual_stop,
        required_by=detail.required_by,
        part_of=detail.part_of,
        consists_of=detail.consists_of,
    )


def discover_scope(
    scope: ServiceScope,
    *,
    runner: CommandRunner = run_systemctl,
    timeout: float = DEFAULT_TIMEOUT,
    stop: Event | None = None,
) -> tuple[tuple[ServiceRecord, ...], ScopeStatus]:
    """Discover loaded services and installed unit files for one systemd scope."""
    base = _base_command(scope)
    list_units_cmd = (
        *base,
        "list-units",
        "--type=service",
        "--all",
        "--output=json",
        "--no-pager",
        "--no-legend",
    )
    units_result = runner(list_units_cmd, timeout, stop)
    if units_result.cancelled:
        return (), ScopeStatus(scope=scope, available=False, unit_files_available=False, error=None)
    if units_result.timed_out or units_result.os_error or units_result.returncode != 0:
        return (
            (),
            ScopeStatus(
                scope=scope,
                available=False,
                unit_files_available=False,
                error=_format_command_error(scope, "service query", units_result),
            ),
        )
    try:
        loaded_entries = parse_list_units_json(units_result.stdout)
    except MalformedOutputError as error:
        return (
            (),
            ScopeStatus(
                scope=scope,
                available=False,
                unit_files_available=False,
                error=f"{SCOPE_LABELS[scope]} service query returned malformed output: {error}",
            ),
        )

    warnings: list[str] = []
    enriched_by_unit: dict[str, LoadedServiceEntry] = {}
    if loaded_entries:
        unit_names = list(dict.fromkeys(entry.unit for entry in loaded_entries))
        for start in range(0, len(unit_names), SHOW_BATCH_SIZE):
            batch_units = unit_names[start : start + SHOW_BATCH_SIZE]
            show_cmd = (
                *base,
                "show",
                "--no-pager",
                "-p",
                ",".join(SHOW_PROPERTIES),
                "--",
                *batch_units,
            )
            show_result = runner(show_cmd, timeout, stop)
            if show_result.cancelled:
                return (), ScopeStatus(scope=scope, available=False, unit_files_available=False, error=None)
            if show_result.timed_out or show_result.os_error or show_result.returncode != 0:
                warnings.append(_format_command_error(scope, "service metadata query", show_result))
                break
            try:
                batch_entries = parse_show_output(show_result.stdout)
            except MalformedOutputError as error:
                warnings.append(f"{SCOPE_LABELS[scope]} service metadata query returned malformed output: {error}")
                break
            if not batch_entries:
                warnings.append(
                    f"{SCOPE_LABELS[scope]} service metadata query returned malformed output: "
                    "no service entries matched requested units."
                )
                break
            for item in batch_entries:
                enriched_by_unit[item.unit] = item

    merged_loaded = [_merge_loaded_metadata(entry, enriched_by_unit.get(entry.unit)) for entry in loaded_entries]

    unit_files_cmd = (*base, "list-unit-files", "--type=service", "--output=json", "--no-pager", "--no-legend")
    files_result = runner(unit_files_cmd, timeout, stop)
    if files_result.cancelled:
        return (), ScopeStatus(scope=scope, available=False, unit_files_available=False, error=None)

    unit_file_entries: list[UnitFileEntry] = []
    unit_files_available = True
    if files_result.timed_out or files_result.os_error or files_result.returncode != 0:
        unit_files_available = False
        warnings.append(_format_command_error(scope, "unit-file query", files_result))
    else:
        try:
            unit_file_entries = parse_unit_files_json(files_result.stdout)
        except MalformedOutputError as error:
            unit_files_available = False
            warnings.append(f"{SCOPE_LABELS[scope]} unit-file query returned malformed output: {error}")

    records = merge_scope_services(scope, merged_loaded, unit_file_entries)
    status = ScopeStatus(
        scope=scope,
        available=True,
        unit_files_available=unit_files_available,
        error="\n".join(warnings) if warnings else None,
    )
    return records, status


def discover_services(
    stop: Event | None = None,
    *,
    runner: CommandRunner = run_systemctl,
    timeout: float = DEFAULT_TIMEOUT,
) -> ServicesSnapshot:
    """Discover both System and User systemd services."""
    system_records, system_status = discover_scope("system", runner=runner, timeout=timeout, stop=stop)
    if stop is not None and stop.is_set():
        return ServicesSnapshot(
            services=(),
            system=system_status,
            user=ScopeStatus(scope="user", available=False, unit_files_available=False, error=None),
            timestamp=time.monotonic(),
        )
    user_records, user_status = discover_scope("user", runner=runner, timeout=timeout, stop=stop)
    combined = tuple(
        sorted(
            (*system_records, *user_records),
            key=lambda record: (record.unit.casefold(), record.scope),
        )
    )
    return ServicesSnapshot(
        services=combined,
        system=system_status,
        user=user_status,
        timestamp=time.monotonic(),
    )
