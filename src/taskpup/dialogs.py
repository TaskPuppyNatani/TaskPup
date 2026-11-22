"""Dialogs for inspecting and acting on a selected process."""

from PySide6.QtCore import Qt, SignalInstance
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFrame, QLabel, QListWidget, QListWidgetItem, QMessageBox,
    QPlainTextEdit, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)

from taskpup.management import TreePlan
from taskpup.model import memory_text
from taskpup.platform import online_cpus
from taskpup.processes import ProcessRow, STATUSES
from taskpup.service_controls import ACTION_EFFECTS, ACTION_LABELS, RiskAssessment, ServiceAction
from taskpup.services import SCOPE_LABELS, ServiceIdentity, ServiceRecord


def process_label(row: ProcessRow) -> str:
    return f"PID {row.identity.pid} · {' '.join(row.stat.name.split())}"


def message(parent: QWidget, title: str, text: str, icon: QMessageBox.Icon, *, details: str = "") -> None:
    box = QMessageBox(icon, title, text, QMessageBox.StandardButton.Ok, parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    if details:
        box.setDetailedText(details)
    box.exec()


def confirm_signal(parent: QWidget, title: str, text: str) -> bool:
    box = QMessageBox(QMessageBox.Icon.Warning, title, text, QMessageBox.StandardButton.Cancel, parent)
    box.setTextFormat(Qt.TextFormat.PlainText)
    accept = box.addButton(title, QMessageBox.ButtonRole.DestructiveRole)
    accept.setObjectName("danger")
    box.setDefaultButton(QMessageBox.StandardButton.Cancel)
    box.exec()
    return box.clickedButton() is accept


def confirm_tree(parent: QWidget, row: ProcessRow, plan: TreePlan, force: bool) -> bool:
    title = "Force-kill process tree" if force else "End process tree"
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    layout = QVBoxLayout(dialog)
    signal_name = "SIGKILL" if force else "SIGTERM"
    effect = "Force killing can cause unsaved work to be lost." if force else "Processes can handle or ignore the termination request."
    label = QLabel(
        f"{process_label(row)}\n"
        f"Send {signal_name} to these {len(plan.targets)} processes?\n{effect}"
    )
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    layout.addWidget(label)
    targets = QListWidget()
    targets.setAccessibleName("Processes that will receive the signal")
    for stat in reversed(plan.targets):
        targets.addItem(f"PID {stat.identity.pid} · {' '.join(stat.name.split())}")
    layout.addWidget(targets)
    add_buttons(dialog, layout, title, danger=True)
    dialog.resize(480, 350)
    return dialog.exec() == QDialog.DialogCode.Accepted


def add_buttons(
    dialog: QDialog, layout: QVBoxLayout, label: str, *, danger: bool = False,
) -> QPushButton:
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
    accept = buttons.addButton(label, QDialogButtonBox.ButtonRole.AcceptRole)
    cancel = buttons.button(QDialogButtonBox.StandardButton.Cancel)
    if danger:
        accept.setObjectName("danger")
        cancel.setDefault(True)
        cancel.setFocus()
    else:
        accept.setDefault(True)
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    return accept


def choose_priority(parent: QWidget, row: ProcessRow, current: int) -> int | None:
    dialog = QDialog(parent)
    dialog.setWindowTitle("Change priority")
    layout = QVBoxLayout(dialog)
    text = QLabel(f"{process_label(row)}\nNice value for the main thread. Lower values give it more priority.")
    text.setTextFormat(Qt.TextFormat.PlainText)
    text.setWordWrap(True)
    layout.addWidget(text)
    nice = QSpinBox()
    nice.setAccessibleName("Nice value")
    nice.setRange(-20, 19)
    nice.setValue(current)
    layout.addWidget(nice)
    add_buttons(dialog, layout, "Apply")
    nice.setFocus()
    dialog.resize(390, 135)
    return nice.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


def choose_affinity(parent: QWidget, row: ProcessRow, current: set[int]) -> set[int] | None:
    dialog = QDialog(parent)
    dialog.setWindowTitle("Change CPU affinity")
    layout = QVBoxLayout(dialog)
    label = QLabel(f"{process_label(row)}\nChoose the CPUs where the main thread may run.")
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    layout.addWidget(label)
    listing = QListWidget()
    listing.setAccessibleName("Available CPU cores")
    try:
        available = online_cpus()
    except (OSError, ValueError):
        available = set()
    items: dict[int, QListWidgetItem] = {}
    for cpu in sorted(available | current):
        item = QListWidgetItem(f"CPU {cpu}", listing)
        item.setCheckState(Qt.CheckState.Checked if cpu in current else Qt.CheckState.Unchecked)
        items[cpu] = item
    layout.addWidget(listing)
    apply = add_buttons(dialog, layout, "Apply")

    def checked() -> set[int]:
        return {cpu for cpu, item in items.items() if item.checkState() == Qt.CheckState.Checked}

    listing.itemChanged.connect(lambda: apply.setEnabled(bool(checked())))
    dialog.resize(385, 370)
    return checked() if dialog.exec() == QDialog.DialogCode.Accepted else None


def show_properties(parent: QWidget, row: ProcessRow) -> None:
    stat = row.stat
    cpu = f"{row.cpu:.1f}%" if row.cpu is not None else "Waiting for next sample"
    dialog = QDialog(parent)
    dialog.setWindowTitle("Process properties")
    layout = QVBoxLayout(dialog)
    details = QPlainTextEdit(
        f"Process: {stat.name}\n"
        f"PID: {row.identity.pid}\n"
        f"Parent PID: {stat.ppid}\n"
        f"User: {row.username or 'Unavailable'}\n"
        f"Status: {STATUSES.get(stat.state, stat.state)}\n"
        f"CPU: {cpu}\n"
        f"Resident memory: {memory_text(stat.rss)}\n"
        f"Threads: {stat.threads}\n"
        f"Nice: {stat.nice}\n"
        f"Executable: {row.executable or 'Unavailable'}\n\n"
        f"Command line\n{row.command or 'Unavailable'}"
    )
    details.setAccessibleName("Process properties")
    details.setReadOnly(True)
    layout.addWidget(details)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    dialog.resize(540, 370)
    dialog.exec()


def confirm_service_action(
    parent: QWidget,
    record: ServiceRecord,
    action: ServiceAction,
    risk: RiskAssessment,
) -> bool:
    """Ask the user to confirm a systemd service control operation."""
    action_label = ACTION_LABELS[action]
    title = f"{action_label} service"
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    layout = QVBoxLayout(dialog)
    layout.setSpacing(10)

    heading = QLabel(f"{action_label}: {record.unit}")
    heading.setObjectName("resourceName")
    heading.setTextFormat(Qt.TextFormat.PlainText)
    heading.setWordWrap(True)
    layout.addWidget(heading)

    details_lines = [
        f"Scope: {record.scope_label} service",
        f"Current state: {record.state_label} · Startup: {record.enablement_label}",
        ACTION_EFFECTS[action],
    ]
    if record.scope == "system":
        details_lines.append("This System service change may prompt for administrator authorization via Polkit.")
    summary = QLabel("\n".join(details_lines))
    summary.setTextFormat(Qt.TextFormat.PlainText)
    summary.setWordWrap(True)
    layout.addWidget(summary)

    if risk.notes:
        note_label = QLabel("\n".join(risk.notes))
        note_label.setObjectName("performanceMuted")
        note_label.setTextFormat(Qt.TextFormat.PlainText)
        note_label.setWordWrap(True)
        layout.addWidget(note_label)

    ack_checkbox: QCheckBox | None = None
    if risk.level == "high" and risk.warnings:
        warning_box = QFrame()
        warning_box.setObjectName("serviceRiskBox")
        warning_layout = QVBoxLayout(warning_box)
        warning_layout.setContentsMargins(10, 8, 10, 8)
        warning_layout.setSpacing(4)
        warning_title = QLabel(f"High-risk operation ({risk.category or 'Critical Service'})")
        warning_title.setObjectName("serviceRiskTitle")
        warning_title.setTextFormat(Qt.TextFormat.PlainText)
        warning_title.setWordWrap(True)
        warning_body = QLabel("\n".join(f"• {warning}" for warning in risk.warnings))
        warning_body.setObjectName("serviceNoticeText")
        warning_body.setTextFormat(Qt.TextFormat.PlainText)
        warning_body.setWordWrap(True)
        warning_layout.addWidget(warning_title)
        warning_layout.addWidget(warning_body)
        layout.addWidget(warning_box)

        ack_checkbox = QCheckBox("I understand the potential impact on this system")
        layout.addWidget(ack_checkbox)

    disruptive = action in {"stop", "restart", "disable"} or risk.level == "high"
    accept = add_buttons(dialog, layout, action_label, danger=disruptive)
    if ack_checkbox is not None:
        accept.setEnabled(False)
        ack_checkbox.toggled.connect(accept.setEnabled)

    dialog.setMinimumWidth(440)
    return dialog.exec() == QDialog.DialogCode.Accepted


def confirm_close_with_pending_service_action(
    parent: QWidget,
    identity: ServiceIdentity,
    action: ServiceAction,
    *,
    finished_signal: SignalInstance | None = None,
) -> bool:
    """Confirm exiting while a systemd service operation is still being monitored."""
    dialog = QDialog(parent)
    dialog.setWindowTitle("Service operation in progress")
    layout = QVBoxLayout(dialog)
    layout.setSpacing(10)

    action_label = ACTION_LABELS[action]
    scope_label = SCOPE_LABELS[identity.scope]

    heading = QLabel(f"{action_label} on {identity.unit} is still in progress")
    heading.setObjectName("resourceName")
    heading.setTextFormat(Qt.TextFormat.PlainText)
    heading.setWordWrap(True)
    layout.addWidget(heading)

    body = QLabel(
        f"Service: {identity.unit}\n"
        f"Scope: {scope_label} service\n"
        f"Requested operation: {action_label}\n\n"
        "TaskPup is still monitoring this operation. Exiting now stops local monitoring, "
        "but does not guarantee that the request is cancelled: systemd may continue changing "
        "the service in the background after TaskPup closes, and the final outcome will be unknown."
    )
    body.setTextFormat(Qt.TextFormat.PlainText)
    body.setWordWrap(True)
    layout.addWidget(body)

    buttons = QDialogButtonBox()
    keep_open = buttons.addButton("Keep TaskPup Open", QDialogButtonBox.ButtonRole.RejectRole)
    exit_anyway = buttons.addButton("Exit Anyway", QDialogButtonBox.ButtonRole.DestructiveRole)
    exit_anyway.setObjectName("danger")
    keep_open.setDefault(True)
    keep_open.setFocus()
    keep_open.clicked.connect(dialog.reject)
    exit_anyway.clicked.connect(dialog.accept)
    layout.addWidget(buttons)

    completed_while_open = False

    def on_finished(_result: object) -> None:
        nonlocal completed_while_open
        completed_while_open = True
        dialog.reject()

    if finished_signal is not None:
        finished_signal.connect(on_finished)
    try:
        dialog.setMinimumWidth(450)
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
    finally:
        if finished_signal is not None:
            try:
                finished_signal.disconnect(on_finished)
            except RuntimeError:
                pass
    return accepted and not completed_while_open
