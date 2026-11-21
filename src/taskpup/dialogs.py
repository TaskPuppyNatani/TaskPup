"""Dialogs for inspecting and acting on a selected process."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QLabel, QListWidget, QListWidgetItem, QMessageBox,
    QPlainTextEdit, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)

from taskpup.management import TreePlan
from taskpup.model import memory_text
from taskpup.platform import online_cpus
from taskpup.processes import ProcessRow, STATUSES


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
