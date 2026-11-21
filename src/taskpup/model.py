"""Sortable flat and hierarchical Qt models over process snapshots."""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from html import escape
from pathlib import Path
from typing import overload

from PySide6.QtCore import QAbstractItemModel, QModelIndex, QObject, QPersistentModelIndex, Qt
from PySide6.QtGui import QIcon

from taskpup.processes import Identity, ProcessRow, STATUSES


COLUMNS = (
    "Process", "PID", "Parent PID", "User", "CPU", "Memory", "Status", "Threads",
    "Nice", "Command line",
)
WIDTHS = (212, 72, 90, 116, 74, 97, 106, 72, 62, 300)
NUMBER_COLUMNS = {1, 2, 4, 5, 7, 8}


def memory_text(size: int) -> str:
    amount = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:,.0f} {unit}" if unit == "B" else f"{amount:,.1f} {unit}"
        amount /= 1024
    return ""


def values(row: ProcessRow) -> tuple[str | int | float | None, ...]:
    stat = row.stat
    return (
        stat.name, row.identity.pid, stat.ppid, row.username, row.cpu, stat.rss,
        STATUSES.get(stat.state, stat.state), stat.threads, stat.nice,
        row.command or row.executable,
    )


@dataclass(eq=False, slots=True)
class Node:
    process: ProcessRow | None = None
    parent: "Node | None" = None
    number: int = 0
    children: list["Node"] = field(default_factory=list)


class ProcessModel(QAbstractItemModel):
    def __init__(self) -> None:
        super().__init__()
        self.root = Node()
        self.nodes: dict[Identity, Node] = {}
        self.icons: dict[str, str] = {}
        self.icon_cache: dict[str, QIcon] = {}

    def replace(
        self,
        rows: Iterable[ProcessRow],
        query: str,
        uid: int | None,
        tree: bool,
        column: int,
        order: Qt.SortOrder,
    ) -> None:
        self.beginResetModel()
        self.root = Node()
        selected_rows = {row.identity.pid: row for row in rows if uid is None or row.uid == uid}
        parents: dict[int, int] = {}
        if tree:
            for pid, row in selected_rows.items():
                parent = selected_rows.get(row.stat.ppid)
                if (
                    parent is not None and parent.identity.start_ticks <= row.identity.start_ticks
                    and parent.identity.pid != pid
                ):
                    parents[pid] = parent.identity.pid
        terms = query.casefold().split()
        visible: set[int] = set()
        for pid, row in selected_rows.items():
            if terms:
                text = " ".join(str(value) for value in values(row) if value is not None)
                searchable = f"{text} {row.executable}".casefold()
                if not all(term in searchable for term in terms):
                    continue
            while pid not in visible:
                visible.add(pid)
                if pid not in parents:
                    break
                pid = parents[pid]

        by_pid = {pid: Node(selected_rows[pid]) for pid in visible}
        for pid, node in by_pid.items():
            node.parent = by_pid.get(parents.get(pid, 0), self.root)
            node.parent.children.append(node)

        # Work iteratively so a long process tree does not exhaust Python's stack.
        self.nodes = {}
        pending = [self.root]
        while pending:
            parent = pending.pop()
            parent.children.sort(
                key=lambda node: self.sort_value(node, column),
                reverse=order == Qt.SortOrder.DescendingOrder,
            )
            for number, node in enumerate(parent.children):
                node.number = number
                if node.process is not None:
                    self.nodes[node.process.identity] = node
                pending.append(node)
        self.endResetModel()

    @staticmethod
    def sort_value(node: Node, column: int) -> tuple[str | int | float, int]:
        assert node.process is not None
        value = values(node.process)[column]
        if isinstance(value, str):
            value = value.casefold()
        return (-1 if value is None else value, node.process.identity.pid)

    def index_for(self, identity: Identity | None) -> QModelIndex:
        node = self.nodes.get(identity) if identity is not None else None
        if node is None:
            return QModelIndex()
        return self.createIndex(node.number, 0, node)

    def identities(self) -> Iterator[Identity]:
        return iter(self.nodes)

    def process_at(self, index: QModelIndex | QPersistentModelIndex) -> ProcessRow | None:
        return index.internalPointer().process if index.isValid() else None

    def icon_for(self, row: ProcessRow) -> QIcon:
        name = self.icons.get(Path(row.executable).name) or self.icons.get(row.stat.name)
        key = name or ""
        if key not in self.icon_cache:
            icon = QIcon(key) if key.startswith("/") else QIcon.fromTheme(key)
            if icon.isNull():
                icon = QIcon.fromTheme("application-x-executable")
            self.icon_cache[key] = icon
        return self.icon_cache[key]

    def index(
        self, row: int, column: int, parent: QModelIndex | QPersistentModelIndex = QModelIndex(),
    ) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        node = parent.internalPointer() if parent.isValid() else self.root
        return self.createIndex(row, column, node.children[row])

    @overload
    def parent(self, /) -> QObject | None: ...

    @overload
    def parent(self, index: QModelIndex | QPersistentModelIndex, /) -> QModelIndex: ...

    def parent(self, index: QModelIndex | QPersistentModelIndex | None = None, /) -> QModelIndex | QObject | None:
        if index is None:
            return super().parent()
        if not index.isValid():
            return QModelIndex()
        node = index.internalPointer().parent
        if node is None or node is self.root:
            return QModelIndex()
        return self.createIndex(node.number, 0, node)

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        if parent.isValid() and parent.column() != 0:
            return 0
        node = parent.internalPointer() if parent.isValid() else self.root
        return len(node.children)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        return len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole and 0 <= section < len(COLUMNS):
            return COLUMNS[section]
        return None

    def data(self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        row = self.process_at(index)
        if row is None:
            return None
        column = index.column()
        if role == Qt.ItemDataRole.DecorationRole and column == 0:
            return self.icon_for(row)
        if role == Qt.ItemDataRole.TextAlignmentRole and column in NUMBER_COLUMNS:
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        if role not in {Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole}:
            return None
        value = values(row)[column]
        if column == 4 and row.cpu is not None:
            value = f"{row.cpu:,.1f}%"
        elif column == 5:
            value = memory_text(row.stat.rss)
        if role == Qt.ItemDataRole.ToolTipRole:
            if column == 0:
                value = f"PID {row.identity.pid} · {row.stat.name}"
            return f"<qt>{escape(str(value))}</qt>" if value is not None and value != "" else None
        return "—" if value is None or value == "" else value
