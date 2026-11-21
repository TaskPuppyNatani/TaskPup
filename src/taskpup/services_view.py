"""Read-only Qt table model, filters, and details view for systemd services."""

from collections.abc import Iterable
from html import escape
from typing import cast

from PySide6.QtCore import QAbstractTableModel, QItemSelectionModel, QModelIndex, QPersistentModelIndex, QPoint, QSignalBlocker, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QScrollArea, QSplitter, QTreeView, QVBoxLayout, QWidget,
)

from taskpup.services import (
    ScopeFilter, ServiceIdentity, ServiceRecord, ServicesSnapshot, StateFilter, UNAVAILABLE, matches_filters,
)

SERVICE_COLUMNS = ("Service", "Description", "State", "Startup", "Scope")
SERVICE_WIDTHS = (225, 255, 145, 130, 80)

STATE_FILTERS: tuple[tuple[str, StateFilter], ...] = (
    ("All states", "all"),
    ("Running", "running"),
    ("Active (exited / other)", "active_other"),
    ("Stopped / inactive", "inactive"),
    ("Failed", "failed"),
)

SCOPE_FILTERS: tuple[tuple[str, ScopeFilter], ...] = (
    ("All scopes", "all"),
    ("System", "system"),
    ("User", "user"),
)

DETAIL_FIELDS = (
    "Unit name",
    "Description",
    "Scope",
    "State",
    "Load state",
    "Active state",
    "Substate",
    "Enablement",
    "Vendor preset",
    "Unit file path",
    "Service type",
    "Main PID",
    "Configured user",
    "Result",
    "Active since",
    "Triggered by",
    "Transient",
    "Status",
)

_STATE_COLORS: dict[str, QColor] = {
    "running": QColor("#8fe7ac"),
    "active_other": QColor("#9bd9c7"),
    "failed": QColor("#ff9bb0"),
    "transitioning": QColor("#d0a0ff"),
    "inactive": QColor("#bcb2c9"),
    "other": QColor("#bcb2c9"),
    "unknown": QColor("#bcb2c9"),
}


def _row_values(record: ServiceRecord) -> tuple[str, str, str, str, str]:
    return (
        record.unit,
        record.description or "",
        record.state_label,
        record.enablement_label,
        record.scope_label,
    )


class ServiceTableModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[ServiceRecord] = []
        self.rows_by_identity: dict[ServiceIdentity, int] = {}

    def replace(
        self,
        records: Iterable[ServiceRecord],
        *,
        query: str,
        state_filter: StateFilter,
        scope_filter: ScopeFilter,
        column: int,
        order: Qt.SortOrder,
    ) -> None:
        self.beginResetModel()
        visible = [
            record
            for record in records
            if matches_filters(
                record,
                query=query,
                state_filter=state_filter,
                scope_filter=scope_filter,
            )
        ]
        safe_column = column if 0 <= column < len(SERVICE_COLUMNS) else 0
        visible.sort(
            key=lambda record: self.sort_value(record, safe_column),
            reverse=order == Qt.SortOrder.DescendingOrder,
        )
        self.records = visible
        self.rows_by_identity = {record.identity: row for row, record in enumerate(visible)}
        self.endResetModel()

    @staticmethod
    def sort_value(record: ServiceRecord, column: int) -> tuple[str, str, str]:
        return (_row_values(record)[column].casefold(), record.unit.casefold(), record.scope)

    def index_for(self, identity: ServiceIdentity | None) -> QModelIndex:
        if identity is None:
            return QModelIndex()
        row = self.rows_by_identity.get(identity)
        if row is None:
            return QModelIndex()
        return self.index(row, 0)

    def service_at(self, index: QModelIndex | QPersistentModelIndex) -> ServiceRecord | None:
        if not index.isValid():
            return None
        row = index.row()
        if 0 <= row < len(self.records):
            return self.records[row]
        return None

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self.records)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        return len(SERVICE_COLUMNS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if 0 <= section < len(SERVICE_COLUMNS):
                return SERVICE_COLUMNS[section]
        return None

    def data(self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        record = self.service_at(index)
        if record is None:
            return None
        column = index.column()
        if role == Qt.ItemDataRole.ForegroundRole:
            if column == 2:
                return _STATE_COLORS.get(record.state_category, QColor("#bcb2c9"))
            if column == 3:
                state = record.unit_file_state
                if state in {"enabled", "enabled-runtime"}:
                    return QColor("#8fe7ac")
                if state in {"masked", "masked-runtime", "bad"}:
                    return QColor("#ff9bb0")
                if state in {"generated", "transient"} or (state is None and record.transient is True):
                    return QColor("#cb94ff")
                return QColor("#c9c0d4")
            if column == 4:
                return QColor("#d0a0ff") if record.scope == "user" else QColor("#edeaf4")
            return None
        if role not in {Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole}:
            return None
        value = _row_values(record)[column]
        if role == Qt.ItemDataRole.ToolTipRole:
            if column == 0:
                tooltip = f"{record.scope_label} · {record.unit}"
            else:
                tooltip = value
            return f"<qt>{escape(tooltip)}</qt>" if tooltip else None
        return value if value else "—"


class ServiceDetailsPanel(QFrame):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("performancePanel")
        self.setMinimumWidth(220)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(8)

        self.heading = QLabel("Service details")
        self.heading.setObjectName("resourceName")
        self.heading.setTextFormat(Qt.TextFormat.PlainText)
        self.heading.setWordWrap(True)
        self.heading.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        outer.addWidget(self.heading)

        self.summary = QLabel()
        self.summary.setObjectName("performanceMuted")
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        self.summary.setWordWrap(True)
        self.summary.hide()
        outer.addWidget(self.summary)

        self.empty_hint = QLabel("Select a service to inspect its unit metadata.")
        self.empty_hint.setObjectName("performanceMuted")
        self.empty_hint.setTextFormat(Qt.TextFormat.PlainText)
        self.empty_hint.setWordWrap(True)
        outer.addWidget(self.empty_hint)

        self.details_scroll = QScrollArea()
        self.details_scroll.setObjectName("serviceDetailsScroll")
        self.details_scroll.setWidgetResizable(True)
        self.details_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.details_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget()
        content.setObjectName("serviceDetailsContent")
        fields_layout = QVBoxLayout(content)
        fields_layout.setContentsMargins(0, 4, 4, 4)
        fields_layout.setSpacing(10)

        self.rows: dict[str, QWidget] = {}
        self.fields: dict[str, QLabel] = {}
        for name in DETAIL_FIELDS:
            row_widget = QWidget()
            row_layout = QVBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(2)
            caption = QLabel(name)
            caption.setObjectName("performanceMuted")
            caption.setTextFormat(Qt.TextFormat.PlainText)
            value = QLabel()
            value.setObjectName("serviceDetailValue")
            value.setAccessibleName(name)
            value.setTextFormat(Qt.TextFormat.PlainText)
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            row_layout.addWidget(caption)
            row_layout.addWidget(value)
            fields_layout.addWidget(row_widget)
            self.rows[name] = row_widget
            self.fields[name] = value
        fields_layout.addStretch()
        self.details_scroll.setWidget(content)
        self.details_scroll.hide()
        outer.addWidget(self.details_scroll, 1)

    def show_service(self, record: ServiceRecord | None) -> None:
        if record is None:
            self.heading.setText("Service details")
            self.summary.clear()
            self.summary.hide()
            self.empty_hint.show()
            self.details_scroll.hide()
            for label in self.fields.values():
                label.clear()
            return

        self.heading.setText(record.unit)
        self.summary.setText(f"{record.scope_label} service · {record.state_label} · {record.enablement_label}")
        self.summary.show()
        self.empty_hint.hide()
        self.details_scroll.show()

        if record.main_pid is not None:
            main_pid = str(record.main_pid)
        elif record.loaded:
            main_pid = "None"
        else:
            main_pid = UNAVAILABLE

        if record.user:
            configured_user = record.user
        elif record.loaded:
            configured_user = "Default (unset)"
        else:
            configured_user = UNAVAILABLE

        if record.triggered_by:
            triggered_by = ", ".join(record.triggered_by)
        elif record.loaded:
            triggered_by = "None"
        else:
            triggered_by = UNAVAILABLE

        if record.transient is True:
            transient_text = "Yes"
        elif record.transient is False:
            transient_text = "No"
        else:
            transient_text = UNAVAILABLE

        values = {
            "Unit name": record.unit,
            "Description": record.description or UNAVAILABLE,
            "Scope": record.scope_label,
            "State": record.state_label,
            "Load state": record.load_state_label,
            "Active state": record.active_state_label,
            "Substate": record.sub_state_label,
            "Enablement": record.enablement_label,
            "Vendor preset": record.preset_label,
            "Unit file path": record.fragment_path or UNAVAILABLE,
            "Service type": record.service_type or UNAVAILABLE,
            "Main PID": main_pid,
            "Configured user": configured_user,
            "Result": record.result or UNAVAILABLE,
            "Active since": record.active_enter_timestamp or UNAVAILABLE,
            "Triggered by": triggered_by,
            "Transient": transient_text,
            "Status": record.status_text or "",
        }
        for name, text in values.items():
            self.fields[name].setText(text)
        self.rows["Status"].setVisible(bool(record.status_text))


class ServicesPage(QWidget):
    refresh_requested = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.snapshot: ServicesSnapshot | None = None
        self.loading = False
        self.initialized = False
        self.model = ServiceTableModel()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(11)

        section = QHBoxLayout()
        title = QLabel("Services")
        title.setObjectName("section")
        self.count = QLabel("0")
        self.count.setObjectName("count")
        self.state_summary = QLabel("Open Services to load systemd units")
        self.state_summary.setObjectName("count")
        self.state_summary.setTextFormat(Qt.TextFormat.PlainText)
        section.addWidget(title)
        section.addWidget(self.count)
        section.addStretch()
        section.addWidget(self.state_summary)
        layout.addLayout(section)

        controls = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setAccessibleName("Search services")
        self.search.setPlaceholderText("Search by service name or description…")
        self.search.setClearButtonEnabled(True)

        self.state_filter = QComboBox()
        self.state_filter.setAccessibleName("Filter by service state")
        for label, key in STATE_FILTERS:
            self.state_filter.addItem(label, key)

        self.scope_filter = QComboBox()
        self.scope_filter.setAccessibleName("Filter by service scope")
        for label, key in SCOPE_FILTERS:
            self.scope_filter.addItem(label, key)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setAccessibleName("Refresh services")
        self.refresh_button.setToolTip("Refresh services (F5)")

        controls.addWidget(self.search, 1)
        controls.addWidget(self.state_filter)
        controls.addWidget(self.scope_filter)
        controls.addWidget(self.refresh_button)
        layout.addLayout(controls)

        self.notice = QFrame()
        self.notice.setObjectName("serviceNotice")
        notice_layout = QHBoxLayout(self.notice)
        notice_layout.setContentsMargins(10, 7, 10, 7)
        self.notice_label = QLabel()
        self.notice_label.setObjectName("serviceNoticeText")
        self.notice_label.setTextFormat(Qt.TextFormat.PlainText)
        self.notice_label.setWordWrap(True)
        notice_layout.addWidget(self.notice_label)
        self.notice.hide()
        layout.addWidget(self.notice)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setChildrenCollapsible(False)

        self.view = QTreeView()
        self.view.setAccessibleName("Systemd services")
        self.view.setMinimumWidth(300)
        self.view.setModel(self.model)
        self.view.setRootIsDecorated(False)
        self.view.setItemsExpandable(False)
        self.view.setUniformRowHeights(True)
        self.view.setAlternatingRowColors(True)
        self.view.setAllColumnsShowFocus(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.view.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.view.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        header = self.view.header()
        header.setSectionsClickable(True)
        header.setSortIndicatorShown(True)
        header.setSortIndicator(0, Qt.SortOrder.AscendingOrder)
        for column, width in enumerate(SERVICE_WIDTHS):
            self.view.setColumnWidth(column, width)

        self.details = ServiceDetailsPanel()
        self.splitter.addWidget(self.view)
        self.splitter.addWidget(self.details)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setSizes([780, 340])
        layout.addWidget(self.splitter, 1)

        self.search.textChanged.connect(self.redraw)
        self.state_filter.currentIndexChanged.connect(self.redraw)
        self.scope_filter.currentIndexChanged.connect(self.redraw)
        header.sortIndicatorChanged.connect(self.redraw)
        self.view.selectionModel().selectionChanged.connect(self.update_selection)
        self.refresh_button.clicked.connect(self.request_refresh)

    def ensure_loaded(self) -> None:
        if not self.initialized and not self.loading:
            self.request_refresh()

    def request_refresh(self) -> None:
        self.loading = True
        self.initialized = True
        self.state_summary.setText("Refreshing services…")
        self.refresh_requested.emit()

    def focus_search(self) -> None:
        self.search.setFocus()
        self.search.selectAll()

    def apply_snapshot(self, snapshot: ServicesSnapshot) -> None:
        self.snapshot = snapshot
        self.loading = False
        self.initialized = True
        warnings = snapshot.warnings()
        if warnings:
            self.notice_label.setText("\n".join(warnings))
            self.notice.show()
        else:
            self.notice_label.clear()
            self.notice.hide()

        system_count = sum(1 for item in snapshot.services if item.scope == "system")
        user_count = sum(1 for item in snapshot.services if item.scope == "user")
        parts = [
            f"System: {system_count:,}" if snapshot.system.available else "System: unavailable",
            f"User: {user_count:,}" if snapshot.user.available else "User: unavailable",
        ]
        self.state_summary.setText(" · ".join(parts))
        self.redraw()

    def apply_error(self, message: str) -> None:
        self.loading = False
        self.initialized = True
        self.notice_label.setText(f"Service discovery failed: {message}")
        self.notice.show()
        self.state_summary.setText("Service refresh failed")

    def current_state_filter(self) -> StateFilter:
        value = self.state_filter.currentData()
        return cast(StateFilter, value) if isinstance(value, str) else "all"

    def current_scope_filter(self) -> ScopeFilter:
        value = self.scope_filter.currentData()
        return cast(ScopeFilter, value) if isinstance(value, str) else "all"

    def selected(self) -> ServiceRecord | None:
        rows = self.view.selectionModel().selectedRows()
        return self.model.service_at(rows[0]) if rows else None

    def update_selection(self) -> None:
        self.details.show_service(self.selected())

    def redraw(self) -> None:
        view = self.view
        header = view.header()
        selection = self.selected()
        selected_identity = selection.identity if selection is not None else None
        top_index = view.indexAt(QPoint(1, 1))
        top = self.model.service_at(top_index)
        top_offset = view.visualRect(top_index).top() if top is not None else 0
        vertical = view.verticalScrollBar().value()
        horizontal = view.horizontalScrollBar().value()

        all_rows = self.snapshot.services if self.snapshot is not None else ()
        with QSignalBlocker(view), QSignalBlocker(view.selectionModel()):
            self.model.replace(
                all_rows,
                query=self.search.text().strip(),
                state_filter=self.current_state_filter(),
                scope_filter=self.current_scope_filter(),
                column=header.sortIndicatorSection(),
                order=header.sortIndicatorOrder(),
            )
            selected_index = self.model.index_for(selected_identity)
            if selected_index.isValid():
                flags = QItemSelectionModel.SelectionFlag
                view.selectionModel().setCurrentIndex(selected_index, flags.ClearAndSelect | flags.Rows)
            else:
                view.selectionModel().clearSelection()
            view.doItemsLayout()
            anchor = self.model.index_for(top.identity if top is not None else None)
            if anchor.isValid() and view.visualRect(anchor).isValid():
                view.scrollTo(anchor, QAbstractItemView.ScrollHint.PositionAtTop)
                vertical = view.verticalScrollBar().value() - top_offset
            view.verticalScrollBar().setValue(vertical)
            view.horizontalScrollBar().setValue(horizontal)

        visible = len(self.model.records)
        total = len(all_rows)
        self.count.setText(f"{visible:,} of {total:,}" if visible != total else f"{visible:,}")
        self.update_selection()
