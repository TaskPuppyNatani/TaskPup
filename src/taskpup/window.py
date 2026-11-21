"""The process manager window and its action handlers."""

from collections.abc import Callable
import os
import signal

from PySide6.QtCore import QItemSelectionModel, QModelIndex, QPoint, QSignalBlocker, QSize, Qt
from PySide6.QtGui import QAction, QBitmap, QCloseEvent, QImage, QKeySequence, QPixmap, QRegion
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QFrame, QHBoxLayout,
    QInputDialog, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox, QProgressBar,
    QPushButton, QStackedWidget, QTabBar, QTreeView, QVBoxLayout, QWidget,
)

from taskpup import dialogs, management
from taskpup.dashboard import PerformanceDashboard
from taskpup.metrics import SystemSample
from taskpup.model import COLUMNS, WIDTHS, ProcessModel
from taskpup.platform import logo_path, open_executable_location, start_task
from taskpup.processes import Identity, ProcessRow, Resources, Snapshot
from taskpup.refresh import RefreshController
from taskpup.report_dialog import ReportDialog
from taskpup.settings import Settings


class Metric(QFrame):
    def __init__(self, title: str, *, percentage: bool = True, secondary: bool = False) -> None:
        super().__init__()
        self.setObjectName("metric")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(13, 9, 13, 10)
        layout.setSpacing(4)
        label = QLabel(title)
        label.setObjectName("metricTitle")
        self.value = QLabel("—")
        self.value.setObjectName("metricValue")
        layout.addWidget(label)
        layout.addWidget(self.value)
        self.bar: QProgressBar | None = None
        if percentage:
            self.bar = QProgressBar()
            self.bar.setAccessibleName(title)
            self.bar.setFixedHeight(4)
            self.bar.setTextVisible(False)
            if secondary:
                self.bar.setObjectName("secondary")
            layout.addWidget(self.bar)
        else:
            layout.addSpacing(4)

    def display(self, number: float | int | None, unavailable: str = "—") -> None:
        if self.bar is None:
            self.value.setText(f"{number:,}" if number is not None else unavailable)
        else:
            self.value.setText(f"{number:.1f}%" if number is not None else unavailable)
            self.bar.setValue(round(number) if number is not None else 0)


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings | None = None) -> None:
        super().__init__()
        self.settings = settings if settings is not None else Settings()
        self.rows: tuple[ProcessRow, ...] = ()
        self.collapsed: set[Identity] = set()
        self.model = ProcessModel()
        self.refresh = RefreshController(self)

        self.setWindowTitle("TaskPup")
        self.resize(1210, 740)
        self.setMinimumSize(770, 470)
        body = QWidget()
        self.setCentralWidget(body)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(20, 15, 20, 8)
        layout.setSpacing(11)

        brand_row = QHBoxLayout()
        brand_row.setSpacing(12)
        brand_icon = QLabel()
        brand_icon.setObjectName("brandLogo")
        logo = QImage(str(logo_path()))
        if not logo.isNull():
            mask = QBitmap.fromImage(logo.createAlphaMask(Qt.ImageConversionFlag.ThresholdDither))
            artwork = QRegion(mask).boundingRect()
            if not artwork.isEmpty():
                logo = logo.copy(artwork)
            brand_icon.setPixmap(QPixmap.fromImage(logo))
            brand_icon.setFixedSize(logo.size().scaled(QSize(48, 48), Qt.AspectRatioMode.KeepAspectRatio))
            brand_icon.setScaledContents(True)
        brand_text = QVBoxLayout()
        brand_text.setSpacing(2)
        brand = QLabel("TaskPup")
        brand.setObjectName("brand")
        tagline = QLabel("Sit. Stay. SIGKILL.")
        tagline.setObjectName("brandTagline")
        brand_text.addWidget(brand)
        brand_text.addWidget(tagline)
        brand_row.addWidget(brand_icon, alignment=Qt.AlignmentFlag.AlignVCenter)
        brand_row.addLayout(brand_text)
        brand_row.setAlignment(brand_text, Qt.AlignmentFlag.AlignVCenter)
        brand_row.addStretch()
        self.report_button = QPushButton("Export System Report…")
        self.report_button.setObjectName("secondary")
        self.report_button.setAccessibleName("Export system diagnostic report")
        brand_row.addWidget(self.report_button, alignment=Qt.AlignmentFlag.AlignVCenter)
        run = QPushButton("Run new task…")
        run.setObjectName("primary")
        brand_row.addWidget(run, alignment=Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(brand_row)

        self.navigation = QTabBar()
        self.navigation.setObjectName("mainNavigation")
        self.navigation.setAccessibleName("TaskPup views")
        self.navigation.setExpanding(False)
        self.navigation.setDrawBase(False)
        self.navigation.setUsesScrollButtons(False)
        self.navigation.addTab("Processes")
        self.navigation.addTab("Performance")
        layout.addWidget(self.navigation, alignment=Qt.AlignmentFlag.AlignLeft)
        pages = QStackedWidget()
        processes = QWidget()
        self.performance = PerformanceDashboard(self.settings)
        pages.addWidget(processes)
        pages.addWidget(self.performance)
        self.navigation.currentChanged.connect(pages.setCurrentIndex)
        layout.addWidget(pages, 1)

        layout = QVBoxLayout(processes)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(11)
        summary = QHBoxLayout()
        self.cpu = Metric("CPU utilization")
        self.ram = Metric("RAM usage", secondary=True)
        self.swap = Metric("Swap usage", secondary=True)
        self.total_processes = Metric("Total processes", percentage=False)
        self.total_processes.setToolTip("Processes discovered in the latest system-wide snapshot")
        for metric in (self.cpu, self.ram, self.swap, self.total_processes):
            summary.addWidget(metric, 1)
        layout.addLayout(summary)
        layout.addSpacing(2)

        section = QHBoxLayout()
        title = QLabel("Processes")
        title.setObjectName("section")
        self.count = QLabel()
        self.count.setObjectName("count")
        section.addWidget(title)
        section.addWidget(self.count)
        section.addStretch()
        self.stop_button = QPushButton("End task…")
        self.stop_button.setObjectName("danger")
        self.stop_button.setEnabled(False)
        section.addWidget(self.stop_button)
        layout.addLayout(section)

        controls = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setAccessibleName("Search processes")
        self.search.setPlaceholderText("Search by name, PID, user, or command…")
        self.search.setClearButtonEnabled(True)
        self.mine = QCheckBox("My processes")
        self.mine.setChecked(self.settings.option("view/mine", False))
        self.mode = QComboBox()
        self.mode.setAccessibleName("Process view")
        self.mode.addItems(["Flat view", "Tree view"])
        self.mode.setCurrentIndex(int(self.settings.option("view/tree", False)))
        self.auto = QCheckBox("Auto-refresh")
        self.auto.setChecked(self.settings.option("view/auto", True))
        refresh_button = QPushButton("Refresh")
        refresh_button.setToolTip("Refresh processes (F5)")
        columns_button = QPushButton("Columns")
        controls.addWidget(self.search, 1)
        for widget in (self.mine, self.mode, self.auto, refresh_button, columns_button):
            controls.addWidget(widget)
        layout.addLayout(controls)

        self.view = QTreeView()
        self.view.setAccessibleName("Processes")
        self.view.setModel(self.model)
        self.view.setUniformRowHeights(True)
        self.view.setAlternatingRowColors(True)
        self.view.setAllColumnsShowFocus(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.view.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.view.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.view.setIndentation(17)
        header = self.view.header()
        header.setSectionsClickable(True)
        header.setSortIndicatorShown(True)
        for column, width in enumerate(WIDTHS):
            self.view.setColumnWidth(column, width)
        layout.addWidget(self.view, 1)

        columns = QMenu(self)
        columns_button.setMenu(columns)
        for section_index, name in enumerate(COLUMNS[1:], start=1):
            action = columns.addAction(name)
            action.setCheckable(True)
            action.toggled.connect(
                lambda checked, col=section_index: self.view.setColumnHidden(col, not checked)
            )
        columns.aboutToShow.connect(lambda: self.update_columns_menu(columns))

        self.settings.restore(self, self.view)
        self.search.textChanged.connect(self.redraw)
        self.mine.toggled.connect(self.redraw)
        self.mode.currentIndexChanged.connect(self.redraw)
        header.sortIndicatorChanged.connect(self.redraw)
        self.view.selectionModel().selectionChanged.connect(self.update_selection)
        self.view.customContextMenuRequested.connect(self.context_menu)
        self.view.doubleClicked.connect(lambda: self.with_selection(self.properties))
        self.view.collapsed.connect(lambda index: self.remember_expansion(index, collapsed=True))
        self.view.expanded.connect(lambda index: self.remember_expansion(index, collapsed=False))

        self.report_button.clicked.connect(self.export_report)
        run.clicked.connect(self.run_task)
        self.stop_button.clicked.connect(self.end_selected)
        refresh_button.clicked.connect(self.refresh.manual)
        self.auto.toggled.connect(self.set_auto)
        self.add_shortcut("Ctrl+N", self.run_task)
        self.add_shortcut("Ctrl+F", self.focus_search)
        self.add_shortcut("F5", self.refresh.manual)
        self.add_shortcut("Alt+Return", self.process_properties_shortcut)

        self.refresh.ready.connect(self.apply_snapshot)
        self.refresh.icons_ready.connect(self.apply_icons)
        self.refresh.failed.connect(self.refresh_failed)
        self.refresh.performance_ready.connect(self.apply_performance)
        self.refresh.performance_failed.connect(self.performance.record_failure)
        self.performance.monitoring_changed.connect(self.refresh.set_performance)
        self.set_auto(self.auto.isChecked())
        self.statusBar().showMessage("Reading processes…")
        self.redraw()
        self.performance.configure()
        self.refresh.request()

    def add_shortcut(self, shortcut: str, callback: Callable[[], None]) -> None:
        action = QAction(self)
        action.setShortcut(QKeySequence(shortcut))
        action.triggered.connect(callback)
        self.addAction(action)

    def export_report(self) -> None:
        ReportDialog(self).exec()

    def focus_search(self) -> None:
        self.navigation.setCurrentIndex(0)
        self.search.setFocus()
        self.search.selectAll()

    def process_properties_shortcut(self) -> None:
        if self.navigation.currentIndex() == 0:
            self.with_selection(self.properties)

    def update_columns_menu(self, columns: QMenu) -> None:
        for column, action in enumerate(columns.actions(), 1):
            with QSignalBlocker(action):
                action.setChecked(not self.view.isColumnHidden(column))

    def set_auto(self, enabled: bool) -> None:
        self.refresh.set_auto(enabled)
        self.statusBar().showMessage("Process auto-refresh on · 1.5 s interval" if enabled else "Process auto-refresh paused")

    def apply_icons(self, icons: dict[str, str]) -> None:
        self.model.icons = icons
        self.model.icon_cache.clear()

    def apply_snapshot(self, snapshot: Snapshot) -> None:
        self.rows = snapshot.rows
        self.collapsed.intersection_update(row.identity for row in self.rows)
        self.redraw()
        self.apply_resources(snapshot.resources)
        self.total_processes.display(len(snapshot.rows))
        self.performance.update_process_totals(len(snapshot.rows), sum(row.stat.threads for row in snapshot.rows))
        if self.statusBar().currentMessage().startswith(("Reading", "Refresh failed")):
            self.statusBar().showMessage(
                "Process auto-refresh on · 1.5 s interval" if self.auto.isChecked() else "Process auto-refresh paused"
            )

    def apply_resources(self, resources: Resources) -> None:
        self.cpu.display(resources.cpu)
        self.ram.display(resources.ram)
        self.swap.display(resources.swap, "No swap" if resources.swap_configured is False else "—")

    def apply_performance(self, sample: SystemSample) -> None:
        self.apply_resources(Resources.from_sample(sample))
        self.performance.record_sample(sample)

    def refresh_failed(self, error: str) -> None:
        self.statusBar().showMessage(f"Refresh failed. {error}")

    def redraw(self) -> None:
        view = self.view
        header = view.header()
        selection = self.selected()
        top_index = view.indexAt(QPoint(1, 1))
        top = self.model.process_at(top_index)
        top_offset = view.visualRect(top_index).top() if top is not None else 0
        vertical = view.verticalScrollBar().value()
        horizontal = view.horizontalScrollBar().value()
        tree = self.mode.currentIndex() == 1
        query = self.search.text().strip()
        with QSignalBlocker(view):
            view.setRootIsDecorated(tree)
            self.model.replace(
                self.rows, query, os.getuid() if self.mine.isChecked() else None,
                tree, header.sortIndicatorSection(), header.sortIndicatorOrder(),
            )
            if tree:
                view.expandAll()
                if not query:
                    for identity in self.collapsed:
                        index = self.model.index_for(identity)
                        if index.isValid():
                            view.collapse(index)
            selected_index = self.model.index_for(selection.identity if selection else None)
            if selected_index.isValid():
                flags = QItemSelectionModel.SelectionFlag
                view.selectionModel().setCurrentIndex(selected_index, flags.ClearAndSelect | flags.Rows)
            view.doItemsLayout()
            anchor = self.model.index_for(top.identity if top else None)
            if anchor.isValid() and view.visualRect(anchor).isValid():
                view.scrollTo(anchor, QAbstractItemView.ScrollHint.PositionAtTop)
                vertical = view.verticalScrollBar().value() - top_offset
            view.verticalScrollBar().setValue(vertical)
            view.horizontalScrollBar().setValue(horizontal)
        count = len(self.model.nodes)
        self.count.setText(f"{count:,} of {len(self.rows):,}" if count != len(self.rows) else f"{count:,}")
        self.update_selection()

    def remember_expansion(self, index: QModelIndex, *, collapsed: bool) -> None:
        row = self.model.process_at(index)
        if row is not None and not self.search.text().strip():
            if collapsed:
                self.collapsed.add(row.identity)
            else:
                self.collapsed.discard(row.identity)

    def selected(self) -> ProcessRow | None:
        rows = self.view.selectionModel().selectedRows()
        return self.model.process_at(rows[0]) if rows else None

    def update_selection(self) -> None:
        row = self.selected()
        self.stop_button.setEnabled(row is not None and self.can_manage(row))

    @staticmethod
    def can_manage(row: ProcessRow) -> bool:
        return management.protected_reason(row.stat) is None and row.stat.state not in {"Z", "X", "x"}

    def with_selection(self, action: Callable[[ProcessRow], None]) -> None:
        row = self.selected()
        if row is not None:
            action(row)

    def context_menu(self, position: QPoint) -> None:
        index = self.view.indexAt(position)
        row = self.model.process_at(index)
        if row is None:
            return
        self.view.setCurrentIndex(index)
        menu = QMenu(self)
        actions: dict[QAction, Callable[[ProcessRow], None]] = {}

        def add(label: str, callback: Callable[[ProcessRow], None], enabled: bool = True) -> None:
            action = menu.addAction(label)
            action.setEnabled(enabled)
            actions[action] = callback

        mutable = self.can_manage(row)
        add("Properties", self.properties)
        add("Open executable location", self.open_location, bool(row.executable))
        add("Copy PID", lambda target: QApplication.clipboard().setText(str(target.identity.pid)))
        add("Copy command line", lambda target: QApplication.clipboard().setText(target.command), bool(row.command))
        menu.addSeparator()
        add("Suspend…", self.suspend, mutable and row.stat.state != "T")
        add("Resume", self.resume, mutable and row.stat.state == "T")
        add("Change priority…", self.priority, mutable)
        add("Change CPU affinity…", self.affinity, mutable)
        menu.addSeparator()
        add("End task…", lambda target: self.terminate(target, force=False), mutable)
        add("End process tree…", lambda target: self.terminate_tree(target, force=False), mutable)
        add("Force kill…", lambda target: self.terminate(target, force=True), mutable)
        add("Force-kill process tree…", lambda target: self.terminate_tree(target, force=True), mutable)
        action = menu.exec(self.view.viewport().mapToGlobal(position))
        if action is not None:
            actions[action](row)
        menu.deleteLater()

    def do_action(self, action: Callable[[], None], success: str | None = None) -> None:
        try:
            action()
        except management.ProcessActionError as error:
            dialogs.message(self, "Process action failed", str(error), QMessageBox.Icon.Warning)
        else:
            if success:
                self.statusBar().showMessage(success, 4500)
        self.refresh.manual()

    def end_selected(self) -> None:
        self.with_selection(lambda row: self.terminate(row, force=False))

    def terminate(self, row: ProcessRow, *, force: bool) -> None:
        title = "Force kill" if force else "End task"
        sig = signal.SIGKILL if force else signal.SIGTERM
        details = (
            "Force killing can cause unsaved work to be lost."
            if force else "The process can handle or ignore the termination request."
        )
        if dialogs.confirm_signal(self, title, f"Send {sig.name} to {dialogs.process_label(row)}?\n\n{details}"):
            self.do_action(lambda: management.send_signal(row.identity, sig), f"{sig.name} sent to PID {row.identity.pid}")

    def terminate_tree(self, row: ProcessRow, *, force: bool) -> None:
        def action() -> None:
            plan = management.preview_tree(row.identity)
            if not dialogs.confirm_tree(self, row, plan, force):
                return
            sig = signal.SIGKILL if force else signal.SIGTERM
            failures = management.signal_tree(plan, sig)
            sent = len(plan.targets) - len(failures)
            if failures:
                dialogs.message(
                    self, "Process tree partially handled",
                    f"{sig.name} sent to {sent} of {len(plan.targets)} processes.",
                    QMessageBox.Icon.Warning, details="\n".join(failures),
                )
                return
            self.statusBar().showMessage(f"{sig.name} sent to {sent} processes", 4500)

        self.do_action(action)

    def suspend(self, row: ProcessRow) -> None:
        if dialogs.confirm_signal(
            self, "Suspend", f"Pause {dialogs.process_label(row)} with SIGSTOP?\n\nThe process will remain stopped until resumed.",
        ):
            self.do_action(lambda: management.send_signal(row.identity, signal.SIGSTOP), f"Suspended PID {row.identity.pid}")

    def resume(self, row: ProcessRow) -> None:
        self.do_action(lambda: management.send_signal(row.identity, signal.SIGCONT), f"Resumed PID {row.identity.pid}")

    def priority(self, row: ProcessRow) -> None:
        def action() -> None:
            stat = management.check_identity(row.identity, mutable=True)
            value = dialogs.choose_priority(self, row, stat.nice)
            if value is not None and value != stat.nice:
                management.set_priority(row.identity, value)
                self.statusBar().showMessage(f"Nice set to {value} for PID {row.identity.pid}", 4500)

        self.do_action(action)

    def affinity(self, row: ProcessRow) -> None:
        def action() -> None:
            current = management.get_affinity(row.identity)
            cpus = dialogs.choose_affinity(self, row, current)
            if cpus is not None and cpus != current:
                management.set_affinity(row.identity, cpus)
                self.statusBar().showMessage(f"CPU affinity updated for PID {row.identity.pid}", 4500)

        self.do_action(action)

    def properties(self, row: ProcessRow) -> None:
        def action() -> None:
            management.check_identity(row.identity)
            dialogs.show_properties(self, row)

        self.do_action(action)

    def open_location(self, row: ProcessRow) -> None:
        self.do_action(lambda: open_executable_location(row.identity))

    def run_task(self) -> None:
        command, accepted = QInputDialog.getText(
            self, "Run new task", "Executable and arguments", QLineEdit.EchoMode.Normal,
        )
        if accepted:
            self.do_action(lambda: start_task(command), "Task started")

    def closeEvent(self, event: QCloseEvent) -> None:
        self.refresh.stop()
        self.performance.save()
        self.settings.save(
            self, self.view, auto=self.auto.isChecked(), tree=self.mode.currentIndex() == 1,
            mine=self.mine.isChecked(),
        )
        super().closeEvent(event)
