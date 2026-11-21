"""Performance pages and their in-memory monitoring history."""

import time

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QShowEvent
from PySide6.QtWidgets import (
    QButtonGroup, QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QStackedWidget, QVBoxLayout, QWidget,
)

from taskpup.graphs import History, HistoryGraph
from taskpup.metrics import SystemSample
from taskpup.model import memory_text
from taskpup.settings import Settings

HISTORY_OPTIONS = {30: "30 seconds", 60: "60 seconds", 300: "5 minutes", 900: "15 minutes"}
INTERVAL_OPTIONS = {1: "1 second", 2: "2 seconds", 5: "5 seconds"}
NAMES = ("CPU", "Memory", "Swap")
COLORS = ("#cb94ff", "#8fe7ac", "#92bdf4")
STATS = (
    ("Utilization", "Frequency", "Temperature", "Uptime", "Physical cores", "Logical CPUs", "Processes", "Threads"),
    ("Utilization", "Total", "Used", "Available", "Cached", "Buffers"),
    ("Utilization", "Total", "Used", "Available", "Swap in", "Swap out"),
)
UNAVAILABLE = "Unavailable"


def percent(value: float | None) -> str:
    return f"{value:.1f}%" if value is not None else UNAVAILABLE


def capacity(value: int | None) -> str:
    return memory_text(value) if value is not None else UNAVAILABLE


def counter(value: int | None) -> str:
    return f"{value:,}" if value is not None else UNAVAILABLE


def uptime(value: float | None) -> str:
    if value is None:
        return UNAVAILABLE
    days, remainder = divmod(int(value), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    return f"{days}d {hours:02d}h {minutes:02d}m" if days else f"{hours}h {minutes:02d}m"


class ResourceCard(QPushButton):
    def __init__(self, name: str, color: str) -> None:
        super().__init__()
        self.setObjectName("resourceCard")
        self.setCheckable(True)
        self.setAccessibleName(name)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(11, 8, 11, 9)
        layout.setSpacing(3)
        heading = QHBoxLayout()
        title = QLabel(name)
        title.setObjectName("resourceName")
        self.value = QLabel("—")
        self.value.setStyleSheet(f"color: {color}; font-weight: 700;")
        heading.addWidget(title)
        heading.addStretch()
        heading.addWidget(self.value)
        layout.addLayout(heading)
        self.info = QLabel()
        self.info.setObjectName("performanceMuted")
        layout.addWidget(self.info)
        self.graph = HistoryGraph(color, compact=True)
        self.graph.setFixedHeight(34)
        layout.addWidget(self.graph)
        for child in (title, self.value, self.info, self.graph):
            child.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def display(self, value: float | None, info: str) -> None:
        shown = percent(value) if value is not None else "—"
        self.value.setText(shown)
        self.info.setText(info)
        self.setAccessibleDescription(f"{percent(value)}. {info}")


class PerformanceDashboard(QWidget):
    monitoring_changed = Signal(int, bool)

    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings
        self.histories = tuple(History() for _ in NAMES)
        self.logical_histories: dict[int, History] = {}
        self.latest: SystemSample | None = None
        self.anchor: float | None = None
        self.processes: int | None = None
        self.threads: int | None = None
        self.logical_tiles: dict[int, tuple[QWidget, QLabel, HistoryGraph]] = {}
        self.resource = settings.choice("performance/resource", 0, (0, 1, 2))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(11)
        toolbar = QHBoxLayout()
        self.state = QLabel()
        self.state.setObjectName("performanceMuted")
        toolbar.addWidget(self.state)
        toolbar.addStretch()
        self.duration_box = self.make_choice("History", HISTORY_OPTIONS, 60)
        self.interval_box = self.make_choice("Sample interval", INTERVAL_OPTIONS, 1, key="interval")
        toolbar.addWidget(QLabel("History"))
        toolbar.addWidget(self.duration_box)
        toolbar.addWidget(QLabel("Sample every"))
        toolbar.addWidget(self.interval_box)
        self.pause = QPushButton()
        self.pause.setCheckable(True)
        self.pause.setChecked(settings.option("performance/paused", False))
        self.pause.setMinimumWidth(80)
        toolbar.addWidget(self.pause)
        layout.addLayout(toolbar)

        body = QHBoxLayout()
        body.setSpacing(12)
        sidebar = QWidget()
        sidebar.setFixedWidth(190)
        resources = QVBoxLayout(sidebar)
        resources.setContentsMargins(0, 0, 0, 0)
        resources.setSpacing(8)
        group = QButtonGroup(self)
        self.cards = [ResourceCard(name, color) for name, color in zip(NAMES, COLORS, strict=True)]
        for index, card in enumerate(self.cards):
            group.addButton(card, index)
            resources.addWidget(card)
        self.cards[self.resource].setChecked(True)
        resources.addStretch()
        body.addWidget(sidebar)

        self.details = QStackedWidget()
        self.plots: list[HistoryGraph] = []
        self.subtitles: list[QLabel] = []
        self.statistics: list[dict[str, QLabel]] = []
        self.logical_mode = QPushButton("Per logical CPU")
        self.logical_mode.setCheckable(True)
        self.logical_mode.setChecked(settings.option("performance/logical", False))
        self.cpu_charts = QStackedWidget()
        self.logical_area = QScrollArea()
        self.logical_area.setWidgetResizable(True)
        self.logical_area.setFrameShape(QFrame.Shape.NoFrame)
        self.logical_area.setMinimumHeight(105)
        self.logical_area.setAccessibleName("Logical CPU history graphs")
        self.logical_canvas = QWidget()
        self.logical_grid = QGridLayout(self.logical_canvas)
        self.logical_grid.setContentsMargins(0, 0, 0, 0)
        self.logical_grid.setSpacing(6)
        self.logical_area.setWidget(self.logical_canvas)
        self.logical_scale = QLabel()
        self.logical_scale.setObjectName("performanceMuted")
        for index, name in enumerate(NAMES):
            self.details.addWidget(self.make_detail(index, name))
        self.details.setCurrentIndex(self.resource)
        body.addWidget(self.details, 1)
        layout.addLayout(body, 1)

        group.idClicked.connect(self.select_resource)
        self.duration_box.currentIndexChanged.connect(self.update_charts)
        self.interval_box.currentIndexChanged.connect(self.configure)
        self.pause.toggled.connect(self.configure)
        self.logical_mode.toggled.connect(self.update_charts)
        self.show_state("Paused" if self.pause.isChecked() else "Waiting for samples")
        self.update_charts()

    def make_choice(self, name: str, options: dict[int, str], default: int, *, key: str = "duration") -> QComboBox:
        combo = QComboBox()
        combo.setAccessibleName(name)
        value = self.settings.choice(f"performance/{key}", default, tuple(options))
        for seconds, label in options.items():
            combo.addItem(label, seconds)
        combo.setCurrentIndex(combo.findData(value))
        return combo

    @property
    def duration(self) -> int:
        return tuple(HISTORY_OPTIONS)[self.duration_box.currentIndex()]

    @property
    def interval(self) -> int:
        return tuple(INTERVAL_OPTIONS)[self.interval_box.currentIndex()]

    def make_detail(self, index: int, name: str) -> QWidget:
        panel = QFrame()
        panel.setObjectName("performancePanel")
        pane = QVBoxLayout(panel)
        pane.setContentsMargins(13, 10, 13, 11)
        pane.setSpacing(7)
        top = QHBoxLayout()
        title = QLabel(name)
        title.setObjectName("performanceTitle")
        top.addWidget(title)
        top.addStretch()
        if index == 0:
            top.addWidget(self.logical_mode)
        pane.addLayout(top)
        subtitle = QLabel()
        subtitle.setObjectName("performanceMuted")
        subtitle.setTextFormat(Qt.TextFormat.PlainText)
        self.subtitles.append(subtitle)
        pane.addWidget(subtitle)

        graph = HistoryGraph(COLORS[index])
        graph.setMinimumHeight(128)
        graph.setAccessibleName(f"{name} utilization history")
        self.plots.append(graph)
        if index == 0:
            self.cpu_charts.addWidget(graph)
            logical_page = QWidget()
            grid = QVBoxLayout(logical_page)
            grid.setContentsMargins(0, 0, 0, 0)
            grid.setSpacing(3)
            grid.addWidget(self.logical_scale)
            grid.addWidget(self.logical_area, 1)
            self.cpu_charts.addWidget(logical_page)
            pane.addWidget(self.cpu_charts, 1)
        else:
            pane.addWidget(graph, 1)

        stats = QGridLayout()
        stats.setVerticalSpacing(6)
        stats.setHorizontalSpacing(10)
        labels: dict[str, QLabel] = {}
        for position, key in enumerate(STATS[index]):
            name_label = QLabel(key)
            name_label.setObjectName("performanceMuted")
            value = QLabel(UNAVAILABLE)
            value.setObjectName("performanceValue")
            row, column = divmod(position, 4)
            stats.addWidget(name_label, 2 * row, column)
            stats.addWidget(value, 2 * row + 1, column)
            stats.setColumnStretch(column, 1)
            labels[key] = value
        self.statistics.append(labels)
        if index == 0:
            for key in ("Processes", "Threads"):
                labels[key].setToolTip("From the most recent process-table scan")
        if index == 1:
            labels["Used"].setToolTip("Total physical memory minus available memory")
            for key in ("Cached", "Buffers"):
                labels[key].setToolTip("Informational Linux figures. These are not added to used memory.")
        pane.addLayout(stats)
        return panel

    def show_state(self, state: str) -> None:
        self.state.setText(state)
        self.pause.setText("Resume" if self.pause.isChecked() else "Pause")
        self.pause.setAccessibleName(f"{self.pause.text()} performance monitoring")

    def configure(self, *_: object) -> None:
        paused = self.pause.isChecked()
        if paused and self.state.text() != "Paused":
            self.mark_gap(time.monotonic())
        self.show_state("Paused" if paused else "Waiting for samples" if self.latest is None else "Live")
        self.monitoring_changed.emit(self.interval * 1000, not paused)

    def save(self) -> None:
        self.settings.save_performance(
            duration=self.duration, interval=self.interval, paused=self.pause.isChecked(),
            resource=self.resource, logical=self.logical_mode.isChecked(),
        )

    def select_resource(self, resource: int) -> None:
        self.resource = resource
        self.details.setCurrentIndex(resource)
        self.update_charts()

    def mark_gap(self, timestamp: float) -> None:
        for history in (*self.histories, *self.logical_histories.values()):
            history.append(timestamp, None)

    def record_failure(self, error: str) -> None:
        if self.pause.isChecked():
            return
        self.anchor = time.monotonic()
        self.mark_gap(self.anchor)
        self.latest = None
        self.show_state("Sample unavailable")
        self.state.setToolTip(error)
        if self.isVisible():
            self.update_charts()

    def record_sample(self, sample: SystemSample) -> None:
        if self.pause.isChecked():
            return
        self.latest = sample
        self.anchor = sample.timestamp
        values = (
            sample.cpu_percent,
            sample.memory.percent if sample.memory is not None else None,
            sample.swap.percent if sample.swap is not None else None,
        )
        for history, value in zip(self.histories, values, strict=True):
            history.append(sample.timestamp, value)
        if sample.logical_percent:
            for cpu in self.logical_histories.keys() - sample.logical_percent.keys():
                del self.logical_histories[cpu]
            for cpu, value in sample.logical_percent.items():
                if cpu not in self.logical_histories:
                    self.logical_histories[cpu] = History()
                self.logical_histories[cpu].append(sample.timestamp, value)
        else:
            for history in self.logical_histories.values():
                history.append(sample.timestamp, None)
        if self.state.text() != "Live":
            self.show_state("Live")
            self.state.setToolTip("")
        if self.isVisible():
            self.update_charts()

    def update_process_totals(self, processes: int, threads: int) -> None:
        self.processes, self.threads = processes, threads
        labels = self.statistics[0]
        labels["Processes"].setText(counter(processes))
        labels["Threads"].setText(counter(threads))

    def update_charts(self, *_: object) -> None:
        sample = self.latest
        memory = sample.memory if sample is not None else None
        swap = sample.swap if sample is not None else None
        model = (sample.cpu_model if sample is not None else None) or "CPU model unavailable"
        swap_info = "No swap configured" if swap is not None and not swap.total else (
            f"{capacity(swap.used)} / {capacity(swap.total)}" if swap is not None else "Swap data unavailable"
        )
        cards = (
            (sample.cpu_percent if sample is not None else None, f"{sample.logical_cores} logical CPUs" if sample and sample.logical_cores is not None else "CPU topology unavailable"),
            (memory.percent, f"{capacity(memory.used)} / {capacity(memory.total)}") if memory is not None else (None, "Memory data unavailable"),
            (swap.percent if swap is not None else None, swap_info),
        )
        for card, history, (value, info) in zip(self.cards, self.histories, cards, strict=True):
            card.display(value, info)
            card.graph.set_series(history.samples, self.anchor, self.duration)

        self.cpu_charts.setCurrentIndex(int(self.logical_mode.isChecked()))
        index = self.resource
        if index == 0 and self.logical_mode.isChecked():
            self.render_logical_cpus()
        else:
            self.plots[index].set_series(self.histories[index].samples, self.anchor, self.duration)
        if index == 0:
            self.subtitles[index].setText(model)
            values = (
                percent(cards[0][0]),
                f"{sample.frequency_mhz / 1000:.2f} GHz" if sample and sample.frequency_mhz is not None else UNAVAILABLE,
                f"{sample.temperature_c:.1f} °C" if sample and sample.temperature_c is not None else UNAVAILABLE,
                uptime(sample.uptime_s if sample else None),
                counter(sample.physical_cores if sample else None), counter(sample.logical_cores if sample else None),
                counter(self.processes), counter(self.threads),
            )
        elif index == 1:
            self.subtitles[index].setText(f"{capacity(memory.total)} physical memory" if memory else "Memory data unavailable")
            values = (percent(cards[1][0]), *(capacity(value) for value in (
                (memory.total, memory.used, memory.available, memory.cached, memory.buffers) if memory else (None,) * 5
            )))
        else:
            self.subtitles[index].setText(swap_info)
            values = (
                percent(cards[2][0]),
                *(capacity(value) for value in ((swap.total, swap.used, swap.available) if swap else (None,) * 3)),
                *(f"{capacity(round(rate))}/s" if rate is not None else UNAVAILABLE
                  for rate in ((swap.in_per_second, swap.out_per_second) if swap else (None,) * 2)),
            )
        for label, value in zip(self.statistics[index].values(), values, strict=True):
            label.setText(value)

    def render_logical_cpus(self) -> None:
        self.logical_scale.setText(
            f"0–100% utilization · Last {HISTORY_OPTIONS[self.duration]}"
            if self.logical_histories else "Logical CPU readings unavailable"
        )
        if self.logical_tiles.keys() != self.logical_histories.keys():
            for cpu in self.logical_tiles.keys() - self.logical_histories.keys():
                tile, _, _ = self.logical_tiles.pop(cpu)
                self.logical_grid.removeWidget(tile)
                tile.deleteLater()
            count = len(self.logical_histories)
            columns = min(4, count)
            for position, cpu in enumerate(sorted(self.logical_histories)):
                if cpu not in self.logical_tiles:
                    tile = QFrame()
                    tile.setObjectName("logicalCpu")
                    area = QVBoxLayout(tile)
                    area.setContentsMargins(6, 3, 6, 4)
                    area.setSpacing(2)
                    label = QLabel()
                    label.setObjectName("performanceMuted")
                    graph = HistoryGraph(COLORS[0], compact=True)
                    graph.setMinimumHeight(40)
                    graph.setAccessibleName(f"CPU {cpu} utilization history")
                    area.addWidget(label)
                    area.addWidget(graph, 1)
                    self.logical_tiles[cpu] = tile, label, graph
                self.logical_grid.addWidget(self.logical_tiles[cpu][0], *divmod(position, columns))
        readings = self.latest.logical_percent if self.latest else {}
        for cpu, (_, label, graph) in self.logical_tiles.items():
            value = readings.get(cpu)
            label.setText(f"CPU {cpu}  {value:.0f}%" if value is not None else f"CPU {cpu}  —")
            graph.set_series(self.logical_histories[cpu].samples, self.anchor, self.duration)

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        self.update_charts()
