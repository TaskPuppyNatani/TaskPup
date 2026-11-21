"""Shared detail layout for storage and network throughput."""

from html import escape

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QFrame, QGridLayout, QHeaderView, QLabel, QScrollArea,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from taskpup.graphs import History, HistoryGraph, rate_text
from taskpup.model import memory_text
from taskpup.network import InterfaceSample
from taskpup.storage import DiskSample, Filesystem

TransferSample = DiskSample | InterfaceSample
READ_COLOR = "#cb94ff"
WRITE_COLOR = "#8fe7ac"
UNAVAILABLE = "Unavailable"


def transfer_rates(sample: TransferSample | None) -> tuple[float | None, float | None]:
    if isinstance(sample, DiskSample):
        return sample.read_rate, sample.write_rate
    if isinstance(sample, InterfaceSample):
        return sample.receive_rate, sample.transmit_rate
    return None, None


def _capacity(value: int | None) -> str:
    return memory_text(value) if value is not None else UNAVAILABLE


def _percent(value: float | None) -> str:
    return f"{value:.1f}%" if value is not None else UNAVAILABLE


class TransferPage(QScrollArea):
    def __init__(self, *, storage: bool) -> None:
        super().__init__()
        self.storage = storage
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        panel = QFrame()
        panel.setObjectName("performancePanel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(13, 10, 13, 11)
        layout.setSpacing(8)
        self.title = QLabel()
        self.title.setObjectName("performanceTitle")
        self.title.setTextFormat(Qt.TextFormat.PlainText)
        self.title.setWordWrap(True)
        layout.addWidget(self.title)
        self.subtitle = QLabel()
        self.subtitle.setObjectName("performanceMuted")
        self.subtitle.setTextFormat(Qt.TextFormat.PlainText)
        self.subtitle.setWordWrap(True)
        layout.addWidget(self.subtitle)

        self.telemetry = QWidget()
        details = QVBoxLayout(self.telemetry)
        details.setContentsMargins(0, 0, 0, 0)
        details.setSpacing(8)
        self.plots: list[HistoryGraph] = []
        names = ("Read throughput", "Write throughput") if storage else ("Receive throughput", "Transmit throughput")
        for name, color in zip(names, (READ_COLOR, WRITE_COLOR), strict=True):
            heading = QLabel(name)
            heading.setObjectName("performanceValue")
            heading.setStyleSheet(f"color: {color};")
            details.addWidget(heading)
            plot = HistoryGraph(color, maximum=None, unit="B/s")
            plot.setMinimumHeight(115)
            plot.setAccessibleName(f"{name} history")
            details.addWidget(plot, 1)
            self.plots.append(plot)
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(4)
        fields = (
            ("Read", "Write", "Device active time", "Device capacity", "Bytes read", "Bytes written", "Temperature")
            if storage else
            ("Receive", "Transmit", "Connection", "Bytes received", "Bytes transmitted", "Local link speed")
        )
        self.values: dict[str, tuple[QLabel, QLabel]] = {}
        for index, name in enumerate(fields):
            row, column = divmod(index, 4 if storage else 3)
            label = QLabel(name)
            label.setWordWrap(True)
            label.setObjectName("performanceMuted")
            value = QLabel()
            value.setWordWrap(True)
            value.setObjectName("performanceValue")
            value.setAccessibleName(name)
            grid.addWidget(label, row * 2, column)
            grid.addWidget(value, row * 2 + 1, column)
            grid.setColumnStretch(column, 1)
            self.values[name] = label, value
        if storage:
            self.values["Device active time"][1].setToolTip("Time the device handled I/O during the last sample interval")
        else:
            self.values["Local link speed"][1].setToolTip("Link rate reported by Linux for this interface")
        details.addLayout(grid)
        self.footer = QLabel()
        self.footer.setObjectName("performanceMuted")
        self.footer.setWordWrap(True)
        details.addWidget(self.footer)
        layout.addWidget(self.telemetry, 1)
        self.mount_status = QLabel()
        self.mount_status.setObjectName("performanceMuted")
        self.mount_status.setWordWrap(True)
        self.mounts: QTableWidget | None = None
        self._filesystems: tuple[Filesystem, ...] | None = None
        if storage:
            self.mounts = QTableWidget(0, 6)
            self.mounts.setAccessibleName("Mounted filesystem capacity")
            self.mounts.setHorizontalHeaderLabels(("Mount point", "Type", "Total", "Used", "Available", "Used %"))
            self.mounts.verticalHeader().hide()
            self.mounts.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            self.mounts.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            self.mounts.setAlternatingRowColors(True)
            header = self.mounts.horizontalHeader()
            header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            layout.addWidget(self.mount_status)
            layout.addWidget(self.mounts)
        self.setWidget(panel)

    def display(
        self, metadata: TransferSample, sample: TransferSample | None, histories: tuple[History, History],
        anchor: float | None, duration: int,
    ) -> None:
        self.telemetry.show()
        self.mount_status.hide()
        if self.mounts is not None:
            self.mounts.hide()
        rates = tuple(rate_text(value) if value is not None else UNAVAILABLE for value in transfer_rates(sample))
        for plot, history in zip(self.plots, histories, strict=True):
            plot.set_series(history.samples, anchor, duration)
        if isinstance(metadata, DiskSample):
            label = metadata.label.removesuffix(f" ({metadata.name})")
            if label == f"{metadata.name} ({metadata.kind})":
                label = metadata.name
            self.title.setText(label)
            self.subtitle.setText(
                f"{metadata.name}  ·  {metadata.kind}" if label != metadata.name else f"{metadata.kind}  ·  Block device",
            )
            disk = sample if isinstance(sample, DiskSample) else None
            readings = (
                *rates, _percent(disk.activity if disk else None), _capacity(disk.capacity if disk else None),
                _capacity(disk.bytes_read if disk else None), _capacity(disk.bytes_written if disk else None),
                f"{disk.temperature_c:.1f} °C" if disk and disk.temperature_c is not None else UNAVAILABLE,
            )
            self._set_optional("Temperature", metadata.temperature_supported)
            self._set_optional("Device active time", metadata.activity_supported)
            self._set_optional("Device capacity", metadata.capacity is not None)
            self.footer.setText(
                "This device is temporarily unavailable." if disk is None else
                "Totals come from Linux block-device counters. See Mounted filesystems for space usage."
            )
        else:
            self.title.setText(metadata.name)
            self.subtitle.setText(f"{metadata.kind}  ·  Network interface")
            link = sample if isinstance(sample, InterfaceSample) else None
            readings = (
                *rates, link.status if link else UNAVAILABLE,
                _capacity(link.bytes_received if link else None), _capacity(link.bytes_transmitted if link else None),
                f"{link.speed_mbps:,} Mb/s" if link and link.speed_mbps is not None else UNAVAILABLE,
            )
            self._set_optional("Local link speed", metadata.speed_supported)
            self.footer.setText(
                "This interface is temporarily unavailable." if link is None else
                "Rates and totals reflect this interface. The local link speed is shown when the driver reports it."
            )
        for (_, label), value in zip(self.values.values(), readings, strict=True):
            label.setText(value)

    def _set_optional(self, name: str, supported: bool) -> None:
        label, value = self.values[name]
        label.setVisible(supported)
        value.setVisible(supported)

    def display_filesystems(self, filesystems: tuple[Filesystem, ...] | None) -> None:
        table = self.mounts
        assert table is not None
        self.title.setText("Mounted filesystems")
        self.subtitle.setText("Space usage on local filesystems")
        self.telemetry.hide()
        self.mount_status.setText(
            "Filesystem readings are unavailable." if filesystems is None else
            "Each row represents one filesystem, with a representative mount point."
            if filesystems else "No local mounted filesystems were discovered."
        )
        self.mount_status.show()
        table.setVisible(bool(filesystems))
        if not filesystems or self._filesystems == filesystems:
            return
        self._filesystems = filesystems
        table.setRowCount(len(filesystems))
        for row, fs in enumerate(filesystems):
            values = (fs.mountpoint, fs.fstype, _capacity(fs.total), _capacity(fs.used),
                      _capacity(fs.available), _percent(fs.percent))
            for col, value in enumerate(values):
                item = table.item(row, col)
                if item is None:
                    item = QTableWidgetItem()
                    table.setItem(row, col, item)
                item.setText(value)
                if col == 0:
                    item.setToolTip(f"<qt>{escape(value)}</qt>")
                elif col >= 2:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
