"""Persist window and process-view preferences through Qt."""

from PySide6.QtCore import QByteArray, QSettings, Qt
from PySide6.QtWidgets import QMainWindow, QTreeView

from taskpup.model import COLUMNS


class Settings:
    def __init__(self, store: QSettings | None = None) -> None:
        self.store = store if store is not None else QSettings()

    def option(self, key: str, default: bool) -> bool:
        return bool(self.store.value(key, default, type=bool))

    def restore(self, window: QMainWindow, view: QTreeView) -> None:
        geometry = self.store.value("window/geometry")
        if isinstance(geometry, QByteArray):
            window.restoreGeometry(geometry)
        header = self.store.value("view/header")
        if isinstance(header, QByteArray):
            view.header().restoreState(header)
        else:
            view.header().setSortIndicator(4, Qt.SortOrder.DescendingOrder)
        view.setColumnHidden(0, False)
        if view.header().sortIndicatorSection() not in range(len(COLUMNS)):
            view.header().setSortIndicator(4, Qt.SortOrder.DescendingOrder)

    def save(self, window: QMainWindow, view: QTreeView, *, auto: bool, tree: bool, mine: bool) -> None:
        self.store.setValue("window/geometry", window.saveGeometry())
        self.store.setValue("view/header", view.header().saveState())
        self.store.setValue("view/auto", auto)
        self.store.setValue("view/tree", tree)
        self.store.setValue("view/mine", mine)
        self.store.sync()
