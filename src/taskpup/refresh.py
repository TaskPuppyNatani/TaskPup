"""Run one refresh at a time and publish its result from the GUI thread."""

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Event

from PySide6.QtCore import QObject, QTimer, Signal, Slot

from taskpup.platform import desktop_icons
from taskpup.processes import Sampler, Snapshot


class RefreshController(QObject):
    ready = Signal(object)
    icons_ready = Signal(object)
    failed = Signal(str)

    def __init__(self, parent: QObject, sample: Callable[[Event], Snapshot] | None = None) -> None:
        super().__init__(parent)
        self.sample = sample if sample is not None else Sampler().sample
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="taskpup-sampler")
        self.stop_requested = Event()
        self.future: Future[tuple[Snapshot, dict[str, str] | None]] | None = None
        self.load_icons = True
        self.pending = False

        self.interval = QTimer(self)
        self.interval.setInterval(1500)
        self.interval.timeout.connect(self.request)
        self.poll = QTimer(self)
        self.poll.setInterval(35)
        self.poll.timeout.connect(self.collect)

    @Slot(bool)
    def set_auto(self, enabled: bool) -> None:
        if enabled:
            self.interval.start()
        else:
            self.interval.stop()

    @Slot()
    def manual(self) -> None:
        if self.future is not None:
            self.pending = True
        self.request()

    @Slot()
    def request(self) -> None:
        if self.future is None and not self.stop_requested.is_set():
            self.future = self.executor.submit(self.collect_sample, self.load_icons)
            self.poll.start()

    def collect_sample(self, load_icons: bool) -> tuple[Snapshot, dict[str, str] | None]:
        icons = desktop_icons() if load_icons else None
        return self.sample(self.stop_requested), icons

    @Slot()
    def collect(self) -> None:
        if self.future is None or not self.future.done():
            return
        future, self.future = self.future, None
        self.poll.stop()
        try:
            snapshot, icons = future.result()
        except Exception as error:
            self.failed.emit(str(error))
        else:
            if icons is not None:
                self.load_icons = False
                self.icons_ready.emit(icons)
            self.ready.emit(snapshot)
        if self.pending:
            self.pending = False
            self.request()

    def stop(self) -> None:
        self.stop_requested.set()
        self.interval.stop()
        self.poll.stop()
        self.executor.shutdown(wait=False, cancel_futures=True)
