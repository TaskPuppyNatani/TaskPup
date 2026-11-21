"""Schedule process and performance samples on one background worker."""

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from threading import Event

from PySide6.QtCore import QObject, QTimer, Signal, Slot

from taskpup.metrics import SystemSample, SystemSampler
from taskpup.platform import desktop_icons
from taskpup.processes import Resources, Sampler, Snapshot


@dataclass(slots=True)
class RefreshResult:
    epoch: int
    snapshot: Snapshot | None = None
    system: SystemSample | None = None
    icons: dict[str, str] | None = None
    process_error: str | None = None
    performance_error: str | None = None


class RefreshController(QObject):
    ready = Signal(object)
    icons_ready = Signal(object)
    failed = Signal(str)
    performance_ready = Signal(object)
    performance_failed = Signal(str)

    def __init__(
        self, parent: QObject, sample: Callable[[Event], Snapshot] | None = None,
        system: SystemSampler | None = None,
    ) -> None:
        super().__init__(parent)
        self.sample = sample
        self.system = system if system is not None else SystemSampler()
        self.processes = Sampler(self.system)
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="taskpup-sampler")
        self.stop_requested = Event()
        self.future: Future[RefreshResult] | None = None
        self.load_icons = True
        self.process_pending = self.performance_pending = False
        self.process_active = self.performance_active = False
        self.monitoring = False
        self.epoch = 0
        # Used only on the worker. Epoch changes invalidate old CPU and swap intervals.
        self.worker_epoch = 0
        self.latest: SystemSample | None = None

        self.interval = QTimer(self)
        self.interval.setInterval(1500)
        self.interval.timeout.connect(self.request)
        self.performance_interval = QTimer(self)
        self.performance_interval.timeout.connect(self.request_performance)
        self.poll = QTimer(self)
        self.poll.setInterval(35)
        self.poll.timeout.connect(self.collect)

    @Slot(bool)
    def set_auto(self, enabled: bool) -> None:
        if enabled and not self.stop_requested.is_set():
            self.interval.start()
        else:
            self.interval.stop()

    @Slot(int, bool)
    def set_performance(self, milliseconds: int, enabled: bool) -> None:
        if self.stop_requested.is_set():
            return
        self.performance_interval.setInterval(milliseconds)
        if enabled == self.monitoring:
            return
        self.epoch += 1
        self.monitoring = enabled
        self.performance_pending = enabled
        if enabled:
            self.performance_interval.start()
            self.submit()
        else:
            self.performance_interval.stop()

    @Slot()
    def manual(self) -> None:
        self.process_pending = True
        self.submit()

    @Slot()
    def request(self) -> None:
        if not self.process_active:
            self.manual()

    @Slot()
    def request_performance(self) -> None:
        if self.monitoring and not self.performance_active:
            self.performance_pending = True
            self.submit()

    def submit(self) -> None:
        if self.future is not None or self.stop_requested.is_set():
            return
        process, performance = self.process_pending, self.performance_pending
        if not (process or performance):
            return
        self.process_pending = self.performance_pending = False
        self.process_active, self.performance_active = process, performance
        self.future = self.executor.submit(
            self.collect_sample, process, performance, self.load_icons and process, self.monitoring, self.epoch,
        )
        self.poll.start()

    def collect_sample(
        self, process: bool, performance: bool, load_icons: bool, monitoring: bool, epoch: int,
    ) -> RefreshResult:
        result = RefreshResult(epoch)
        if epoch != self.worker_epoch:
            self.system.reset()
            self.worker_epoch = epoch
            self.latest = None
        if performance or (process and self.sample is None and (self.latest is None or not monitoring)):
            try:
                self.latest = self.system.sample(detailed=performance)
            except Exception as error:
                if performance:
                    result.performance_error = str(error)
            else:
                if performance:
                    result.system = self.latest
        if process and not self.stop_requested.is_set():
            try:
                if load_icons:
                    result.icons = desktop_icons()
                if self.sample is not None:
                    result.snapshot = self.sample(self.stop_requested)
                else:
                    resources = Resources.from_sample(self.latest) if self.latest is not None else Resources(None, None, None)
                    result.snapshot = self.processes.sample(self.stop_requested, resources)
            except Exception as error:
                result.process_error = str(error)
        return result

    @Slot()
    def collect(self) -> None:
        if self.future is None or not self.future.done() or self.stop_requested.is_set():
            return
        future, self.future = self.future, None
        self.process_active = self.performance_active = False
        self.poll.stop()
        result = future.result()
        if result.icons is not None:
            self.load_icons = False
            self.icons_ready.emit(result.icons)
        if result.snapshot is not None:
            self.ready.emit(result.snapshot)
        if result.process_error is not None:
            self.failed.emit(result.process_error)
        if result.epoch == self.epoch and self.monitoring:
            if result.system is not None:
                self.performance_ready.emit(result.system)
            elif result.performance_error is not None:
                self.performance_failed.emit(result.performance_error)
        self.submit()

    def stop(self) -> None:
        self.stop_requested.set()
        self.interval.stop()
        self.performance_interval.stop()
        self.poll.stop()
        self.executor.shutdown(wait=False, cancel_futures=True)
