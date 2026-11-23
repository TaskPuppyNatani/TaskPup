"""Schedule process and performance samples on one background worker."""

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from threading import Event

from PySide6.QtCore import QObject, QTimer, Signal, Slot

from taskpup.metrics import SystemSample, SystemSampler
from taskpup.platform import desktop_icons
from taskpup.processes import Resources, Sampler, Snapshot
from taskpup.service_controls import ServiceAction, ServiceConfirmation, ServiceOperationResult, execute_service_action
from taskpup.services import ServiceIdentity, ServicesSnapshot, discover_services


@dataclass(slots=True)
class RefreshResult:
    epoch: int
    snapshot: Snapshot | None = None
    system: SystemSample | None = None
    icons: dict[str, str] | None = None
    process_error: str | None = None
    performance_error: str | None = None


@dataclass(slots=True)
class ServicesRefreshResult:
    generation: int
    snapshot: ServicesSnapshot | None = None
    error: str | None = None


def _default_service_executor(
    identity: ServiceIdentity,
    action: ServiceAction,
    stop: Event,
    high_risk_acknowledged: ServiceConfirmation | None,
) -> ServiceOperationResult:
    return execute_service_action(
        identity,
        action,
        stop,
        high_risk_acknowledged=high_risk_acknowledged,
    )


class RefreshController(QObject):
    ready = Signal(object)
    icons_ready = Signal(object)
    failed = Signal(str)
    performance_ready = Signal(object)
    performance_failed = Signal(str)
    services_ready = Signal(object)
    services_failed = Signal(str)
    service_action_started = Signal(object, str)
    service_action_finished = Signal(object)

    def __init__(
        self, parent: QObject, sample: Callable[[Event], Snapshot] | None = None,
        system: SystemSampler | None = None,
        services: Callable[[Event], ServicesSnapshot] | None = None,
        service_executor: Callable[[ServiceIdentity, ServiceAction, Event, ServiceConfirmation | None], ServiceOperationResult] | None = None,
    ) -> None:
        super().__init__(parent)
        self.sample = sample
        self.system = system if system is not None else SystemSampler()
        self.services_loader = services if services is not None else discover_services
        self.service_action_runner = service_executor if service_executor is not None else _default_service_executor
        self.processes = Sampler(self.system)
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="taskpup-sampler")
        self.services_executor: ThreadPoolExecutor | None = None
        self.service_action_executor: ThreadPoolExecutor | None = None
        self.stop_requested = Event()
        self.future: Future[RefreshResult] | None = None
        self.services_future: Future[ServicesRefreshResult] | None = None
        self.services_run_stop: Event | None = None
        self.service_action_future: Future[ServiceOperationResult] | None = None
        self.service_action_stop: Event | None = None
        self.service_action_target: tuple[ServiceIdentity, ServiceAction] | None = None
        self.load_icons = True
        self.process_pending = self.performance_pending = False
        self.process_active = self.performance_active = False
        self.services_pending = False
        self.services_generation = 0
        self.services_applied_generation = 0
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
    def request_services(self) -> None:
        if self.stop_requested.is_set():
            return
        self.services_generation += 1
        self.services_pending = True
        if self.services_run_stop is not None:
            self.services_run_stop.set()
        self.submit_services()

    def submit_services(self) -> None:
        if self.services_future is not None or not self.services_pending or self.stop_requested.is_set():
            return
        self.services_pending = False
        if self.services_executor is None:
            self.services_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="taskpup-services")
        generation = self.services_generation
        run_stop = Event()
        self.services_run_stop = run_stop
        self.services_future = self.services_executor.submit(self.collect_services_sample, generation, run_stop)
        self.poll.start()

    def collect_services_sample(self, generation: int, run_stop: Event) -> ServicesRefreshResult:
        if self.stop_requested.is_set() or run_stop.is_set():
            return ServicesRefreshResult(generation)
        try:
            snapshot = self.services_loader(run_stop)
        except Exception as error:
            return ServicesRefreshResult(generation, error=str(error))
        if self.stop_requested.is_set() or run_stop.is_set():
            return ServicesRefreshResult(generation)
        return ServicesRefreshResult(generation, snapshot=snapshot)

    def pending_service_action(self) -> tuple[ServiceIdentity, ServiceAction] | None:
        """Return the currently active (identity, action) after draining any already-completed future."""
        if self.service_action_future is not None and self.service_action_future.done():
            self.collect()
        if self.service_action_future is None or self.service_action_target is None:
            return None
        return self.service_action_target

    @Slot(object, str, object)
    def request_service_action(
        self,
        identity: ServiceIdentity,
        action: ServiceAction,
        high_risk_acknowledged: ServiceConfirmation | None = None,
    ) -> bool:
        if self.stop_requested.is_set() or self.service_action_future is not None:
            return False
        # Invalidate any pre-operation discovery refresh so stale state cannot overwrite post-action state.
        self.services_generation += 1
        self.services_pending = False
        if self.services_run_stop is not None:
            self.services_run_stop.set()
        if self.service_action_executor is None:
            self.service_action_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="taskpup-service-action")
        action_stop = Event()
        self.service_action_stop = action_stop
        self.service_action_target = (identity, action)
        self.service_action_future = self.service_action_executor.submit(
            self.run_service_action, identity, action, action_stop, high_risk_acknowledged,
        )
        self.poll.start()
        self.service_action_started.emit(identity, action)
        return True

    def run_service_action(
        self,
        identity: ServiceIdentity,
        action: ServiceAction,
        action_stop: Event,
        high_risk_acknowledged: ServiceConfirmation | None,
    ) -> ServiceOperationResult:
        if self.stop_requested.is_set() or action_stop.is_set():
            return ServiceOperationResult(
                identity,
                action,
                "cancelled",
                f"Cancelled {action} on {identity.unit} before dispatch.",
            )
        try:
            return self.service_action_runner(identity, action, action_stop, high_risk_acknowledged)
        except Exception as error:
            return ServiceOperationResult(
                identity=identity,
                action=action,
                outcome="failed",
                summary=f"Unexpected error while running {action} on {identity.unit}.",
                detail=str(error),
            )

    @Slot()
    def collect(self) -> None:
        if self.stop_requested.is_set():
            self.poll.stop()
            return
        if self.future is not None and self.future.done():
            future, self.future = self.future, None
            self.process_active = self.performance_active = False
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
        if not self.stop_requested.is_set() and self.services_future is not None and self.services_future.done():
            services_future, self.services_future = self.services_future, None
            self.services_run_stop = None
            services_result = services_future.result()
            if (
                not self.stop_requested.is_set()
                and services_result.generation == self.services_generation
                and services_result.generation > self.services_applied_generation
            ):
                if services_result.snapshot is not None:
                    self.services_applied_generation = services_result.generation
                    self.services_ready.emit(services_result.snapshot)
                elif services_result.error is not None:
                    self.services_applied_generation = services_result.generation
                    self.services_failed.emit(services_result.error)
            self.submit_services()
        if not self.stop_requested.is_set() and self.service_action_future is not None and self.service_action_future.done():
            action_future, self.service_action_future = self.service_action_future, None
            self.service_action_stop = None
            self.service_action_target = None
            action_result = action_future.result()
            if not self.stop_requested.is_set():
                self.service_action_finished.emit(action_result)
                if not self.stop_requested.is_set() and action_result.outcome not in {"cancelled", "interrupted"}:
                    self.request_services()
        if self.stop_requested.is_set() or (
            self.future is None and self.services_future is None and self.service_action_future is None
        ):
            self.poll.stop()

    def stop(self) -> None:
        self.stop_requested.set()
        if self.services_run_stop is not None:
            self.services_run_stop.set()
        if self.service_action_stop is not None:
            self.service_action_stop.set()
        self.services_pending = False
        self.service_action_target = None
        self.interval.stop()
        self.performance_interval.stop()
        self.poll.stop()
        self.executor.shutdown(wait=False, cancel_futures=True)
        if self.services_executor is not None:
            self.services_executor.shutdown(wait=False, cancel_futures=True)
        if self.service_action_executor is not None:
            self.service_action_executor.shutdown(wait=False, cancel_futures=True)
