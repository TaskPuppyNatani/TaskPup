"""Small, reusable history and graph widgets for performance readings."""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import deque
from collections.abc import Sequence
import math

from PySide6.QtCore import QEvent, QLineF, QRectF, Qt
from PySide6.QtGui import QColor, QMouseEvent, QPaintEvent, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QToolTip, QWidget


Sample = tuple[float, float | None]


def _finite_number(value: float, name: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(f"{name} must be a finite number") from error
    if not math.isfinite(result):
        raise ValueError(f"{name} must be a finite number")
    return result


class History:
    """A bounded, timestamped history with explicit gaps for missing readings."""

    MAX_SECONDS = 900
    MAX_SAMPLES = 1024

    def __init__(self) -> None:
        # Allow for timer jitter and pause markers within the 15-minute window.
        self._samples: deque[Sample] = deque(maxlen=self.MAX_SAMPLES)

    @property
    def samples(self) -> tuple[Sample, ...]:
        """Return an immutable snapshot suitable for ``HistoryGraph.set_series``."""
        return tuple(self._samples)

    def append(self, timestamp: float, value: float | None) -> None:
        timestamp = _finite_number(timestamp, "timestamp")
        if self._samples and timestamp <= self._samples[-1][0]:
            raise ValueError("timestamp must be greater than the previous timestamp")
        if value is not None:
            value = _finite_number(value, "value")

        self._samples.append((timestamp, value))
        cutoff = timestamp - self.MAX_SECONDS
        while self._samples and self._samples[0][0] < cutoff:
            self._samples.popleft()


class HistoryGraph(QWidget):
    """A lightweight QPainter graph for timestamped performance samples."""

    def __init__(
        self,
        color: str,
        *,
        compact: bool = False,
        maximum: float | None = 100.0,
        unit: str = "%",
        fill: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.compact = compact
        self.maximum = None if maximum is None else _finite_number(maximum, "maximum")
        if self.maximum is not None and self.maximum <= 0:
            raise ValueError("maximum must be greater than zero or None")
        self.unit = unit
        self.fill = fill
        self._color = QColor(color)
        if not self._color.isValid():
            self._color = self.palette().color(self.foregroundRole())
        self._samples: tuple[Sample, ...] = ()
        self._now: float | None = None
        self._duration = 60
        self.setMouseTracking(True)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, False)

    def set_series(
        self,
        samples: Sequence[tuple[float, float | None]],
        now: float | None,
        duration: int,
    ) -> None:
        """Set visible history and repaint; timestamps must be strictly ordered."""
        if isinstance(duration, bool) or not isinstance(duration, int) or duration <= 0:
            raise ValueError("duration must be a positive integer number of seconds")
        if now is not None:
            now = _finite_number(now, "now")

        if now is None and samples:
            now = samples[-1][0]
        self._now = now
        self._duration = duration

        if now is None:
            self._samples = ()
        else:
            first = bisect_left(samples, now - duration, key=lambda sample: sample[0])
            last = bisect_right(samples, now, key=lambda sample: sample[0])
            self._samples = tuple(samples[first:last])
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.fillRect(self.rect(), self.palette().color(self.backgroundRole()))

        plot = self._plot_rect()
        if plot.width() <= 1.0 or plot.height() <= 1.0:
            painter.end()
            return

        value_maximum = self._value_maximum()
        self._draw_axes(painter, plot)
        self._draw_series(painter, plot, value_maximum)
        if not self.compact and not any(value is not None for _, value in self._samples):
            painter.setPen(self.palette().color(self.foregroundRole()))
            painter.drawText(plot, Qt.AlignmentFlag.AlignCenter, "No readings in this interval")
        painter.end()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        plot = self._plot_rect()
        if self._now is None or plot.width() <= 0 or not plot.contains(event.position()):
            self.setToolTip("")
            QToolTip.hideText()
            return
        fraction = min(1.0, max(0.0, (event.position().x() - plot.left()) / plot.width()))
        target = self._now - self._duration + fraction * self._duration
        sample = next((sample for sample in reversed(self._samples) if sample[0] <= target), None)
        if sample is None:
            self.setToolTip("")
            QToolTip.hideText()
            return
        age = max(0.0, self._now - sample[0])
        reading = f"{sample[1]:.1f}{self.unit}" if sample[1] is not None else "Unavailable"
        self.setToolTip(f"{reading} · {age:.1f}s ago")
        QToolTip.showText(event.globalPosition().toPoint(), self.toolTip(), self)

    def leaveEvent(self, event: QEvent) -> None:
        self.setToolTip("")
        QToolTip.hideText()
        super().leaveEvent(event)

    def _plot_rect(self) -> QRectF:
        if self.compact:
            return QRectF(self.rect()).adjusted(1.0, 1.0, -1.0, -1.0)
        metrics = self.fontMetrics()
        labels = self._y_labels()
        left = max(metrics.horizontalAdvance(label) for label in labels) + 10
        return QRectF(self.rect()).adjusted(float(left), metrics.height() / 2 + 2, -5.0, -metrics.height() - 7.0)

    def _value_maximum(self) -> float:
        if self.maximum is not None:
            return self.maximum
        values = [value for _, value in self._samples if value is not None]
        return max(0.0, max(values, default=0.0)) or 1.0

    def _y_labels(self) -> tuple[str, str, str]:
        maximum = self._value_maximum()
        return (f"{maximum:g}{self.unit}", f"{maximum / 2:g}{self.unit}", f"0{self.unit}")

    def _draw_axes(self, painter: QPainter, plot: QRectF) -> None:
        grid = self.palette().color(self.foregroundRole())
        grid.setAlpha(24 if self.compact else 42)
        labels = self.palette().color(self.foregroundRole())
        labels.setAlpha(175)
        painter.setPen(grid)
        for fraction in (0.0, 0.5, 1.0):
            y = plot.bottom() - fraction * plot.height()
            painter.drawLine(QLineF(plot.left(), y, plot.right(), y))
        for fraction in (0.0, 0.25, 0.5, 0.75, 1.0):
            x = plot.left() + fraction * plot.width()
            painter.drawLine(QLineF(x, plot.top(), x, plot.bottom()))

        if self.compact:
            return
        painter.setPen(labels)
        font_height = painter.fontMetrics().height()
        axis_left = 2.0
        for fraction, text in zip((1.0, 0.5, 0.0), self._y_labels()):
            y = plot.bottom() - fraction * plot.height() - font_height / 2
            painter.drawText(QRectF(axis_left, y, plot.left() - axis_left - 4.0, font_height),
                             Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, text)
        painter.drawText(QRectF(plot.left(), plot.bottom() + 3.0, plot.width() / 2, font_height),
                         Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop, f"{self._duration}s ago")
        painter.drawText(QRectF(plot.right() - 45.0, plot.bottom() + 3.0, 45.0, font_height),
                         Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop, "Now")

    def _draw_series(self, painter: QPainter, plot: QRectF, maximum: float) -> None:
        if self._now is None or not self._samples:
            return
        start = self._now - self._duration
        painter.save()
        painter.setClipRect(plot)
        fill = QColor(self._color)
        fill.setAlpha(28)
        pen = QPen(self._color)
        pen.setWidthF(1.6 if not self.compact else 1.25)
        painter.setPen(pen)
        segments: list[list[tuple[float, float]]] = []
        current: list[tuple[float, float]] = []
        for timestamp, value in self._samples:
            if value is None:
                if current:
                    segments.append(current)
                    current = []
                continue
            x = plot.left() + (timestamp - start) / self._duration * plot.width()
            y = plot.bottom() - min(max(value, 0.0), maximum) / maximum * plot.height()
            current.append((x, y))
        if current:
            segments.append(current)

        for points in segments:
            path = QPainterPath()
            path.moveTo(*points[0])
            for point in points[1:]:
                path.lineTo(*point)
            painter.drawPath(path)
            if len(points) > 1 and self.fill:
                area = QPainterPath(path)
                area.lineTo(points[-1][0], plot.bottom())
                area.lineTo(points[0][0], plot.bottom())
                area.closeSubpath()
                painter.fillPath(area, fill)
            elif len(points) == 1:
                painter.drawPoint(path.currentPosition())
        painter.restore()

