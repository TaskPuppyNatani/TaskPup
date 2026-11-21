from __future__ import annotations

import pytest
from PySide6.QtGui import QImage
from PySide6.QtWidgets import QApplication

from taskpup.graphs import History, HistoryGraph, rate_text


def test_history_keeps_only_900_seconds_and_preserves_gaps() -> None:
    history = History()
    for timestamp in range(1001):
        history.append(timestamp, None if timestamp == 500 else float(timestamp))

    samples = history.samples
    assert samples[0] == (100.0, 100.0)
    assert samples[-1] == (1000.0, 1000.0)
    assert len(samples) == 901
    assert samples[400] == (500.0, None)


def test_history_has_hard_cap_when_samples_arrive_rapidly() -> None:
    history = History()
    for tick in range(2000):
        history.append(tick / 100, float(tick))

    assert len(history.samples) == History.MAX_SAMPLES


def test_history_rejects_invalid_or_non_monotonic_timestamps() -> None:
    history = History()
    history.append(10, 1.0)

    with pytest.raises(ValueError, match="greater than the previous"):
        history.append(10, 2.0)
    with pytest.raises(ValueError, match="greater than the previous"):
        history.append(9, 2.0)
    with pytest.raises(ValueError, match="finite"):
        history.append(float("nan"), 2.0)
    with pytest.raises(ValueError, match="finite"):
        history.append(11, float("inf"))


@pytest.mark.parametrize("compact", [False, True])
def test_history_graph_renders_series_with_missing_gap(qt_app: QApplication, compact: bool) -> None:
    graph = HistoryGraph("#45a7ff", compact=compact)
    graph.resize(180, 90)
    graph.set_series(((0, 10), (1, 25), (2, None), (3, 50)), now=3, duration=3)
    image = QImage(graph.size(), QImage.Format.Format_ARGB32)

    graph.render(image)

    assert not image.isNull()
    assert graph._samples[2] == (2.0, None)


def test_history_graph_uses_latest_sample_when_now_is_missing(qt_app: QApplication) -> None:
    graph = HistoryGraph("#45a7ff", compact=True)
    graph.set_series(((4, 10), (5, 20)), now=None, duration=5)

    assert graph._now == 5.0
    assert graph._y_labels() == ("100%", "50%", "0%")


def test_throughput_axes_scale_to_visible_samples_and_both_traces(qt_app: QApplication) -> None:
    graph = HistoryGraph("#cb94ff", maximum=None, unit="B/s", secondary_color="#8fe7ac")
    graph.set_series(((10, 2**30), (50, None), (80, 0)), now=80, duration=35,
                     secondary=((50, 1500), (80, 2000)))
    assert graph._value_maximum() == 2048
    assert graph._y_labels() == ("2.0 KiB/s", "1.0 KiB/s", "0 B/s")
    graph.set_series(((81, 0),), now=81, duration=30)
    assert graph._value_maximum() == 1
    assert not graph._secondary_samples
    assert rate_text(0) == "0 B/s" and rate_text(0.25) == "0.25 B/s"


def test_percentage_plot_places_high_values_above_low_values(qt_app: QApplication) -> None:
    graph = HistoryGraph("#ff00ff", fill=False)
    graph.resize(300, 160)
    graph.set_series(((0.1, 75), (0.9, 75)), now=1, duration=1)
    image = QImage(graph.size(), QImage.Format.Format_ARGB32)
    graph.render(image)
    plot = graph._plot_rect()
    x = round(plot.center().x())
    high = round(plot.bottom() - 0.75 * plot.height())
    low = round(plot.bottom() - 0.25 * plot.height())

    def purple_at(y: int) -> bool:
        return any(
            image.pixelColor(x, row).red() > 170 and image.pixelColor(x, row).blue() > 170
            and image.pixelColor(x, row).green() < 100
            for row in range(y - 2, y + 3)
        )

    assert graph._y_labels() == ("100%", "50%", "0%")
    assert high < low and purple_at(high) and not purple_at(low)

