from __future__ import annotations

import threading
import time
from typing import Any, Protocol


class Clock(Protocol):
    def monotonic(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...


# Windows Event.wait(timeout) rounds short timeouts up to the timer quantum (~15 ms).
# time.sleep uses the high-resolution timer, so 1 ms slices stay near 1 ms and bound cancel latency.
CANCEL_SLICE_SECONDS = 0.001


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)


class FakeClock:
    """Deterministic clock for CI. sleep() advances time without waiting."""

    def __init__(self, start: float = 0.0):
        self.t = start
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            self.sleeps.append(seconds)
            self.t += seconds

    def advance(self, seconds: float) -> None:
        self.t += seconds


class RateLimiter:
    """Pace request *start* times. Does not sleep after the last acquire."""

    def __init__(self, rate_per_second: float, clock: Clock | None = None):
        if rate_per_second <= 0:
            raise ValueError("rate must be positive")
        self.interval = 1.0 / rate_per_second
        self.clock: Clock = clock or SystemClock()
        self._lock = threading.Lock()
        self._next_start: float | None = None
        self.events: list[dict[str, Any]] = []

    def acquire(self, cancel: threading.Event | None = None) -> dict[str, Any]:
        with self._lock:
            now = self.clock.monotonic()
            scheduled = now if self._next_start is None else max(now, self._next_start)
            wait = scheduled - now
            self._next_start = scheduled + self.interval
        cancelled = self._wait(wait, cancel)
        start = self.clock.monotonic()
        event: dict[str, Any] = {"scheduled": scheduled, "start": start}
        if cancelled or (cancel is not None and cancel.is_set()):
            event["cancelled"] = True
        return event

    def _wait(self, seconds: float, cancel: threading.Event | None) -> bool:
        if seconds <= 0:
            return cancel is not None and cancel.is_set()
        if cancel is None or not isinstance(self.clock, SystemClock):
            self.clock.sleep(seconds)
            return cancel is not None and cancel.is_set()
        deadline = time.monotonic() + seconds
        while True:
            if cancel.is_set():
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(remaining if remaining < CANCEL_SLICE_SECONDS else CANCEL_SLICE_SECONDS)

    def complete(self, event: dict[str, Any]) -> dict[str, Any]:
        event["end"] = self.clock.monotonic()
        event["duration"] = event["end"] - event["start"]
        event["limiter_wait"] = max(0.0, event["start"] - event["scheduled"])
        with self._lock:
            self.events.append(event)
        return event

    def starts_in_window(self, start: float, window: float = 1.0) -> int:
        end = start + window
        return sum(1 for event in self.events if start <= event["start"] < end)
