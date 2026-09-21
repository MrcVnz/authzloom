from __future__ import annotations

import threading

from .errors import BudgetExhausted


class Budget:
    def __init__(self, max_requests: int):
        if max_requests < 1:
            raise ValueError("max_requests must be positive")
        self.max_requests = max_requests
        self._remaining = max_requests
        self._used = 0
        self._lock = threading.Lock()

    def consume(self) -> int:
        with self._lock:
            if self._remaining <= 0:
                raise BudgetExhausted("request budget exhausted")
            self._remaining -= 1
            self._used += 1
            return self._used

    @property
    def used(self) -> int:
        with self._lock:
            return self._used
