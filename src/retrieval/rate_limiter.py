"""Rate limiting, retries and the shared retrieval error (design spec section 8.3-8.4).

with_retries() is added in the next step.
"""

import time
from collections import deque


class RetrievalError(Exception):
    """An external API could not be reached or answered with an error."""


class RateLimiter:
    """Allow at most `max_calls` calls in any `window_seconds` sliding window.

    NVD allows 5 requests per 30 s without an API key and 50 with one.
    The clock and sleep are passed in so tests never really wait.
    """

    def __init__(self, max_calls: int, window_seconds: float, clock=time.monotonic, sleep=time.sleep):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.clock = clock
        self.sleep = sleep
        self._recent_calls = deque()  # timestamps of calls still inside the window

    def acquire(self) -> None:
        """Wait (if needed) until another call is allowed, then record it."""
        self._forget_old_calls()
        if len(self._recent_calls) >= self.max_calls:
            oldest = self._recent_calls[0]
            self.sleep(oldest + self.window_seconds - self.clock())
            self._forget_old_calls()
        self._recent_calls.append(self.clock())

    def _forget_old_calls(self) -> None:
        now = self.clock()
        while self._recent_calls and now - self._recent_calls[0] >= self.window_seconds:
            self._recent_calls.popleft()


def with_retries(call, sleep=time.sleep, retries=3, base_delay=1.0):
    raise NotImplementedError
