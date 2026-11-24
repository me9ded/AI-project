"""Rate limiting, retries and the shared retrieval error (design spec section 8.3-8.4)."""

import threading
import time
from collections import deque

import requests

# Failures that are worth trying again: the network or the server, not our request.
_RETRYABLE_EXCEPTIONS = (requests.ConnectionError, requests.Timeout)


class RetrievalError(Exception):
    """An external API could not be reached or answered with an error.

    `status_code` is the HTTP status when the API answered (e.g. 404), or None
    when it could not be reached at all.
    """

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class RateLimiter:
    """Allow at most `max_calls` calls in any `window_seconds` sliding window.

    NVD allows 5 requests per 30 s without an API key and 50 with one.
    Safe to share between threads (FastAPI runs requests on worker threads).
    The clock and sleep are passed in so tests never really wait.
    """

    def __init__(self, max_calls: int, window_seconds: float, clock=time.monotonic, sleep=time.sleep):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.clock = clock
        self.sleep = sleep
        self._recent_calls = deque()  # timestamps of calls still inside the window
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Wait (if needed) until another call is allowed, then record it."""
        with self._lock:  # one thread at a time, so two can't take the last slot
            self._forget_old_calls()
            while len(self._recent_calls) >= self.max_calls:
                # Loop, not if: a coarse clock can make us wake a moment too early.
                oldest = self._recent_calls[0]
                self.sleep(oldest + self.window_seconds - self.clock())
                self._forget_old_calls()
            self._recent_calls.append(self.clock())

    def _forget_old_calls(self) -> None:
        now = self.clock()
        while self._recent_calls and now - self._recent_calls[0] >= self.window_seconds:
            self._recent_calls.popleft()


def with_retries(call, sleep=time.sleep, retries: int = 3, base_delay: float = 1.0):
    """Run `call()` (an HTTP request) and return its response, retrying when it may help.

    Retried: connection errors, timeouts, HTTP 429 and HTTP 5xx, waiting 1, 2, 4 s.
    Any other 4xx, or still failing after `retries` retries -> RetrievalError.
    """
    for attempt in range(retries + 1):
        try:
            response = call()
        except _RETRYABLE_EXCEPTIONS as error:
            last_problem = error
        else:
            if response.status_code < 400:
                return response
            last_problem = RetrievalError(f"HTTP {response.status_code}", response.status_code)
            if not _is_retryable_status(response.status_code):
                raise last_problem

        if attempt < retries:
            sleep(base_delay * 2 ** attempt)

    status_code = getattr(last_problem, "status_code", None)  # None for network errors
    raise RetrievalError(f"Gave up after {retries} retries: {last_problem}", status_code) from last_problem


def _is_retryable_status(status_code: int) -> bool:
    return status_code == 429 or status_code >= 500


def read_json(response, source: str):
    """The response body as JSON. A body that is not JSON counts as a failed request,
    so cached_fetch can still fall back to stale data."""
    try:
        return response.json()
    except ValueError as error:  # requests' JSONDecodeError is a ValueError
        raise RetrievalError(f"{source} sent a body that is not JSON: {error}") from error
