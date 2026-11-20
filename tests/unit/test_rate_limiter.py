"""Tests for src/retrieval/rate_limiter.py (design spec section 8.3-8.4, test IDs R1-R7)."""

import pytest
import requests

from src.retrieval.rate_limiter import RateLimiter, RetrievalError, with_retries
from tests.unit.fakes import FakeClock, FakeResponse, FakeSession, FakeSleep


def make_limiter(max_calls=5, window_seconds=30, start=0.0):
    clock = FakeClock(start)
    sleep = FakeSleep(clock)  # sleeping moves the fake clock forward
    return RateLimiter(max_calls, window_seconds, clock=clock, sleep=sleep), clock, sleep


# ---------------------------------------------------------------------------
# RateLimiter: sliding window (NVD: 5 per 30 s without a key, 50 with one).
# ---------------------------------------------------------------------------

# R1: calls up to the limit go straight through.
def test_calls_within_limit_do_not_sleep():
    limiter, _, sleep = make_limiter(max_calls=5)

    for _ in range(5):
        limiter.acquire()

    assert sleep.calls == []


# R2: one call too many waits until the oldest call leaves the window.
def test_call_over_limit_sleeps_until_window_frees_up():
    limiter, clock, sleep = make_limiter(max_calls=5, window_seconds=30)
    for _ in range(5):
        limiter.acquire()

    limiter.acquire()

    assert sleep.calls == [30]
    assert clock() == 30


# R3: once the window has passed, the next call does not wait.
def test_call_after_window_expired_does_not_sleep():
    limiter, clock, sleep = make_limiter(max_calls=5, window_seconds=30)
    for _ in range(5):
        limiter.acquire()

    clock.advance(31)
    limiter.acquire()

    assert sleep.calls == []


def test_window_slides_with_each_call():
    limiter, clock, sleep = make_limiter(max_calls=2, window_seconds=30)
    limiter.acquire()        # t=0
    clock.advance(10)
    limiter.acquire()        # t=10
    clock.advance(5)

    limiter.acquire()        # t=15: must wait until the t=0 call expires at t=30

    assert sleep.calls == [15]
    assert clock() == 30


# ---------------------------------------------------------------------------
# with_retries: exponential backoff 1, 2, 4 s on 429 / 5xx / connection errors.
# ---------------------------------------------------------------------------

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def run_with_retries(responses):
    session = FakeSession(responses)
    sleep = FakeSleep()
    result = with_retries(lambda: session.get(URL, timeout=10), sleep=sleep)
    return result, session, sleep


# R4: temporary server errors are retried; the first good response is returned.
def test_retries_server_errors_then_returns_success():
    ok = FakeResponse(200, {"totalResults": 1})

    result, session, sleep = run_with_retries([FakeResponse(503), FakeResponse(503), ok])

    assert result is ok
    assert len(session.calls) == 3
    assert sleep.calls == [1, 2]


# R5: still failing after 3 retries -> RetrievalError, with the cause kept.
def test_gives_up_after_three_retries():
    session = FakeSession([requests.ConnectionError("offline")] * 4)
    sleep = FakeSleep()

    with pytest.raises(RetrievalError) as error:
        with_retries(lambda: session.get(URL, timeout=10), sleep=sleep)

    assert len(session.calls) == 4
    assert sleep.calls == [1, 2, 4]
    assert isinstance(error.value.__cause__, requests.ConnectionError)


def test_timeouts_are_retried():
    ok = FakeResponse(200)

    result, _, sleep = run_with_retries([requests.Timeout("slow"), ok])

    assert result is ok
    assert sleep.calls == [1]


# R6: other 4xx errors will not get better by retrying.
def test_client_error_is_not_retried():
    session = FakeSession([FakeResponse(404)])
    sleep = FakeSleep()

    with pytest.raises(RetrievalError):
        with_retries(lambda: session.get(URL, timeout=10), sleep=sleep)

    assert len(session.calls) == 1
    assert sleep.calls == []


# R7: 429 Too Many Requests is retried.
def test_too_many_requests_is_retried():
    ok = FakeResponse(200)

    result, session, sleep = run_with_retries([FakeResponse(429), ok])

    assert result is ok
    assert len(session.calls) == 2
    assert sleep.calls == [1]


def test_success_on_first_try_does_not_sleep():
    ok = FakeResponse(200)

    result, session, sleep = run_with_retries([ok])

    assert result is ok
    assert sleep.calls == []
