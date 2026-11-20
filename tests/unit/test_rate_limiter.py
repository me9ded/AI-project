"""Tests for src/retrieval/rate_limiter.py (design spec section 8.3-8.4, test IDs R1-R7)."""

from src.retrieval.rate_limiter import RateLimiter
from tests.unit.fakes import FakeClock, FakeSleep


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
