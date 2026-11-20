"""Test doubles shared by the Task 2 unit tests.

They replace the network (requests.Session), the clock and time.sleep, so unit tests
run fast, never touch the internet and never really wait.
"""

import json
from pathlib import Path

import requests


class FakeResponse:
    """A minimal stand-in for requests.Response."""

    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}", response=self)


class FakeSession:
    """A stand-in for requests.Session.

    Give it a list of responses. Each get/post call returns the next one in order.
    If the next item is an exception, it is raised instead. Every call is recorded
    in `calls` so tests can check the URL, body and headers that were sent.
    """

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def get(self, url, **kwargs):
        return self._next_response("GET", url, kwargs)

    def post(self, url, **kwargs):
        return self._next_response("POST", url, kwargs)

    def _next_response(self, method, url, kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self.responses:
            raise AssertionError(f"Unexpected {method} {url}: no fake response queued")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeClock:
    """A clock that only moves when the test (or FakeSleep) moves it."""

    def __init__(self, start=0.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeSleep:
    """Records every sleep request instead of waiting.

    If a FakeClock is given, sleeping also moves that clock forward, so code that
    sleeps and then checks the time sees the time pass.
    """

    def __init__(self, clock=None):
        self.calls = []
        self.clock = clock

    def __call__(self, seconds):
        self.calls.append(seconds)
        if self.clock is not None:
            self.clock.advance(seconds)


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "t2"


def load_fixture(name):
    """Load a saved API response from tests/fixtures/t2/."""
    with open(FIXTURES_DIR / name, encoding="utf-8") as file:
        return json.load(file)
