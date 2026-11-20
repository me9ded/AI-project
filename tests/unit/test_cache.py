"""Tests for src/retrieval/cache.py (design spec section 8.1-8.2, test IDs C1-C8)."""

import pytest

from src.retrieval.cache import SqliteCache, cached_fetch
from src.retrieval.rate_limiter import RetrievalError
from tests.unit.fakes import FakeClock

ONE_DAY = 24 * 60 * 60
LOG4J_QUERY = {"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"]}]}


def make_cache(tmp_path, clock=None):
    return SqliteCache(tmp_path / "cache" / "retrieval.sqlite3", ttl_seconds=ONE_DAY, clock=clock or FakeClock())


# C1: what goes in comes back out.
def test_set_then_get_returns_the_value(tmp_path):
    cache = make_cache(tmp_path)

    cache.set("osv:query:Maven:log4j-core:2.14.1", LOG4J_QUERY)

    assert cache.get("osv:query:Maven:log4j-core:2.14.1") == LOG4J_QUERY


def test_set_replaces_an_existing_value(tmp_path):
    cache = make_cache(tmp_path)

    cache.set("kev:catalog", {"count": 1})
    cache.set("kev:catalog", {"count": 2})

    assert cache.get("kev:catalog") == {"count": 2}


# C2: a key that was never stored.
def test_get_missing_key_returns_none(tmp_path):
    cache = make_cache(tmp_path)

    assert cache.get("nvd:cve:CVE-0000-0000") is None
    assert cache.get_stale("nvd:cve:CVE-0000-0000") is None


# C3: after the TTL, get() treats the entry as expired but get_stale() still has it.
def test_entry_expires_after_ttl_but_stays_available_as_stale(tmp_path):
    clock = FakeClock(start=1_000.0)
    cache = make_cache(tmp_path, clock)
    cache.set("nvd:cve:CVE-2021-44228", {"score": 10.0})

    clock.advance(ONE_DAY - 1)
    assert cache.get("nvd:cve:CVE-2021-44228") == {"score": 10.0}

    clock.advance(1)  # exactly one TTL old -> expired
    assert cache.get("nvd:cve:CVE-2021-44228") is None
    assert cache.get_stale("nvd:cve:CVE-2021-44228") == {"score": 10.0}


# C4: the cache lives in a file, so a new SqliteCache on the same path sees old entries.
def test_entries_survive_reopening_the_file(tmp_path):
    clock = FakeClock()
    make_cache(tmp_path, clock).set("osv:vuln:GHSA-jfh8-c2jp-5v3q", {"id": "GHSA-jfh8-c2jp-5v3q"})

    reopened = make_cache(tmp_path, clock)

    assert reopened.get("osv:vuln:GHSA-jfh8-c2jp-5v3q") == {"id": "GHSA-jfh8-c2jp-5v3q"}


# ---------------------------------------------------------------------------
# cached_fetch(cache, key, fetch) -> (value, is_stale)   (design spec section 8.2)
# ---------------------------------------------------------------------------

class FakeFetch:
    """Counts calls; returns `value`, or raises `error` if one is given."""

    def __init__(self, value=None, error=None):
        self.value = value
        self.error = error
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.value


# C5: a fresh cache hit means no network call.
def test_cached_fetch_uses_fresh_cache_without_fetching(tmp_path):
    cache = make_cache(tmp_path)
    cache.set("kev:catalog", {"cves": ["CVE-2021-44228"]})
    fetch = FakeFetch(value={"cves": []})

    value, is_stale = cached_fetch(cache, "kev:catalog", fetch)

    assert value == {"cves": ["CVE-2021-44228"]}
    assert is_stale is False
    assert fetch.calls == 0


# C6: a miss fetches once and stores the result for next time.
def test_cached_fetch_fetches_and_stores_on_miss(tmp_path):
    cache = make_cache(tmp_path)
    fetch = FakeFetch(value=LOG4J_QUERY)

    value, is_stale = cached_fetch(cache, "osv:query:Maven:log4j-core:2.14.1", fetch)

    assert value == LOG4J_QUERY
    assert is_stale is False
    assert fetch.calls == 1
    assert cache.get("osv:query:Maven:log4j-core:2.14.1") == LOG4J_QUERY


def test_cached_fetch_refetches_when_entry_expired(tmp_path):
    clock = FakeClock()
    cache = make_cache(tmp_path, clock)
    cache.set("nvd:cve:CVE-2021-44228", {"score": 9.9})
    clock.advance(ONE_DAY)
    fetch = FakeFetch(value={"score": 10.0})

    value, is_stale = cached_fetch(cache, "nvd:cve:CVE-2021-44228", fetch)

    assert value == {"score": 10.0}
    assert is_stale is False
    assert fetch.calls == 1


# C7: the API is down but we have old data -> use it and say it is stale.
def test_cached_fetch_falls_back_to_stale_value_when_fetch_fails(tmp_path):
    clock = FakeClock()
    cache = make_cache(tmp_path, clock)
    cache.set("nvd:cve:CVE-2021-44228", {"score": 10.0})
    clock.advance(ONE_DAY * 3)
    fetch = FakeFetch(error=RetrievalError("NVD unavailable"))

    value, is_stale = cached_fetch(cache, "nvd:cve:CVE-2021-44228", fetch)

    assert value == {"score": 10.0}
    assert is_stale is True


# C8: the API is down and nothing is cached -> the error reaches the caller.
def test_cached_fetch_raises_when_fetch_fails_and_nothing_cached(tmp_path):
    cache = make_cache(tmp_path)
    fetch = FakeFetch(error=RetrievalError("NVD unavailable"))

    with pytest.raises(RetrievalError):
        cached_fetch(cache, "nvd:cve:CVE-2021-44228", fetch)
