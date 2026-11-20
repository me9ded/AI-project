"""Tests for src/retrieval/cache.py (design spec section 8.1-8.2, test IDs C1-C8)."""

from src.retrieval.cache import SqliteCache
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
