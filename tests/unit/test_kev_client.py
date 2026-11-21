"""Tests for src/retrieval/kev_client.py (design spec section 5, test IDs K1-K4)."""

from src.retrieval.cache import SqliteCache
from src.retrieval.kev_client import KevClient
from tests.unit.fakes import FakeClock, FakeResponse, FakeSession, FakeSleep, load_fixture

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def make_client(tmp_path, responses, clock=None):
    session = FakeSession(responses)
    cache = SqliteCache(tmp_path / "cache.sqlite3", clock=clock or FakeClock())
    return KevClient(session, cache, sleep=FakeSleep()), session


def kev_response():
    return FakeResponse(200, load_fixture("kev_excerpt.json"))


# K1: Log4Shell is in the catalog of actively exploited vulnerabilities.
def test_log4shell_is_exploited(tmp_path):
    client, session = make_client(tmp_path, [kev_response()])

    exploited, is_stale = client.is_exploited("CVE-2021-44228")

    assert exploited is True
    assert is_stale is False
    assert session.calls[0]["method"] == "GET"
    assert session.calls[0]["url"] == KEV_URL


# K2: a CVE that is not in the catalog.
def test_cve_not_in_catalog_is_not_exploited(tmp_path):
    client, _ = make_client(tmp_path, [kev_response()])

    exploited, _ = client.is_exploited("CVE-0000-0000")

    assert exploited is False


def test_lookup_ignores_case(tmp_path):
    client, _ = make_client(tmp_path, [kev_response()])

    exploited, _ = client.is_exploited("cve-2021-44228")

    assert exploited is True


# K3: the catalog is downloaded once and reused (it is refreshed once a day).
def test_catalog_downloaded_once_for_many_lookups(tmp_path):
    client, session = make_client(tmp_path, [kev_response()])

    for _ in range(10):
        client.is_exploited("CVE-2021-44228")

    assert len(session.calls) == 1


def test_catalog_downloaded_again_after_a_day(tmp_path):
    clock = FakeClock()
    client, session = make_client(tmp_path, [kev_response(), kev_response()], clock)
    client.is_exploited("CVE-2021-44228")

    clock.advance(24 * 60 * 60)
    client.is_exploited("CVE-2021-44228")

    assert len(session.calls) == 2
