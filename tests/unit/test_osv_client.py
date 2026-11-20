"""Tests for src/retrieval/osv_client.py (design spec section 5, test IDs O1-O9)."""

from src.retrieval.cache import SqliteCache
from src.retrieval.osv_client import OsvClient
from tests.unit.fakes import FakeClock, FakeResponse, FakeSession, FakeSleep, load_fixture

LOG4J_CORE = "org.apache.logging.log4j:log4j-core"
QUERY_URL = "https://api.osv.dev/v1/query"


def make_client(tmp_path, responses, clock=None):
    session = FakeSession(responses)
    cache = SqliteCache(tmp_path / "cache.sqlite3", clock=clock or FakeClock())
    client = OsvClient(session, cache, sleep=FakeSleep())
    return client, session, cache


# O1: the query body names the package, its ecosystem and the installed version.
def test_query_package_posts_name_ecosystem_and_version(tmp_path):
    client, session, _ = make_client(tmp_path, [FakeResponse(200, {"vulns": []})])

    client.query_package(LOG4J_CORE, "Maven", "2.14.1")

    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == QUERY_URL
    assert call["json"] == {"package": {"name": LOG4J_CORE, "ecosystem": "Maven"}, "version": "2.14.1"}
    assert call["timeout"] == 10


# O2: no version known (e.g. npm audit without a lockfile) -> leave it out.
def test_query_package_without_version_leaves_version_out(tmp_path):
    client, session, _ = make_client(tmp_path, [FakeResponse(200, {"vulns": []})])

    client.query_package("lodash", "npm", None)

    assert session.calls[0]["json"] == {"package": {"name": "lodash", "ecosystem": "npm"}}


# O3: returns the OSV vulns (raw dicts) and whether the data is stale.
def test_query_package_returns_vulns_from_osv(tmp_path):
    fixture = load_fixture("osv_query_log4j_core_2.14.1.json")
    client, _, _ = make_client(tmp_path, [FakeResponse(200, fixture)])

    vulns, is_stale = client.query_package(LOG4J_CORE, "Maven", "2.14.1")

    aliases = {alias for vuln in vulns for alias in vuln["aliases"]}
    assert len(vulns) == 8
    assert "CVE-2021-44228" in aliases
    assert is_stale is False


def test_query_package_with_no_vulns_returns_empty_list(tmp_path):
    client, _, _ = make_client(tmp_path, [FakeResponse(200, {})])  # OSV sends {} when nothing matches

    vulns, is_stale = client.query_package("requests", "PyPI", "2.32.3")

    assert vulns == []
    assert is_stale is False


# O5: the same query twice -> one HTTP call, the second comes from the cache.
def test_query_package_uses_cache_for_repeat_queries(tmp_path):
    fixture = load_fixture("osv_query_log4j_core_2.14.1.json")
    client, session, _ = make_client(tmp_path, [FakeResponse(200, fixture)])

    first, _ = client.query_package(LOG4J_CORE, "Maven", "2.14.1")
    second, is_stale = client.query_package(LOG4J_CORE, "Maven", "2.14.1")

    assert len(session.calls) == 1
    assert second == first
    assert is_stale is False


def test_different_versions_are_cached_separately(tmp_path):
    client, session, _ = make_client(
        tmp_path, [FakeResponse(200, {"vulns": []}), FakeResponse(200, {"vulns": []})]
    )

    client.query_package(LOG4J_CORE, "Maven", "2.14.1")
    client.query_package(LOG4J_CORE, "Maven", "2.17.1")

    assert len(session.calls) == 2


# O7: an advisory ID is looked up directly.
def test_get_vuln_fetches_advisory_by_id(tmp_path):
    fixture = load_fixture("osv_vuln_GHSA-jfh8-c2jp-5v3q.json")
    client, session, _ = make_client(tmp_path, [FakeResponse(200, fixture)])

    vuln, is_stale = client.get_vuln("GHSA-jfh8-c2jp-5v3q")

    assert session.calls[0]["method"] == "GET"
    assert session.calls[0]["url"] == "https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q"
    assert "CVE-2021-44228" in vuln["aliases"]
    assert is_stale is False


def test_get_vuln_uses_cache(tmp_path):
    fixture = load_fixture("osv_vuln_GHSA-jfh8-c2jp-5v3q.json")
    client, session, _ = make_client(tmp_path, [FakeResponse(200, fixture)])

    client.get_vuln("GHSA-jfh8-c2jp-5v3q")
    client.get_vuln("GHSA-jfh8-c2jp-5v3q")

    assert len(session.calls) == 1
