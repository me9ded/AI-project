"""Tests for src/retrieval/nvd_client.py (design spec section 5, test IDs N1-N13)."""

import pytest
import requests

from src.retrieval.cache import SqliteCache
from src.retrieval.rate_limiter import RetrievalError
from src.retrieval.nvd_client import NvdClient
from tests.unit.fakes import FakeClock, FakeResponse, FakeSession, FakeSleep, load_fixture

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class FakeLimiter:
    """Counts acquire() calls instead of rate limiting."""

    def __init__(self):
        self.acquired = 0

    def acquire(self):
        self.acquired += 1


def make_client(tmp_path, responses, api_key=None, clock=None):
    session = FakeSession(responses)
    limiter = FakeLimiter()
    cache = SqliteCache(tmp_path / "cache.sqlite3", clock=clock or FakeClock())
    client = NvdClient(session, cache, limiter, api_key=api_key, sleep=FakeSleep())
    return client, session, limiter


def log4shell_response():
    return FakeResponse(200, load_fixture("nvd_CVE-2021-44228.json"))


# N1: with an API key, it is sent in the apiKey header.
def test_api_key_is_sent_in_header(tmp_path):
    client, session, _ = make_client(tmp_path, [log4shell_response()], api_key="secret-key")

    client.get_cve("CVE-2021-44228")

    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == NVD_URL
    assert call["params"] == {"cveId": "CVE-2021-44228"}
    assert call["headers"] == {"apiKey": "secret-key"}
    assert call["timeout"] == 10


# N2: without a key, no apiKey header at all.
def test_no_api_key_header_without_key(tmp_path):
    client, session, _ = make_client(tmp_path, [log4shell_response()])

    client.get_cve("CVE-2021-44228")

    assert "apiKey" not in session.calls[0].get("headers", {})


# N3: score, CWEs and the English summary from the real Log4Shell record.
def test_parses_log4shell_record(tmp_path):
    client, _, _ = make_client(tmp_path, [log4shell_response()])

    cve, is_stale = client.get_cve("CVE-2021-44228")

    assert cve.id == "CVE-2021-44228"
    assert cve.cvss_score == 10.0
    assert "CWE-502" in cve.cwes
    assert cve.summary.startswith("Apache Log4j2")
    assert is_stale is False


# N12: the fixture also has a non-CVSS "ssvcV203" metric; it must not break scoring.
def test_non_cvss_metrics_are_ignored(tmp_path):
    response = load_fixture("nvd_CVE-2021-44228.json")
    assert "ssvcV203" in response["vulnerabilities"][0]["cve"]["metrics"]
    client, _, _ = make_client(tmp_path, [FakeResponse(200, response)])

    cve, _ = client.get_cve("CVE-2021-44228")

    assert cve.cvss_score == 10.0


# N8: an unknown CVE (HTTP 200, totalResults 0) is "not found", not an error.
def test_unknown_cve_returns_none(tmp_path):
    client, _, _ = make_client(tmp_path, [FakeResponse(200, load_fixture("nvd_not_found.json"))])

    cve, is_stale = client.get_cve("CVE-2021-99999999")

    assert cve is None
    assert is_stale is False


# Cache: a repeat lookup makes no request and does not use up the rate limit.
def test_repeat_lookup_uses_cache_and_skips_the_limiter(tmp_path):
    client, session, limiter = make_client(tmp_path, [log4shell_response()])

    client.get_cve("CVE-2021-44228")
    cve, _ = client.get_cve("CVE-2021-44228")

    assert len(session.calls) == 1
    assert limiter.acquired == 1
    assert cve.cvss_score == 10.0


# ---------------------------------------------------------------------------
# Scores and CWEs from hand-made records
# ---------------------------------------------------------------------------

def metric(score, metric_type="Primary"):
    return {"type": metric_type, "cvssData": {"baseScore": score}}


def nvd_record(metrics=None, weaknesses=None):
    cve = {
        "id": "CVE-2026-0001",
        "descriptions": [{"lang": "es", "value": "Descripción"}, {"lang": "en", "value": "Description"}],
        "metrics": metrics or {},
        "weaknesses": weaknesses or [],
    }
    return FakeResponse(200, {"totalResults": 1, "vulnerabilities": [{"cve": cve}]})


def score_for(tmp_path, metrics):
    client, _, _ = make_client(tmp_path, [nvd_record(metrics=metrics)])
    cve, _ = client.get_cve("CVE-2026-0001")
    return cve.cvss_score


# N4: fall back to older CVSS versions when newer ones are missing.
def test_falls_back_to_v30_then_v2(tmp_path):
    assert score_for(tmp_path / "a", {"cvssMetricV30": [metric(7.5)], "cvssMetricV2": [metric(5.0)]}) == 7.5
    assert score_for(tmp_path / "b", {"cvssMetricV2": [metric(5.0)]}) == 5.0


# N13: CVSS v4.0 comes after v3.1 but before v3.0 and v2.
def test_cvss_v40_order(tmp_path):
    assert score_for(tmp_path / "a", {"cvssMetricV40": [metric(8.7)]}) == 8.7
    assert score_for(tmp_path / "b", {"cvssMetricV40": [metric(8.7)], "cvssMetricV30": [metric(7.5)]}) == 8.7
    assert score_for(tmp_path / "c", {"cvssMetricV31": [metric(9.8)], "cvssMetricV40": [metric(8.7)]}) == 9.8


# N5: NVD's own (Primary) score wins over a Secondary (CNA) score, whatever the order.
def test_primary_score_preferred_over_secondary(tmp_path):
    metrics = {"cvssMetricV31": [metric(6.1, "Secondary"), metric(7.2, "Primary")]}

    assert score_for(tmp_path, metrics) == 7.2


def test_secondary_score_used_when_no_primary(tmp_path):
    assert score_for(tmp_path, {"cvssMetricV31": [metric(6.1, "Secondary")]}) == 6.1


# N6: no CVSS metrics at all (NVD has not scored it yet) -> None, severity becomes PENDING later.
def test_no_metrics_gives_no_score(tmp_path):
    assert score_for(tmp_path, {}) is None


# N7: NVD placeholders are not real weaknesses; duplicates are listed once.
def test_cwe_placeholders_removed_and_duplicates_merged(tmp_path):
    weaknesses = [
        {"description": [{"lang": "en", "value": "NVD-CWE-noinfo"}, {"lang": "en", "value": "CWE-79"}]},
        {"description": [{"lang": "en", "value": "CWE-79"}, {"lang": "en", "value": "NVD-CWE-Other"}]},
    ]
    client, _, _ = make_client(tmp_path, [nvd_record(weaknesses=weaknesses)])

    cve, _ = client.get_cve("CVE-2026-0001")

    assert cve.cwes == ["CWE-79"]


def test_english_description_chosen_when_not_first(tmp_path):
    client, _, _ = make_client(tmp_path, [nvd_record()])

    cve, _ = client.get_cve("CVE-2026-0001")

    assert cve.summary == "Description"


# ---------------------------------------------------------------------------
# Rate limit and failures
# ---------------------------------------------------------------------------

ONE_DAY = 24 * 60 * 60


# N9: every attempt, retries included, counts against NVD's limit.
def test_every_attempt_goes_through_the_limiter(tmp_path):
    client, session, limiter = make_client(tmp_path, [FakeResponse(503), log4shell_response()])

    client.get_cve("CVE-2021-44228")

    assert len(session.calls) == 2
    assert limiter.acquired == 2


# N10: a body that is not JSON is a failed request (so the stale fallback still applies).
def test_bad_json_raises_retrieval_error(tmp_path):
    client, _, _ = make_client(tmp_path, [FakeResponse(200, ValueError("Expecting value"))])

    with pytest.raises(RetrievalError):
        client.get_cve("CVE-2021-44228")


def test_falls_back_to_stale_cache_when_nvd_is_down(tmp_path):
    clock = FakeClock()
    offline = [requests.ConnectionError("offline")] * 4
    client, _, _ = make_client(tmp_path, [log4shell_response(), *offline], clock=clock)
    client.get_cve("CVE-2021-44228")
    clock.advance(ONE_DAY * 2)

    cve, is_stale = client.get_cve("CVE-2021-44228")

    assert cve.cvss_score == 10.0
    assert is_stale is True


# N11: NVD's docs don't say which status means "rate limited", and 403 also means a
# bad API key, so 403 is reported once (status kept) instead of being retried.
def test_forbidden_is_not_retried_and_keeps_its_status(tmp_path):
    client, session, _ = make_client(tmp_path, [FakeResponse(403)], api_key="wrong-key")

    with pytest.raises(RetrievalError) as error:
        client.get_cve("CVE-2021-44228")

    assert error.value.status_code == 403
    assert len(session.calls) == 1
