"""Live checks against the real OSV.dev, NVD and CISA KEV APIs (design spec 9.10, L1-L2).

Skipped by default. Run them with:

    python -m pytest -m live

Each test starts with an empty cache in a temporary folder, so it really calls the
APIs. Without an NVD_API_KEY in .env, NVD allows 5 requests per 30 seconds, so these
tests take about a minute. Answers can change over time as new advisories appear;
the checks only rely on facts that should stay true.
"""

import pytest
import requests

from scripts.warm_cache import DEMO_INPUTS
from src.retrieval import build_service, load_env
from src.retrieval.version_matcher import parse_version

pytestmark = pytest.mark.live

LOG4J_CORE = "org.apache.logging.log4j:log4j-core"
DEMO_CVES = {"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"}


@pytest.fixture
def live_service(tmp_path):
    env = {**load_env(), "CVE_CACHE_PATH": str(tmp_path / "live.sqlite3")}
    return build_service(requests.Session(), env)


# L1: the Log4Shell demo against the real APIs.
def test_log4shell_demo_against_the_real_apis(live_service):
    result = live_service.retrieve(DEMO_INPUTS["Log4Shell log line"])

    records = {record.id: record for record in result.records if record.package_name == LOG4J_CORE}
    assert DEMO_CVES <= set(records)
    assert all(records[cve].affected is True for cve in DEMO_CVES)
    log4shell = records["CVE-2021-44228"]
    assert log4shell.cvss_score == 10.0
    assert log4shell.severity == "CRITICAL"
    assert log4shell.in_kev is True
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in log4shell.sources
    upgrade = result.recommended_upgrades[LOG4J_CORE]
    assert parse_version(upgrade, "Maven") >= parse_version("2.17.1", "Maven")
    assert result.incomplete is False, result.warnings


# L2: the pip-audit screenshot demo (jinja2 2.10) against the real APIs.
def test_jinja2_demo_against_the_real_apis(live_service):
    result = live_service.retrieve(DEMO_INPUTS["pip-audit screenshot"])

    assert result.records
    assert all(record.affected is True for record in result.records)
    # At least one CVE; a future GitHub-only advisory (no CVE) would be fine too.
    assert any(record.id.startswith("CVE-") for record in result.records)
    assert "jinja2" in result.recommended_upgrades
    assert result.incomplete is False, result.warnings
