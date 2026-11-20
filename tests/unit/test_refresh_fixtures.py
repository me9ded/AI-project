"""Tests for the trimming rules in scripts/refresh_fixtures.py (see tests/fixtures/t2/README.md)."""

from scripts.refresh_fixtures import shorten, trim_kev_catalog, trim_nvd_response, trim_osv_vuln


def test_shorten_keeps_short_text_and_cuts_long_text():
    assert shorten("short", limit=10) == "short"
    assert shorten("a" * 20, limit=10) == "a" * 10 + " …"


def make_osv_vuln():
    return {
        "id": "GHSA-test",
        "aliases": ["CVE-2021-0001"],
        "summary": "Example",
        "details": "x" * 500,
        "modified": "2026-01-01T00:00:00Z",
        "affected": [
            {"package": {"ecosystem": "Maven", "name": "g:core"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}],
             "versions": ["0.9"], "database_specific": {"source": "big"}},
            {"package": {"ecosystem": "Maven", "name": "g:core"}, "ranges": [], "versions": []},
            {"package": {"ecosystem": "Maven", "name": "other:a"}, "ranges": [], "versions": []},
            {"package": {"ecosystem": "Maven", "name": "other:b"}, "ranges": [], "versions": []},
        ],
        "references": [{"url": f"https://example.com/{n}"} for n in range(10)],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-502"], "github_reviewed": True},
    }


def test_trim_osv_vuln_keeps_all_entries_for_the_package_plus_one_other():
    trimmed = trim_osv_vuln(make_osv_vuln(), "G:CORE")

    names = [entry["package"]["name"] for entry in trimmed["affected"]]
    assert names == ["g:core", "g:core", "other:a"]
    assert set(trimmed["affected"][0]) == {"package", "ranges", "versions"}


def test_trim_osv_vuln_shortens_text_and_drops_unused_fields():
    trimmed = trim_osv_vuln(make_osv_vuln(), "g:core")

    assert len(trimmed["details"]) <= 302
    assert len(trimmed["references"]) == 3
    assert trimmed["database_specific"] == {"severity": "HIGH", "cwe_ids": ["CWE-502"]}
    assert trimmed["severity"] == [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}]
    assert "modified" not in trimmed


def test_trim_nvd_response_keeps_scoring_fields_and_drops_configurations():
    response = {
        "totalResults": 1,
        "vulnerabilities": [{"cve": {
            "id": "CVE-2021-0001",
            "descriptions": [{"lang": "en", "value": "y" * 500}],
            "metrics": {"cvssMetricV31": []},
            "weaknesses": [],
            "references": [{"url": f"https://example.com/{n}"} for n in range(10)],
            "configurations": [{"nodes": []}],
        }}],
    }

    cve = trim_nvd_response(response)["vulnerabilities"][0]["cve"]

    assert "configurations" not in cve
    assert len(cve["references"]) == 5
    assert len(cve["descriptions"][0]["value"]) <= 302
    assert cve["metrics"] == {"cvssMetricV31": []}


def test_trim_kev_catalog_keeps_wanted_cves_plus_a_few_others():
    catalog = {
        "title": "KEV", "catalogVersion": "1", "dateReleased": "today", "count": 6,
        "vulnerabilities": [
            {"cveID": f"CVE-2020-000{n}", "shortDescription": "s" * 300, "notes": ""} for n in range(5)
        ] + [{"cveID": "CVE-2021-44228", "shortDescription": "log4shell", "notes": ""}],
    }

    trimmed = trim_kev_catalog(catalog, wanted={"CVE-2021-44228"}, extra=2)

    ids = [entry["cveID"] for entry in trimmed["vulnerabilities"]]
    assert ids == ["CVE-2021-44228", "CVE-2020-0000", "CVE-2020-0001"]
    assert trimmed["count"] == 3
    assert len(trimmed["vulnerabilities"][1]["shortDescription"]) <= 202
