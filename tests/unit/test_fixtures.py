"""Sanity checks on the saved API responses in tests/fixtures/t2/.

They make sure trimming kept the facts the client and service tests rely on,
and that our version matcher agrees with real OSV data for the Log4j demo.
"""

from src.retrieval.version_matcher import is_affected, lowest_fix
from tests.unit.fakes import load_fixture

LOG4J_CORE = "org.apache.logging.log4j:log4j-core"
LOG4J_CVES = {"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832"}


def package_entry(vuln, name, ecosystem):
    """All of a package's `affected` entries in one OSV vuln, merged into one.

    Real OSV data often splits a package into one entry per release branch
    (CVE-2021-44228 has three for log4j-core), so the ranges must be combined.
    """
    entries = [
        entry for entry in vuln["affected"]
        if entry["package"]["ecosystem"] == ecosystem and entry["package"]["name"].lower() == name.lower()
    ]
    return {
        "ranges": [r for entry in entries for r in entry.get("ranges", [])],
        "versions": [v for entry in entries for v in entry.get("versions", [])],
    }


def log4j_vulns():
    """The OSV vulns for log4j-core 2.14.1 that are one of the four demo CVEs."""
    vulns = load_fixture("osv_query_log4j_core_2.14.1.json")["vulns"]
    return [vuln for vuln in vulns if LOG4J_CVES & set(vuln.get("aliases", []))]


# --- OSV ------------------------------------------------------------------

def test_osv_log4j_splits_a_package_into_several_entries():
    """Documents the real-data shape the service must handle (spec 7.1)."""
    log4shell = next(v for v in log4j_vulns() if "CVE-2021-44228" in v["aliases"])
    log4j_core_entries = [a for a in log4shell["affected"] if a["package"]["name"] == LOG4J_CORE]

    assert len(log4j_core_entries) > 1


def test_osv_log4j_query_contains_all_four_demo_cves():
    vulns = load_fixture("osv_query_log4j_core_2.14.1.json")["vulns"]
    aliases = {alias for vuln in vulns for alias in vuln.get("aliases", [])}

    assert LOG4J_CVES <= aliases


def test_real_osv_data_marks_2_14_1_affected_and_fixed_in_2_17_1():
    vulns = log4j_vulns()
    entries = [package_entry(vuln, LOG4J_CORE, "Maven") for vuln in vulns]

    assert len(entries) == 4
    assert all(is_affected("2.14.1", entry, "Maven") for entry in entries)
    assert not any(is_affected("2.17.1", entry, "Maven") for entry in entries)
    assert lowest_fix("2.14.1", entries, "Maven") == "2.17.1"


def test_real_osv_data_needs_2_25_4_to_fix_all_eight_vulns():
    """Pins the answer spec test S3 relies on. The three 2026 CVEs are fixed only in
    2.25.4, so no lower version is safe. Update this after a fixture refresh."""
    vulns = load_fixture("osv_query_log4j_core_2.14.1.json")["vulns"]
    entries = [package_entry(vuln, LOG4J_CORE, "Maven") for vuln in vulns]

    assert len(entries) == 8
    assert all(is_affected("2.14.1", entry, "Maven") for entry in entries)
    assert lowest_fix("2.14.1", entries, "Maven") == "2.25.4"


def test_osv_vuln_lookup_links_ghsa_to_log4shell():
    vuln = load_fixture("osv_vuln_GHSA-jfh8-c2jp-5v3q.json")

    assert vuln["id"] == "GHSA-jfh8-c2jp-5v3q"
    assert "CVE-2021-44228" in vuln["aliases"]


def test_osv_jinja2_query_has_affected_pypi_vulns():
    vulns = load_fixture("osv_query_jinja2_2.10.json")["vulns"]

    assert vulns
    for vuln in vulns:
        assert is_affected("2.10", package_entry(vuln, "jinja2", "PyPI"), "PyPI")


# --- NVD ------------------------------------------------------------------

def test_nvd_log4shell_has_score_cwe_and_description():
    cve = load_fixture("nvd_CVE-2021-44228.json")["vulnerabilities"][0]["cve"]

    scores = [m["cvssData"]["baseScore"] for m in cve["metrics"]["cvssMetricV31"]]
    cwes = [d["value"] for w in cve["weaknesses"] for d in w["description"]]
    english = [d["value"] for d in cve["descriptions"] if d["lang"] == "en"]

    assert cve["id"] == "CVE-2021-44228"
    assert 10.0 in scores
    assert "CWE-502" in cwes
    assert english and english[0]


def test_nvd_not_found_has_no_results():
    response = load_fixture("nvd_not_found.json")

    assert response["totalResults"] == 0
    assert response["vulnerabilities"] == []


# --- CISA KEV -------------------------------------------------------------

def test_kev_excerpt_is_small_and_lists_log4shell():
    catalog = load_fixture("kev_excerpt.json")
    cve_ids = [entry["cveID"] for entry in catalog["vulnerabilities"]]

    assert "CVE-2021-44228" in cve_ids
    assert len(cve_ids) <= 10
