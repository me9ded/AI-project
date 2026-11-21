"""Tests for scripts/warm_cache.py (demo preparation, design spec section 10)."""

from scripts.warm_cache import DEMO_INPUTS, check_offline, summarise, warm
from src.retrieval.vulnerability_models import RetrievalResult, VulnerabilityRecord


def make_result(record_ids=("CVE-2021-44228",), upgrades=None, incomplete=False, warnings=()):
    records = [
        VulnerabilityRecord(
            id=record_id, aliases=[], package_name="lib", ecosystem="Maven", installed_version="1.0",
            affected=True, summary="", cvss_score=None, severity="PENDING", cwes=[], fixed_versions=[],
            in_kev=False, sources=[],
        )
        for record_id in record_ids
    ]
    return RetrievalResult(records=records, recommended_upgrades=upgrades or {},
                           incomplete=incomplete, warnings=list(warnings))


class FakeService:
    """Returns a prepared result per extraction and records what it was asked."""

    def __init__(self, results_by_first_package):
        self.results = results_by_first_package
        self.asked = []

    def retrieve(self, extraction):
        self.asked.append(extraction)
        return self.results[extraction["packages"][0]["name"]]


# The demo inputs follow the proposal (section 4.3) and Task 1's extraction format.
def test_demo_inputs_cover_the_proposal_demo():
    assert set(DEMO_INPUTS) == {"Log4Shell log line", "pip-audit screenshot", "Jackson databind note"}
    for extraction in DEMO_INPUTS.values():
        assert extraction["packages"]
        for package in extraction["packages"]:
            assert set(package) == {"name", "version", "ecosystem"}
        assert extraction["cve_ids"] == [] and extraction["advisory_ids"] == []

    log4shell = {p["name"]: p["version"] for p in DEMO_INPUTS["Log4Shell log line"]["packages"]}
    assert log4shell["org.apache.logging.log4j:log4j-core"] == "2.14.1"


def test_warm_runs_every_input_once():
    inputs = {"a": {"packages": [{"name": "x"}]}, "b": {"packages": [{"name": "y"}]}}
    service = FakeService({"x": make_result(), "y": make_result([])})

    results = warm(service, inputs)

    assert list(results) == ["a", "b"]
    assert len(service.asked) == 2
    assert results["b"].records == []


def test_summary_line_shows_counts_upgrade_and_status():
    result = make_result(["CVE-1", "CVE-2"], upgrades={"lib": "2.0"}, incomplete=True, warnings=["NVD unavailable"])

    line = summarise("Demo", result)

    assert "Demo" in line
    assert "2 vulnerabilities" in line
    assert "lib -> 2.0" in line
    assert "INCOMPLETE" in line
    assert "1 warning" in line


def test_offline_check_passes_when_answers_match():
    inputs = {"a": {"packages": [{"name": "x"}]}}
    expected = {"a": make_result()}

    assert check_offline(FakeService({"x": make_result()}), inputs, expected) == []


def test_offline_check_names_inputs_whose_answer_changed():
    inputs = {"a": {"packages": [{"name": "x"}]}, "b": {"packages": [{"name": "y"}]}}
    expected = {"a": make_result(), "b": make_result()}
    offline = FakeService({"x": make_result(), "y": make_result([], incomplete=True)})

    problems = check_offline(offline, inputs, expected)

    assert len(problems) == 1
    assert "b" in problems[0]
