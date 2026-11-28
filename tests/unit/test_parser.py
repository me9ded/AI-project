"""Tests for Task 1 - src/parser (spec: docs/task1-brief.md).

Prompt 1 covers schema.py and patterns.py (the regex layer, no AI).
The expected packages for the demo inputs come from Task 2's DEMO_INPUTS, so these
tests fail if Task 1's output ever stops matching what Task 2 expects.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from scripts.warm_cache import DEMO_INPUTS
from src.parser.patterns import find_ids, find_packages, maven_name, name_appears_in
from src.parser.schema import Extraction, Package

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "t1"


def read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def as_dicts(packages: list[Package]) -> list[dict]:
    return [p.model_dump() for p in packages]


# ---------------------------------------------------------------------------
# Schema (the output contract shared with Task 2)
# ---------------------------------------------------------------------------

def test_contract_has_exactly_the_agreed_keys():
    assert set(Extraction().to_dict()) == {
        "source_type", "packages", "cve_ids", "advisory_ids",
        "extraction_method", "raw_text", "ocr_confidence", "warnings",
    }


def test_schema_rejects_values_task2_cannot_use():
    with pytest.raises(ValidationError):
        Package(name="x", version="1", ecosystem="Go")          # unsupported ecosystem
    with pytest.raises(ValidationError):
        Extraction(extraction_method="guess")                    # unknown method
    with pytest.raises(ValidationError):
        Extraction(confidence=0.9)                                # typo'd field is not silently ignored


# ---------------------------------------------------------------------------
# Demo inputs (must match Task 2's DEMO_INPUTS)
# ---------------------------------------------------------------------------

def test_log4shell_log_matches_task2_demo_input():
    text = read("log4shell.log")
    packages, warnings = find_packages(text)
    assert as_dicts(packages) == DEMO_INPUTS["Log4Shell log line"]["packages"]
    assert find_ids(text) == ([], [])          # the log has no CVE number, and none is invented
    assert warnings == []


def test_pip_audit_table_matches_task2_demo_input():
    text = read("pip_audit.txt")
    packages, _ = find_packages(text)
    assert as_dicts(packages) == DEMO_INPUTS["pip-audit screenshot"]["packages"]
    cve_ids, advisory_ids = find_ids(text)
    assert cve_ids == []
    # pip-audit prints some rows twice; each ID appears once, in order of first appearance
    assert advisory_ids == [
        "PYSEC-2021-66", "PYSEC-2019-217", "PYSEC-2026-1473",
        "PYSEC-2026-1474", "PYSEC-2026-1475", "PYSEC-2026-1471",
    ]


def test_jackson_note_needs_the_llm():
    text = read("jackson_note.txt")
    assert find_packages(text) == ([], [])     # regex finds nothing, so Prompt 4's LLM fallback runs
    assert find_ids(text) == ([], [])          # "CVE-2017-something" is not a complete ID


# ---------------------------------------------------------------------------
# Extra cases
# ---------------------------------------------------------------------------

def test_requirements_file_pins():
    packages, _ = find_packages(read("requirements.txt"))
    assert as_dicts(packages) == [
        {"name": "jinja2", "version": "2.10", "ecosystem": "PyPI"},
        {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI"},
    ]                                           # "Flask>=2.0" is a range, not a version: skipped


def test_npm_note_with_scoped_package_and_cve():
    text = read("npm_note.txt")
    packages, _ = find_packages(text)
    assert as_dicts(packages) == [
        {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
        {"name": "@angular/core", "version": "11.0.0", "ecosystem": "npm"},
    ]
    assert find_ids(text) == (["CVE-2020-8203"], [])


def test_ids_only_text():
    text = read("cve_only.txt")
    assert find_packages(text) == ([], [])
    assert find_ids(text) == (["CVE-2021-44228", "CVE-2021-45046"], ["GHSA-jfh8-c2jp-5v3q"])


def test_unknown_java_library_is_kept_but_flagged():
    packages, warnings = find_packages(read("java_stacktrace.log"))
    assert as_dicts(packages) == [
        {"name": "com.fasterxml.jackson.core:jackson-databind", "version": "2.9.8", "ecosystem": "Maven"},
        {"name": "commons-text", "version": "1.9", "ecosystem": "unknown"},
    ]
    assert len(warnings) == 1 and "commons-text" in warnings[0]


@pytest.mark.parametrize("text", ["", None, "   \n  "])
def test_empty_input(text):
    assert find_packages(text) == ([], [])
    assert find_ids(text) == ([], [])


def test_ids_are_normalised():
    cve_ids, advisory_ids = find_ids("cve-2021-44228 ghsa-JFH8-C2JP-5V3Q pysec-2021-66 CVE-2021-44228")
    assert cve_ids == ["CVE-2021-44228"]
    assert advisory_ids == ["GHSA-jfh8-c2jp-5v3q", "PYSEC-2021-66"]  # GHSA body stays lower-case for OSV


def test_random_log_line_is_not_a_pip_audit_row():
    # looks like "name version ID" but has no pip-audit header and no PYSEC ID
    assert find_packages("Fixed 2.0 CVE-2021-1234 last week") == ([], [])


@pytest.mark.parametrize("text, expected", [
    ("requests[security]==2.19.0", ("requests", "2.19.0", "PyPI")),               # pip extras
    (r"C:\app\lib\log4j-core-2.14.1.jar", ("org.apache.logging.log4j:log4j-core", "2.14.1", "Maven")),
    ("lib/log4j-api-2.17.1-SNAPSHOT.jar", ("org.apache.logging.log4j:log4j-api", "2.17.1-SNAPSHOT", "Maven")),
    ("jinja2 2.10 PYSEC-2019-217 2.10.1", ("jinja2", "2.10", "PyPI")),              # OCR'd row, header lost
    ("jinja2==2.10\r\n", ("jinja2", "2.10", "PyPI")),                              # Windows line endings
])
def test_single_package_variants(text, expected):
    packages, _ = find_packages(text)
    assert [(p.name, p.version, p.ecosystem) for p in packages] == [expected]


def test_long_junk_input_is_fast():
    import time
    junk = "a-" + ".1" * 5000 + " " + "x" * 100_000 + " lib-" + "1." * 3000 + "1x"
    start = time.perf_counter()
    find_packages(junk)
    find_ids(junk)
    assert time.perf_counter() - start < 1.0


def test_version_at_end_of_sentence():
    packages, _ = find_packages("Please upgrade from jinja2==2.10.")
    assert as_dicts(packages) == [{"name": "jinja2", "version": "2.10", "ecosystem": "PyPI"}]


def test_maven_lookup():
    assert maven_name("log4j-core") == "org.apache.logging.log4j:log4j-core"
    assert maven_name("Jackson-Databind") == "com.fasterxml.jackson.core:jackson-databind"
    assert maven_name("commons-text") is None


# ---------------------------------------------------------------------------
# Guardrail helper (used by the LLM fallback in Prompt 4)
# ---------------------------------------------------------------------------

def test_name_appears_in_text():
    note = read("jackson_note.txt")
    assert name_appears_in("jackson-databind", note)
    assert name_appears_in("com.fasterxml.jackson.core:jackson-databind", note)
    assert not name_appears_in("spring-core", note)   # an invented package is rejected
    assert not name_appears_in("", note)
