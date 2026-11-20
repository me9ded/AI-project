"""Tests for src/retrieval/version_matcher.py (design spec section 6, test IDs V1-V14)."""

import pytest

from src.retrieval.version_matcher import parse_version


# ---------------------------------------------------------------------------
# Parsing: parse_version() gives values that compare the way each ecosystem means.
# ---------------------------------------------------------------------------

# V1: PyPI compares numerically (PEP 440), not as text: "2.10" > "2.9".
def test_pypi_versions_compare_numerically():
    assert parse_version("2.10", "PyPI") > parse_version("2.9", "PyPI")


def test_pypi_release_candidate_is_before_release():
    assert parse_version("1.0rc1", "PyPI") < parse_version("1.0", "PyPI")


def test_pypi_invalid_version_raises_value_error():
    with pytest.raises(ValueError):
        parse_version("not a version", "PyPI")


# V4: Maven - numeric parts as integers, qualifiers before the release, missing parts = 0.
def test_maven_versions_compare_numerically():
    assert parse_version("2.10", "Maven") > parse_version("2.9", "Maven")
    assert parse_version("2.14.1", "Maven") < parse_version("2.15.0", "Maven")


def test_maven_qualifier_is_before_release():
    assert parse_version("2.0-beta9", "Maven") < parse_version("2.0", "Maven")
    assert parse_version("2.0-rc1", "Maven") < parse_version("2.0", "Maven")


def test_maven_missing_parts_count_as_zero():
    assert parse_version("2.0", "Maven") == parse_version("2.0.0", "Maven")


def test_maven_final_qualifier_is_a_release():
    assert parse_version("5.3.0.Final", "Maven") == parse_version("5.3.0", "Maven")


# V6: npm (semver) - numeric compare, pre-release before release.
def test_npm_versions_compare_numerically():
    assert parse_version("4.17.15", "npm") < parse_version("4.17.21", "npm")
    assert parse_version("1.10.0", "npm") > parse_version("1.9.0", "npm")


def test_npm_prerelease_is_before_release():
    assert parse_version("1.0.0-rc.1", "npm") < parse_version("1.0.0", "npm")


@pytest.mark.parametrize("ecosystem", ["npm", "Maven"])
def test_non_numeric_version_raises_value_error(ecosystem):
    with pytest.raises(ValueError):
        parse_version("latest", ecosystem)


def test_unknown_ecosystem_raises_value_error():
    with pytest.raises(ValueError):
        parse_version("1.0", "unknown")
