"""Tests for src/retrieval/version_matcher.py (design spec section 6, test IDs V1-V14)."""

import pytest

from src.retrieval.version_matcher import fixed_versions, is_affected, lowest_fix, parse_version


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


# ---------------------------------------------------------------------------
# Ranges: is_affected() reads an OSV "affected" entry (ranges + explicit versions).
# ---------------------------------------------------------------------------

def make_entry(*ranges, versions=None):
    """Build an OSV 'affected' entry from (type, events) pairs."""
    return {
        "ranges": [{"type": range_type, "events": events} for range_type, events in ranges],
        "versions": versions or [],
    }


# V2: PyPI jinja2-style range [0, 2.10.1).
def test_pypi_version_inside_fixed_range_is_affected():
    entry = make_entry(("ECOSYSTEM", [{"introduced": "0"}, {"fixed": "2.10.1"}]))

    assert is_affected("2.10", entry, "PyPI") is True
    assert is_affected("2.10.1", entry, "PyPI") is False


# V3: Maven log4j-core-style range [2.0-beta9, 2.15.0).
@pytest.mark.parametrize(
    "version, expected",
    [
        ("1.2.17", False),     # before introduced
        ("2.0-beta9", True),   # introduced version itself is affected
        ("2.14.1", True),
        ("2.15.0", False),     # fixed version is not affected
        ("2.17.1", False),
    ],
)
def test_maven_range_from_prerelease_to_fix(version, expected):
    entry = make_entry(("ECOSYSTEM", [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]))

    assert is_affected(version, entry, "Maven") is expected


# V5: npm lodash-style SEMVER range [0, 4.17.21).
def test_npm_semver_range():
    entry = make_entry(("SEMVER", [{"introduced": "0"}, {"fixed": "4.17.21"}]))

    assert is_affected("4.17.15", entry, "npm") is True
    assert is_affected("4.17.21", entry, "npm") is False


# V7: last_affected closes the interval *including* that version.
def test_last_affected_is_inclusive():
    entry = make_entry(("ECOSYSTEM", [{"introduced": "1.0"}, {"last_affected": "1.5"}]))

    assert is_affected("1.5", entry, "PyPI") is True
    assert is_affected("1.6", entry, "PyPI") is False


# V8: explicit versions list, no ranges.
def test_explicit_versions_list():
    entry = make_entry(versions=["1.2.3"])

    assert is_affected("1.2.3", entry, "npm") is True
    assert is_affected("1.2.4", entry, "npm") is False


# V9: an interval that is never closed means every later version is affected.
def test_open_ended_range_affects_all_later_versions():
    entry = make_entry(("ECOSYSTEM", [{"introduced": "3.0"}]))

    assert is_affected("2.9", entry, "PyPI") is False
    assert is_affected("3.0", entry, "PyPI") is True
    assert is_affected("99.0", entry, "PyPI") is True


# V10: several intervals in one range, and several ranges in one entry.
def test_multiple_intervals():
    entry = make_entry(
        ("ECOSYSTEM", [{"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"}, {"fixed": "2.5"}])
    )

    assert is_affected("1.2", entry, "PyPI") is True
    assert is_affected("1.7", entry, "PyPI") is False
    assert is_affected("2.1", entry, "PyPI") is True
    assert is_affected("2.5", entry, "PyPI") is False


def test_multiple_ranges():
    entry = make_entry(
        ("ECOSYSTEM", [{"introduced": "1.0"}, {"fixed": "1.5"}]),
        ("ECOSYSTEM", [{"introduced": "2.0"}, {"fixed": "2.5"}]),
    )

    assert is_affected("1.7", entry, "PyPI") is False
    assert is_affected("2.1", entry, "PyPI") is True


# V11: GIT ranges use commit hashes, not versions, so they are ignored.
def test_git_ranges_are_ignored():
    entry = make_entry(("GIT", [{"introduced": "0"}, {"fixed": "a1b2c3d4"}]))

    assert is_affected("1.0", entry, "PyPI") is False


# V15: the OSV schema does not require events to be in order, so we sort them first.
def test_unsorted_events_are_sorted_before_matching():
    entry = make_entry(
        ("ECOSYSTEM", [{"introduced": "1.0"}, {"introduced": "2.0"}, {"fixed": "2.5"}, {"fixed": "1.5"}])
    )

    assert is_affected("0.9", entry, "PyPI") is False
    assert is_affected("1.2", entry, "PyPI") is True
    assert is_affected("1.7", entry, "PyPI") is False
    assert is_affected("2.1", entry, "PyPI") is True
    assert is_affected("2.6", entry, "PyPI") is False


def test_unsorted_last_affected_events():
    entry = make_entry(
        ("ECOSYSTEM", [{"last_affected": "1.5"}, {"introduced": "0"}])
    )

    assert is_affected("1.5", entry, "PyPI") is True
    assert is_affected("1.6", entry, "PyPI") is False


# ---------------------------------------------------------------------------
# Fixes: fixed_versions() and lowest_fix() (design spec section 6.3).
# ---------------------------------------------------------------------------

# V14: every `fixed` event value from version ranges, without duplicates or GIT hashes.
def test_fixed_versions_collects_fixed_events():
    entry = make_entry(
        ("ECOSYSTEM", [{"introduced": "2.0-beta9"}, {"fixed": "2.3.1"}, {"introduced": "2.4"}, {"fixed": "2.12.2"}]),
        ("ECOSYSTEM", [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]),
        ("ECOSYSTEM", [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]),
        ("GIT", [{"introduced": "0"}, {"fixed": "a1b2c3d4"}]),
    )

    assert fixed_versions(entry) == ["2.3.1", "2.12.2", "2.15.0"]


def test_fixed_versions_empty_when_no_fix():
    entry = make_entry(("ECOSYSTEM", [{"introduced": "0"}]))

    assert fixed_versions(entry) == []


def log4j_entry(first_fix, branch_2_12_fix, latest_fix):
    """An OSV entry shaped like the Log4j advisories: three release branches."""
    return make_entry(
        (
            "ECOSYSTEM",
            [
                {"introduced": "2.0-beta9"}, {"fixed": first_fix},
                {"introduced": "2.4"}, {"fixed": branch_2_12_fix},
                {"introduced": "2.13.0"}, {"fixed": latest_fix},
            ],
        )
    )


LOG4J_ENTRIES = [
    log4j_entry("2.3.1", "2.12.2", "2.15.0"),   # CVE-2021-44228
    log4j_entry("2.3.1", "2.12.2", "2.16.0"),   # CVE-2021-45046
    log4j_entry("2.3.1", "2.12.3", "2.17.0"),   # CVE-2021-45105
    log4j_entry("2.3.2", "2.12.4", "2.17.1"),   # CVE-2021-44832
]


# V12: the Log4j worked example - backports below 2.14.1 are skipped, the answer is 2.17.1.
def test_lowest_fix_for_log4j_example():
    assert lowest_fix("2.14.1", LOG4J_ENTRIES, "Maven") == "2.17.1"


def test_lowest_fix_stays_on_the_installed_branch_when_it_can():
    assert lowest_fix("2.11.0", LOG4J_ENTRIES, "Maven") == "2.12.4"


# V16: the recommendation must not land inside another vulnerability's range.
def test_lowest_fix_never_recommends_a_still_vulnerable_version():
    vuln_x = make_entry(
        ("ECOSYSTEM", [{"introduced": "2.4"}, {"fixed": "2.12.2"}, {"introduced": "2.13.0"}, {"fixed": "2.15.0"}])
    )
    vuln_y = make_entry(("ECOSYSTEM", [{"introduced": "0"}, {"fixed": "2.13.1"}]))

    # 2.13.1 fixes Y but is inside X's [2.13.0, 2.15.0) range, so the answer is 2.15.0.
    assert lowest_fix("2.11.0", [vuln_x, vuln_y], "Maven") == "2.15.0"


def test_lowest_fix_ignores_vulns_without_a_fix_above_installed():
    fixable = make_entry(("ECOSYSTEM", [{"introduced": "0"}, {"fixed": "2.10.1"}]))
    never_fixed = make_entry(("ECOSYSTEM", [{"introduced": "0"}]))

    assert lowest_fix("2.10", [fixable, never_fixed], "PyPI") == "2.10.1"


# V13: nothing fixes anything above the installed version -> None.
def test_lowest_fix_is_none_when_no_fix_exists():
    old_fix_only = make_entry(("ECOSYSTEM", [{"introduced": "0"}, {"fixed": "1.0"}]))
    never_fixed = make_entry(("ECOSYSTEM", [{"introduced": "0"}]))

    assert lowest_fix("3.0", [old_fix_only, never_fixed], "PyPI") is None
    assert lowest_fix("3.0", [], "PyPI") is None
