"""Version matching for OSV affected ranges (design spec section 6).

parse_version() turns a version string into a value that compares correctly for its
ecosystem. PyPI uses the `packaging` library (full PEP 440). npm and Maven use a small
"dotted numbers + qualifier" rule that is good enough for our demo packages.
"""

import re

from packaging.version import Version

# Qualifiers that mean "this is the real release", e.g. Hibernate's "5.3.0.Final".
_RELEASE_QUALIFIERS = {"", "final", "ga", "release"}

# Leading dotted numbers, then whatever is left: "2.0-beta9" -> "2.0", "-beta9".
_DOTTED_VERSION = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")


def parse_version(version: str, ecosystem: str):
    """Return a comparable value for `version`. Raises ValueError if it can't be parsed."""
    if ecosystem == "PyPI":
        return Version(version)  # InvalidVersion is a subclass of ValueError
    if ecosystem in ("npm", "Maven"):
        return _dotted_key(version)
    raise ValueError(f"Unsupported ecosystem: {ecosystem}")


def _dotted_key(version: str) -> tuple:
    """Key for npm/Maven versions: (numbers, is_release, qualifier).

    - numbers are compared as integers, trailing zeros removed so 2.0 == 2.0.0
    - a pre-release qualifier (beta, rc, …) sorts before the release (is_release 0 < 1)
    """
    match = _DOTTED_VERSION.match(version.strip())
    if match is None:
        raise ValueError(f"Not a dotted version: {version!r}")

    numbers = [int(part) for part in match.group(1).split(".")]
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()

    qualifier = match.group(2).lstrip(".-").lower()
    is_release = 1 if qualifier in _RELEASE_QUALIFIERS else 0
    if is_release:
        qualifier = ""
    return (tuple(numbers), is_release, qualifier)


def is_affected(version: str, affected_entry: dict, ecosystem: str) -> bool:
    """True if `version` is listed in, or falls inside a range of, an OSV 'affected' entry."""
    if version in affected_entry.get("versions", []):
        return True

    parsed = parse_version(version, ecosystem)
    return any(_in_range(parsed, events, ecosystem) for events in _version_range_events(affected_entry))


def _version_range_events(affected_entry: dict) -> list[list[dict]]:
    """Event lists of the entry's ECOSYSTEM/SEMVER ranges. GIT ranges use commit
    hashes, not versions, so they are skipped."""
    return [
        version_range.get("events", [])
        for version_range in affected_entry.get("ranges", [])
        if version_range.get("type") in ("ECOSYSTEM", "SEMVER")
    ]


def _in_range(parsed, events: list[dict], ecosystem: str) -> bool:
    """OSV's reference algorithm: sort the events by version, then step through them.

    `introduced` at or below the version switches "affected" on; `fixed` at or below
    it switches it off; `last_affected` switches it off only once the version is past it.
    """
    affected = False
    for event in _sorted_events(events, ecosystem):
        if "introduced" in event:
            if event["introduced"] == "0" or parsed >= parse_version(event["introduced"], ecosystem):
                affected = True
        elif "fixed" in event:
            if parsed >= parse_version(event["fixed"], ecosystem):
                affected = False
        elif "last_affected" in event:
            if parsed > parse_version(event["last_affected"], ecosystem):
                affected = False
    return affected


def _sorted_events(events: list[dict], ecosystem: str) -> list[dict]:
    """Events ordered by version. OSV uses introduced "0" to mean 'the very first version'."""
    def event_key(event: dict):
        value = event.get("introduced") or event.get("fixed") or event.get("last_affected")
        if value is None:
            return (1,)  # e.g. a "limit" event: not used for matching, keep it last
        if value == "0":
            return (-1,)
        return (0, parse_version(value, ecosystem))

    return sorted(events, key=event_key)


def fixed_versions(affected_entry: dict) -> list[str]:
    """Every `fixed` version in the entry's version ranges, in order, without duplicates."""
    found = []
    for events in _version_range_events(affected_entry):
        for event in events:
            fixed = event.get("fixed")
            if fixed is not None and fixed not in found:
                found.append(fixed)
    return found


def lowest_fix(installed: str, affected_entries: list[dict], ecosystem: str) -> str | None:
    """Lowest version that fixes every vulnerability (design spec section 6.3).

    Candidates are the fixed versions above the installed one, tried from lowest
    to highest. The first candidate that none of the vulnerabilities affect wins.
    Vulnerabilities with no fix above the installed version can't be fixed by
    upgrading, so they are left out (the caller warns about them).
    """
    def version_key(version: str):
        return parse_version(version, ecosystem)

    current = version_key(installed)
    fixable = []
    candidates = set()
    for entry in affected_entries:
        upgrades = [fix for fix in fixed_versions(entry) if version_key(fix) > current]
        if upgrades:
            fixable.append(entry)
            candidates.update(upgrades)

    for candidate in sorted(candidates, key=version_key):
        if not any(is_affected(candidate, entry, ecosystem) for entry in fixable):
            return candidate
    return None
