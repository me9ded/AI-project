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
    for version_range in affected_entry.get("ranges", []):
        if version_range.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue  # GIT ranges use commit hashes, not versions
        if _in_range(parsed, version_range.get("events", []), ecosystem):
            return True
    return False


def _in_range(parsed, events: list[dict], ecosystem: str) -> bool:
    """Walk OSV events in order. `introduced` opens an interval; `fixed` closes it
    (excluded) and `last_affected` closes it (included). An unclosed interval runs forever."""
    start = None
    for event in events:
        if "introduced" in event:
            start = event["introduced"]
        elif "fixed" in event and start is not None:
            if _at_or_after(parsed, start, ecosystem) and parsed < parse_version(event["fixed"], ecosystem):
                return True
            start = None
        elif "last_affected" in event and start is not None:
            if _at_or_after(parsed, start, ecosystem) and parsed <= parse_version(event["last_affected"], ecosystem):
                return True
            start = None
    return start is not None and _at_or_after(parsed, start, ecosystem)


def _at_or_after(parsed, start: str, ecosystem: str) -> bool:
    """OSV uses introduced "0" to mean 'from the very first version'."""
    return start == "0" or parsed >= parse_version(start, ecosystem)


def fixed_versions(affected_entry):
    raise NotImplementedError


def lowest_fix(installed, fixed_lists, ecosystem):
    raise NotImplementedError
