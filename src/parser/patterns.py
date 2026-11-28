"""Regex layer of Task 1: deterministic, no AI (docs/task1-brief.md, rules 1, 2 and 5).

Public functions:
    find_ids(text)            -> (cve_ids, advisory_ids)   also used by Task 3's guardrail
    find_packages(text)       -> (packages, warnings)
    maven_name(artifact)      -> "groupId:artifactId" or None
    name_appears_in(name, text) -> bool                     guardrail for the LLM fallback

Vulnerability IDs are ONLY ever produced by `find_ids`, so nothing downstream can
invent one. An incomplete ID such as "CVE-2017-something" does not match.
"""

import re

from src.parser.schema import Package

# ---------------------------------------------------------------------------
# Vulnerability identifiers
# ---------------------------------------------------------------------------

_CVE = r"CVE-\d{4}-\d{4,7}"
_GHSA = r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"
_PYSEC = r"PYSEC-\d{4}-\d+"
ID_RE = re.compile(rf"\b(?:{_CVE}|{_GHSA}|{_PYSEC})\b", re.IGNORECASE)


def _normalise_id(raw: str) -> str:
    """CVE/PYSEC in upper case; GHSA keeps its canonical lower-case body (OSV IDs are case-sensitive)."""
    upper = raw.upper()
    if upper.startswith("GHSA-"):
        return "GHSA-" + raw[5:].lower()
    return upper


def find_ids(text: str) -> tuple[list[str], list[str]]:
    """Return (cve_ids, advisory_ids) in order of first appearance, without duplicates."""
    cve_ids: list[str] = []
    advisory_ids: list[str] = []
    for match in ID_RE.finditer(text or ""):
        vuln_id = _normalise_id(match.group(0))
        target = cve_ids if vuln_id.startswith("CVE-") else advisory_ids
        if vuln_id not in target:
            target.append(vuln_id)
    return cve_ids, advisory_ids


# ---------------------------------------------------------------------------
# Packages and versions
# ---------------------------------------------------------------------------

# Python pin at the start of a line, spaces allowed:   "jinja2 == 2.10", "requests[security]==2.19.0"
PIN_LINE_RE = re.compile(r"^[ \t]*([A-Za-z0-9][\w.-]*)(?:\[[^\]\n]*\])?[ \t]*==[ \t]*(\d[^\s;#,]*)", re.MULTILINE)
# Python pin inside a sentence, no spaces:             "pip install jinja2==2.10"
PIN_INLINE_RE = re.compile(r"(?<![\w.=-])([A-Za-z0-9][\w.-]*)(?:\[[^\]\s]*\])?==(\d[^\s;#,'\")\]]*)")
# npm specifier, scoped or not:                        "lodash@4.17.15", "@angular/core@11.0.0"
NPM_RE = re.compile(r"(?<![\w./@-])((?:@[\w.-]+/)?[\w.-]+)@(\d+\.\d+\.\d+[\w.+-]*)")
# Java JAR file in a log or classpath:                 "log4j-core-2.14.1.jar", "x-1.0-SNAPSHOT.jar"
# (a qualifier must start with a letter, so the regex cannot backtrack badly on long digit strings)
JAR_RE = re.compile(
    r"(?<![\w.-])([A-Za-z][\w.-]*?)-(\d+(?:\.\d+)+(?:[.-][A-Za-z][A-Za-z0-9]*)*)\.jar\b", re.IGNORECASE
)
# pip-audit table row:                                  "jinja2 2.10    PYSEC-2019-217 2.10.1"
PIP_AUDIT_ROW_RE = re.compile(
    r"^[ \t]*([A-Za-z0-9][\w.-]*)[ \t]+(\d[\w.+!-]*)[ \t]+((?:PYSEC|GHSA|CVE)-\S+)",
    re.MULTILINE | re.IGNORECASE,
)
PIP_AUDIT_HEADER_RE = re.compile(r"^[ \t]*Name[ \t]+Version[ \t]+ID\b", re.MULTILINE | re.IGNORECASE)

# Maven: JAR artifact -> groupId. Only the demo libraries (proposal 4.2); more is a stretch item.
MAVEN_GROUPS = {
    "log4j-core": "org.apache.logging.log4j",
    "log4j-api": "org.apache.logging.log4j",
    "jackson-databind": "com.fasterxml.jackson.core",
    "jackson-core": "com.fasterxml.jackson.core",
    "jackson-annotations": "com.fasterxml.jackson.core",
}


def maven_name(artifact: str) -> str | None:
    """'log4j-core' -> 'org.apache.logging.log4j:log4j-core'; None if the artifact is not in the table."""
    artifact = artifact.lower()
    group = MAVEN_GROUPS.get(artifact)
    return f"{group}:{artifact}" if group else None


def _clean_version(version: str) -> str:
    """Drop punctuation that ends a sentence, e.g. 'jinja2==2.10.' -> '2.10'."""
    return version.rstrip(".,;:)-")


def find_packages(text: str) -> tuple[list[Package], list[str]]:
    """Return (packages, warnings). Packages are in order of first appearance, without duplicates."""
    text = text or ""
    hits: list[tuple[int, str, str | None, str]] = []  # (position, name, version, ecosystem)
    warnings: list[str] = []

    for regex in (PIN_LINE_RE, PIN_INLINE_RE):
        for m in regex.finditer(text):
            hits.append((m.start(1), m.group(1).lower(), _clean_version(m.group(2)), "PyPI"))

    # pip-audit rows: trust them when the table header is present or the ID is a PYSEC ID
    # (PYSEC IDs only exist for Python packages), so a random log line is not mistaken for one.
    has_header = bool(PIP_AUDIT_HEADER_RE.search(text))
    for m in PIP_AUDIT_ROW_RE.finditer(text):
        if has_header or m.group(3).upper().startswith("PYSEC-"):
            hits.append((m.start(1), m.group(1).lower(), _clean_version(m.group(2)), "PyPI"))

    for m in NPM_RE.finditer(text):
        hits.append((m.start(1), m.group(1).lower(), _clean_version(m.group(2)), "npm"))

    for m in JAR_RE.finditer(text):
        artifact = m.group(1).lower()
        full_name = maven_name(artifact)
        if full_name:
            hits.append((m.start(1), full_name, m.group(2), "Maven"))
        else:
            hits.append((m.start(1), artifact, m.group(2), "unknown"))
            warning = f"Unknown Java library '{artifact}': its Maven group is not in the lookup table, so it is not looked up."
            if warning not in warnings:
                warnings.append(warning)

    packages: list[Package] = []
    seen: set[tuple[str, str, str | None]] = set()
    for _, name, version, ecosystem in sorted(hits, key=lambda hit: hit[0]):
        key = (ecosystem, name, version)
        if key not in seen:
            seen.add(key)
            packages.append(Package(name=name, version=version or None, ecosystem=ecosystem))
    return packages, warnings


# ---------------------------------------------------------------------------
# Guardrail helper for the LLM fallback (rule 5)
# ---------------------------------------------------------------------------

def _squash(value: str) -> str:
    return re.sub(r"[\s._-]+", "", value.lower())


def name_appears_in(name: str, text: str) -> bool:
    """True if the package name occurs in the text, ignoring case, spaces, '-', '_' and '.'.

    For a Maven name only the artifact part is checked, so "Jackson databind" in the
    text matches 'jackson-databind' and 'com.fasterxml.jackson.core:jackson-databind'.
    """
    key = _squash(name.rsplit(":", 1)[-1])
    return bool(key) and key in _squash(text or "")
