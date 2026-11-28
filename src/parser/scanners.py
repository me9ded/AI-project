"""Field-by-field readers for scanner JSON (docs/task1-brief.md, rule 3).

parse_pip_audit(data) -> Extraction    for `pip-audit -f json` output (see detect.py)

Design choices (see the brief, "Rules" and "Integration notes"):
- Only dependencies with at least one vuln are returned, so the JSON and table versions of a
  scan give the same packages (pip-audit's JSON also lists clean ones such as markupsafe).
- Every ID goes through `find_ids`, so IDs still come only from the regexes; unknown ID types
  (e.g. SNYK-...) are ignored.
- advisory_ids = each vuln's own ID (PYSEC/GHSA), the same IDs the table shows. CVE aliases go to
  cve_ids. Other aliases (GHSA) are left out: Task 2 gets them from OSV anyway, and each extra
  advisory ID would cost Task 2 one more OSV call that adds nothing.
- `raw_text` is filled in by extract() (Prompt 5), not here.
"""

from typing import Any

from src.parser.patterns import find_ids
from src.parser.schema import Extraction, Package

NPM_AUDIT_NOT_SUPPORTED = (
    "npm audit JSON is not supported yet: only the advisory IDs in it are used, not its packages."
)


def _add(target: list[str], values: list[str]) -> None:
    for value in values:
        if value not in target:
            target.append(value)


def parse_pip_audit(data: Any) -> Extraction:
    packages: list[Package] = []
    cve_ids: list[str] = []
    advisory_ids: list[str] = []
    warnings: list[str] = []

    dependencies = data.get("dependencies") if isinstance(data, dict) else None
    if not isinstance(dependencies, list):
        dependencies = []
        warnings.append("pip-audit JSON has no 'dependencies' list; nothing was read from it.")

    seen: set[tuple[str, str | None]] = set()
    for dep in dependencies:
        if not isinstance(dep, dict) or not isinstance(dep.get("name"), str) or not dep["name"].strip():
            _add(warnings, ["Skipped a pip-audit entry without a package name."])
            continue
        name = dep["name"].strip().lower()
        if dep.get("skip_reason"):
            _add(warnings, [f"pip-audit could not check {name}: {dep['skip_reason']}"])
            continue
        vulns = dep.get("vulns")
        if not isinstance(vulns, list) or not vulns:
            continue  # no known vulnerabilities: not a finding

        version = str(dep["version"]).strip() if dep.get("version") else None
        if (name, version) not in seen:
            seen.add((name, version))
            packages.append(Package(name=name, version=version, ecosystem="PyPI"))

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            own_cves, own_advisories = find_ids(str(vuln.get("id", "")))
            aliases = " ".join(a for a in vuln.get("aliases") or [] if isinstance(a, str))
            alias_cves, alias_advisories = find_ids(aliases)
            _add(cve_ids, own_cves + alias_cves)
            # Use the vuln's own advisory ID; fall back to an alias only if its own ID is not recognised.
            _add(advisory_ids, own_advisories or ([] if own_cves else alias_advisories[:1]))

    return Extraction(
        source_type="pip-audit",
        packages=packages,
        cve_ids=cve_ids,
        advisory_ids=advisory_ids,
        extraction_method="parser",
        warnings=warnings,
    )
