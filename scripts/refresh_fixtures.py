"""Download real OSV/NVD/KEV responses and trim them into tests/fixtures/t2/.

Run from the project root:

    python scripts/refresh_fixtures.py

Only public package names and CVE/advisory IDs are sent. The trimming rules are
described in tests/fixtures/t2/README.md. After refreshing, run the unit tests:
answers that depend on the date (for example the Log4j upgrade) may change.
"""

import json
from pathlib import Path

import requests

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "t2"

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

LOG4J_CORE = "org.apache.logging.log4j:log4j-core"
KEV_WANTED = {"CVE-2021-44228", "CVE-2021-45046"}


# ---------------------------------------------------------------------------
# Trimming (pure functions, unit tested)
# ---------------------------------------------------------------------------

def shorten(text: str, limit: int = 300) -> str:
    """Cut long text to `limit` characters and mark the cut with an ellipsis."""
    return text if len(text) <= limit else text[:limit].rstrip() + " …"


def trim_osv_vuln(vuln: dict, package: str) -> dict:
    """Keep the fields Task 2 uses. Keep every `affected` entry for `package`
    plus one entry for another package, so tests can check the filtering."""
    mine = [a for a in vuln["affected"] if a["package"]["name"].lower() == package.lower()]
    others = [a for a in vuln["affected"] if a["package"]["name"].lower() != package.lower()]
    trimmed = {
        "id": vuln["id"],
        "aliases": vuln.get("aliases", []),
        "summary": vuln.get("summary", ""),
        "details": shorten(vuln.get("details", "")),
        "affected": [
            {"package": a["package"], "ranges": a.get("ranges", []), "versions": a.get("versions", [])}
            for a in mine + others[:1]
        ],
        "references": vuln.get("references", [])[:3],
    }
    if "severity" in vuln:
        trimmed["severity"] = vuln["severity"]
    specific = vuln.get("database_specific", {})
    kept = {key: specific[key] for key in ("severity", "cwe_ids") if key in specific}
    if kept:
        trimmed["database_specific"] = kept
    return trimmed


def trim_nvd_response(response: dict) -> dict:
    """Keep the CVE fields Task 2 uses; drop `configurations` (out of scope)."""
    trimmed = dict(response)
    trimmed_vulns = []
    for item in response["vulnerabilities"]:
        cve = item["cve"]
        keep = ("id", "sourceIdentifier", "published", "lastModified", "vulnStatus",
                "cisaExploitAdd", "cisaVulnerabilityName", "metrics", "weaknesses")
        trimmed_cve = {key: cve[key] for key in keep if key in cve}
        trimmed_cve["descriptions"] = [
            {"lang": d["lang"], "value": shorten(d["value"])} for d in cve.get("descriptions", [])
        ]
        trimmed_cve["references"] = cve.get("references", [])[:5]
        trimmed_vulns.append({"cve": trimmed_cve})
    trimmed["vulnerabilities"] = trimmed_vulns
    return trimmed


def trim_kev_catalog(catalog: dict, wanted: set, extra: int = 3) -> dict:
    """The `wanted` CVEs plus the first `extra` other entries, long text shortened."""
    entries = [e for e in catalog["vulnerabilities"] if e["cveID"] in wanted]
    entries += [e for e in catalog["vulnerabilities"] if e["cveID"] not in wanted][:extra]
    entries = [
        {**e, "shortDescription": shorten(e["shortDescription"], 200), "notes": shorten(e["notes"], 200)}
        for e in entries
    ]
    return {
        "title": catalog["title"],
        "catalogVersion": catalog["catalogVersion"],
        "dateReleased": catalog["dateReleased"],
        "count": len(entries),
        "vulnerabilities": entries,
    }


# ---------------------------------------------------------------------------
# Downloading and saving
# ---------------------------------------------------------------------------

def osv_query(session, name, ecosystem, version):
    body = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    response = session.post(OSV_QUERY_URL, json=body, timeout=30)
    response.raise_for_status()
    return response.json()


def get_json(session, url, params=None):
    response = session.get(url, params=params, timeout=60)
    response.raise_for_status()
    return response.json()


def save(name: str, data: dict) -> None:
    path = FIXTURES_DIR / name
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(FIXTURES_DIR.parent.parent.parent)}: {path.stat().st_size:,} bytes")


def main() -> None:
    session = requests.Session()

    log4j = osv_query(session, LOG4J_CORE, "Maven", "2.14.1")
    save("osv_query_log4j_core_2.14.1.json", {"vulns": [trim_osv_vuln(v, LOG4J_CORE) for v in log4j["vulns"]]})

    ghsa = get_json(session, OSV_VULN_URL.format(id="GHSA-jfh8-c2jp-5v3q"))
    save("osv_vuln_GHSA-jfh8-c2jp-5v3q.json", trim_osv_vuln(ghsa, LOG4J_CORE))

    jinja2 = osv_query(session, "jinja2", "PyPI", "2.10")
    save("osv_query_jinja2_2.10.json", {"vulns": [trim_osv_vuln(v, "jinja2") for v in jinja2["vulns"]]})

    # Two NVD calls stay well inside the 5-per-30-seconds limit without an API key.
    save("nvd_CVE-2021-44228.json", trim_nvd_response(get_json(session, NVD_URL, {"cveId": "CVE-2021-44228"})))
    save("nvd_not_found.json", get_json(session, NVD_URL, {"cveId": "CVE-2021-99999999"}))

    save("kev_excerpt.json", trim_kev_catalog(get_json(session, KEV_URL), KEV_WANTED))


if __name__ == "__main__":
    main()
