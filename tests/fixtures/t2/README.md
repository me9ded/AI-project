# Task 2 fixtures – real API responses

Saved once on **2026-11-20** from the public APIs, then trimmed so they stay readable.
Unit tests read them with `load_fixture()` from `tests/unit/fakes.py`. `tests/unit/test_fixtures.py`
checks that trimming kept the facts the other tests rely on.

| File | Source request |
|------|----------------|
| `osv_query_log4j_core_2.14.1.json` | `POST https://api.osv.dev/v1/query` `{"package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"}, "version": "2.14.1"}` |
| `osv_vuln_GHSA-jfh8-c2jp-5v3q.json` | `GET https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q` |
| `osv_query_jinja2_2.10.json` | `POST https://api.osv.dev/v1/query` `{"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "2.10"}` |
| `nvd_CVE-2021-44228.json` | `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228` |
| `nvd_not_found.json` | `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-99999999` (HTTP 200, `totalResults: 0`) |
| `kev_excerpt.json` | `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |

## What was trimmed
- **OSV:** kept `id`, `aliases`, `summary`, `severity`, `database_specific.severity/cwe_ids`, and per
  `affected` entry its `package`, `ranges` and `versions`. Shortened `details` to 300 characters and kept
  the first 3 `references`. Kept every `affected` entry for the queried package, plus **one** entry for a
  different package so tests can check the filtering. Every vuln OSV returned is kept: 8 for log4j-core,
  12 for jinja2, including the GHSA/PYSEC duplicates of the same CVE.
- **NVD:** kept the top-level fields and, for the CVE, `id`, dates, `vulnStatus`, the `cisa*` name and date,
  `descriptions` (shortened to 300 characters), all `metrics` and `weaknesses`, and the first 5 `references`.
  Dropped `configurations` (out of scope).
- **KEV:** 5 of 1,790 entries: CVE-2021-44228, CVE-2021-45046 and the first 3 others. Long text shortened
  to 200 characters; `count` matches the excerpt.

## Things the real data showed
- OSV splits one package into **several `affected` entries**, one per release branch. CVE-2021-44228 has
  three for log4j-core. Merge them before matching.
- log4j-core 2.14.1 now has **8** vulnerabilities, not only the 4 from December 2021. Across all 8 the
  lowest safe upgrade is **2.25.4**; for the 4 demo CVEs alone it is 2.17.1.
- NVD `metrics` can contain non-CVSS keys (`ssvcV203`). Read only `cvssMetricV31`, `cvssMetricV30` and
  `cvssMetricV2`.
- NVD answers an unknown CVE with HTTP 200 and `totalResults: 0`, not 404.

Only public package names and CVE/advisory IDs were sent to the APIs.
