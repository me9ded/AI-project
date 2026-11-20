# Task 2 – Vulnerability Data Retrieval: Design Spec

| | |
|---|---|
| **Project** | AI-Powered CVE Tracker (CST8327 Section 011, Group 5) |
| **Component** | Task 2 – Vulnerability Data Retrieval (backend) |
| **Owner** | Brian Huynh |
| **Branch / folder** | `brian` / `src/retrieval/` |
| **Upstream** | Task 1 – Input Parsing & Extraction (Nibir) |
| **Downstream** | Task 3 – Graph RAG / Neo4j loader (Fouzi), Task 4 – API pipeline (Mariam) |
| **Status** | Draft for team review |

**Development rules**
1. **Red → Green → Refactor.** Every behaviour starts as a failing test (section 9). We write the least code that makes it pass, then tidy up while the tests stay green.
2. **Readable over clever.** Plain functions and small classes, no frameworks, no metaprogramming. A grader should be able to follow each file top to bottom.

---

## 1. Purpose and scope

Task 2 takes the packages and identifiers that Task 1 found and answers three questions for each one:

1. **Which vulnerabilities affect this exact version?** OSV.dev answers this, and our own version matcher double-checks it.
2. **How severe is each one, and what kind of weakness is it?** NVD answers this.
3. **Is it being exploited right now?** CISA KEV answers this.

It returns one clean, de-duplicated record per vulnerability, which Task 3 loads into Neo4j.

**In scope:** OSV.dev client, NVD API 2.0 client, CISA KEV client, version-range matching (PyPI, npm, Maven),
working out the lowest fixed version, SQLite cache, rate limiting, retries, offline fallback.

**Out of scope:** GitHub Advisories API (OSV already includes GHSA data), CWE *names* (NVD only gives IDs),
NVD CPE configuration matching (OSV ranges are more precise for packages), and async or parallel requests.

---

## 2. Requirements

### 2.1 Functional
| ID | Requirement |
|----|-------------|
| FR1 | Accept Task 1's extraction dict (section 4.1). Ignore fields Task 2 doesn't use (`raw_text`, `source_type`, `extraction_method`). |
| FR2 | For every package that has a version, query OSV and keep only the vulnerabilities whose ranges include that version. |
| FR3 | For a package with `version: null` (for example npm audit without a lockfile), query OSV by package only and mark each record `affected = None` ("version unknown"). |
| FR4 | Resolve every `advisory_id` (GHSA-…, PYSEC-…) through OSV to its CVE aliases. |
| FR5 | Enrich every CVE ID, whether found through OSV or given in `cve_ids`, from NVD: CVSS base score, CWE IDs and English description. |
| FR6 | Set `in_kev = True` for every CVE listed in the CISA KEV catalog. |
| FR7 | Version matcher: decide whether a version is inside OSV `ECOSYSTEM`/`SEMVER` ranges for PyPI, npm and Maven (section 6). |
| FR8 | For each package, work out the lowest version that fixes **all** of its known vulnerabilities (demo: log4j-core 2.14.1 → 2.17.1). |
| FR9 | Produce one record per vulnerability, keyed by CVE ID, or by the OSV ID when there is no CVE alias. The same vulnerability reached through two paths gives one record. |
| FR10 | Severity rules (section 7.3): CVSS score → FIRST rating. If there is no score, use the OSV label. If there is no label, use `PENDING`. |
| FR11 | Never invent identifiers. Every ID in the output comes from the input or from an API response. |

### 2.2 Non-functional
| ID | Requirement |
|----|-------------|
| NFR1 | **Cache:** SQLite file, 24 h TTL, survives restarts. It can be filled before the demo so the demo runs offline. |
| NFR2 | **Graceful failure:** an API failure never crashes `retrieve()`. Use stale cache data if there is any, otherwise skip that item. Either way, set `incomplete = True` and add a warning. |
| NFR3 | **NVD rate limit:** at most 50 requests per 30 s with an API key, 5 per 30 s without one. |
| NFR4 | **Retries:** on HTTP 429, HTTP 5xx, connection errors or timeouts, retry with exponential backoff (1 s, 2 s, 4 s), at most 3 retries. Other 4xx errors are not retried. |
| NFR5 | **Testable:** HTTP session, cache, clock and sleep are passed in through constructors. Unit tests use no network and no real sleeping. |
| NFR6 | **Privacy:** only package names, versions and vulnerability IDs leave the machine, never the user's raw text. |
| NFR7 | **Platform:** Python 3.11+. Runtime dependencies: `requests`, `pydantic` (v2), `packaging`, `python-dotenv`. Test dependency: `pytest`. |
| NFR8 | **Secrets:** read `NVD_API_KEY` from `.env`, which is never committed. Ship `.env.example` with the key blank. |

---

## 3. Architecture

```
                 extraction dict (Task 1)
                          │
                          ▼
              ┌──────────────────────────┐
              │  retrieve()  (__init__)  │  builds the real clients from .env
              └────────────┬─────────────┘
                           ▼
              ┌──────────────────────────┐
              │  VulnerabilityService    │  orchestrates, merges, de-duplicates
              └──┬──────────┬─────────┬──┘
                 │          │         │
         ┌───────▼──┐ ┌─────▼────┐ ┌──▼───────┐       ┌──────────────────┐
         │OsvClient │ │NvdClient │ │KevClient │──────▶│ version_matcher  │ (pure functions)
         └───┬──────┘ └───┬──────┘ └───┬──────┘       └──────────────────┘
             │            │ RateLimiter│
             └─────┬──────┴────────────┘
                   ▼
          cached_fetch() ──▶ SqliteCache (cache/retrieval.sqlite3)
                   │
                   ▼  with_retries()
             requests.Session ──▶ api.osv.dev · services.nvd.nist.gov · cisa.gov
```

### 3.1 Files
| File | Responsibility | Depends on |
|------|----------------|------------|
| `__init__.py` | `retrieve(extraction)`: wires the real objects together and calls the service | all |
| `vulnerability_models.py` | Pydantic models, `severity_from_score()`, `severity_from_label()` | pydantic |
| `version_matcher.py` | `parse_version()`, `is_affected()`, `fixed_versions()`, `lowest_fix()` | packaging |
| `cache.py` | `SqliteCache`, `cached_fetch()` | sqlite3, json |
| `rate_limiter.py` | `RateLimiter`, `with_retries()`, `RetrievalError` | requests (exceptions only) |
| `osv_client.py` | `OsvClient.query_package()`, `OsvClient.get_vuln()` | cache, rate_limiter |
| `nvd_client.py` | `NvdClient.get_cve()` → `NvdCve` | cache, rate_limiter |
| `kev_client.py` | `KevClient.is_exploited()` | cache, rate_limiter |
| `vulnerability_service.py` | `VulnerabilityService.retrieve()` | all clients, version_matcher, models |

---

## 4. Data contracts

### 4.1 Input (from Task 1, proposal §2.2.1)
```json
{
  "source_type": "raw-log",
  "packages": [
    { "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "ecosystem": "Maven" }
  ],
  "cve_ids": [],
  "advisory_ids": [],
  "extraction_method": "regex",
  "raw_text": "..."
}
```
- `ecosystem` ∈ `PyPI | npm | Maven | unknown`. Packages marked `unknown` are skipped with a warning, because OSV needs an ecosystem.
- Missing lists are treated as empty.

### 4.2 Output (to Task 3, *proposed, needs agreement with Fouzi*)
```python
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "PENDING"]

class VulnerabilityRecord(BaseModel):
    id: str                        # "CVE-2021-44228", or "GHSA-…"/"PYSEC-…" when no CVE alias
    aliases: list[str]             # other IDs for the same issue (GHSA, PYSEC, …)
    package_name: str | None       # None when the CVE came only from cve_ids
    ecosystem: str | None
    installed_version: str | None
    affected: bool | None          # True / False / None = version unknown
    summary: str                   # NVD English description, else OSV summary/details
    cvss_score: float | None
    severity: Severity
    cwes: list[str]                # ["CWE-502"]; NVD placeholders such as "NVD-CWE-noinfo" are removed
    fixed_versions: list[str]      # every fixed version OSV lists for this package
    in_kev: bool
    sources: list[str]             # canonical pages that back the record (section 7.4)

class RetrievalResult(BaseModel):
    records: list[VulnerabilityRecord]       # sorted by cvss_score, highest first (None last)
    recommended_upgrades: dict[str, str]     # package_name → lowest version fixing all its vulns
    incomplete: bool                         # True if any data is stale or missing
    warnings: list[str]                      # human-readable explanations
```

**How the records map onto the Neo4j schema (proposal Table 4)**
| Record field | Graph element |
|---|---|
| `package_name`, `ecosystem` | `(:Package {key, name, ecosystem})` |
| `installed_version` + `affected=True` | `(:Package)-[:HAS_VERSION]->(:Version)-[:AFFECTED_BY]->(:Vulnerability)` |
| `id`, `summary`, `cvss_score`, `severity`, `in_kev` | `(:Vulnerability)` properties |
| `cwes` | `(:Vulnerability)-[:HAS_WEAKNESS]->(:Weakness {cwe_id})` |
| `fixed_versions` | `(:Vulnerability)-[:FIXED_IN]->(:Version)` |
| `aliases` | `(:Advisory {id})-[:ALIAS_OF]->(:Vulnerability)` |
| `sources` | `(:Vulnerability)-[:DESCRIBED_BY]->(:Source {url})` |

---

## 5. External APIs

| Source | Call | Used fields |
|--------|------|-------------|
| **OSV query** | `POST https://api.osv.dev/v1/query` body `{"package": {"name", "ecosystem"}, "version"}` (`version` omitted when null) | `vulns[]`, `next_page_token` |
| **OSV vuln** | `GET https://api.osv.dev/v1/vulns/{id}` | `id`, `aliases`, `summary`, `details`, `affected[].package`, `affected[].ranges[].{type, events}`, `affected[].versions`, `database_specific.severity`, `database_specific.cwe_ids` |
| **NVD CVE** | `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}`, header `apiKey` when set | `vulnerabilities[0].cve.descriptions[lang=en]`, `metrics.cvssMetricV31 / V30 / V2[].cvssData.baseScore` (prefer `type: "Primary"`), `weaknesses[].description[].value` |
| **CISA KEV** | `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | `vulnerabilities[].cveID` |

Notes
- OSV may page large results with `next_page_token`. The client follows it until it is empty.
- OSV has no published rate limit, so OSV calls only use `with_retries()`. NVD calls also go through the `RateLimiter`.
- NVD returns `totalResults: 0` for an unknown CVE. `get_cve()` returns `None`, which is not an error.

---

## 6. Version matching

### 6.1 Parsing (`parse_version(version, ecosystem)`)
| Ecosystem | Rule |
|-----------|------|
| PyPI | `packaging.version.Version` (full PEP 440: `2.10 > 2.9`, `1.0rc1 < 1.0`) |
| npm | semver: `MAJOR.MINOR.PATCH[-prerelease]`. Compare the numbers; a pre-release sorts before its release. |
| Maven | Split on `.` and `-`. Numeric parts are compared as integers. A qualifier (`alpha`, `beta`, `milestone`, `rc`, `cr`, `snapshot`) sorts before the release. Missing parts count as 0 (`2.0 == 2.0.0`). |

npm and Maven both become a comparable tuple `(numbers…, is_release, qualifier)`. That is simple and good
enough for the versions in our fixtures and demo. Edge cases beyond that are listed in section 11.

### 6.2 `is_affected(version, affected_entry, ecosystem) -> bool`
An OSV `affected` entry is affected if **either** of these is true:
1. `version` is in the explicit `versions` list, **or**
2. for any range with `type` `ECOSYSTEM` or `SEMVER` (`GIT` ranges are ignored), OSV's reference algorithm says so:
   - **sort the events by version first**: the OSV schema does not require them to be in order. `introduced: "0"` means "from the start" and sorts first.
   - start with `affected = False` and step through the sorted events:
     - `introduced: X` with `X <= v` → `affected = True`
     - `fixed: Y` with `Y <= v` → `affected = False` (so the fixed version itself is not affected)
     - `last_affected: Y` with `Y < v` → `affected = False` (so Y itself is still affected)
   - the value left at the end is the answer. A range that is never closed means "affected in every later version".

### 6.3 `lowest_fix(installed, affected_entries, ecosystem) -> str | None`
- `affected_entries` holds the OSV `affected` entry for this package from each vulnerability.
- **Candidates** are all fixed versions (from `fixed_versions()`) **greater than `installed`**. This skips
  backport branches below the installed version.
- Try the candidates from lowest to highest. The answer is the **first candidate that `is_affected()` clears for
  every vulnerability**. Checking each candidate against the full ranges matters when fixes sit on different
  release branches: a version that fixes one vulnerability can still be inside another's range.
- A vulnerability with no fixed version above `installed` can't be fixed by upgrading. It is left out of the
  check and the service adds a warning. If no candidate clears everything, the answer is `None`.

Worked example (log4j-core 2.14.1, each CVE affects `[2.0-beta9, a)`, `[2.4, b)` and `[2.13.0, c)`):
| CVE | Fixed versions a, b, c | Fixed versions > 2.14.1 |
|-----|------------------------|-------------------------|
| CVE-2021-44228 | 2.3.1, 2.12.2, 2.15.0 | 2.15.0 |
| CVE-2021-45046 | 2.3.1, 2.12.2, 2.16.0 | 2.16.0 |
| CVE-2021-45105 | 2.3.1, 2.12.3, 2.17.0 | 2.17.0 |
| CVE-2021-44832 | 2.3.2, 2.12.4, 2.17.1 | 2.17.1 |
| **Result** | 2.15.0, 2.16.0 and 2.17.0 are each still inside a later CVE's range | **2.17.1** |

From 2.11.0 the same data gives **2.12.4**, because the 2.12 branch fixes for all four CVEs are above 2.11.0.

---

## 7. Service logic (`VulnerabilityService.retrieve`)

### 7.1 Steps
1. **Packages.** For each package with a known ecosystem, call `osv.query_package(name, ecosystem, version)`.
   For each OSV vuln, find the `affected` entry for this package, then:
   - if there is a version, call `is_affected()`. Drop the vuln if the answer is False; this double-checks OSV.
   - if there is no version, set `affected = None`.
   - collect `fixed_versions` from that entry's `fixed` events.
2. **Advisory IDs.** For each `advisory_id`, call `osv.get_vuln(id)` and add it the same way, without package or version data unless the OSV entry names exactly one package.
3. **CVE IDs from the input.** Make sure a record exists for each one (package fields `None`).
4. **Key and merge.** A record's key is its first CVE alias in sorted order, or the OSV ID if it has none. If two OSV entries share a key (for example the GHSA and PYSEC entries for the same CVE), merge their aliases and fixed versions and keep the first summary.
5. **Enrich.** For each key that starts with `CVE-`, call `nvd.get_cve()` and `kev.is_exploited()`.
6. **Severity and sources** (sections 7.3 and 7.4).
7. **Upgrades.** For each package, `lowest_fix()` over the OSV `affected` entries of its affected records. Add a warning for each vulnerability that has no fix above the installed version.
8. Sort the records and return a `RetrievalResult`.

### 7.2 Error handling
| Situation | Behaviour |
|-----------|-----------|
| API ok | normal |
| API fails, stale cache exists | use the stale data, `incomplete = True`, warning `"<source> unavailable, using cached data for <key>"` |
| API fails, nothing cached | skip that lookup, `incomplete = True`, warning `"<source> unavailable for <key>"` |
| NVD unknown CVE (`totalResults: 0`) | no enrichment, severity falls back to OSV, no warning |
| Ecosystem `unknown` / unparsable version | skip the package, warning |
| Empty extraction | empty result, no network calls |

### 7.3 Severity
| Score | Label |
|-------|-------|
| `None` | fall back to OSV `database_specific.severity` (`CRITICAL/HIGH/MODERATE→MEDIUM/LOW`), else `PENDING` |
| 0.0 | NONE |
| 0.1 – 3.9 | LOW |
| 4.0 – 6.9 | MEDIUM |
| 7.0 – 8.9 | HIGH |
| 9.0 – 10.0 | CRITICAL |
| < 0 or > 10 | `ValueError` |

CWE fallback: if NVD has no CWE data, use OSV `database_specific.cwe_ids`.

### 7.4 Sources (citation URLs for Task 3's guardrails)
- `https://nvd.nist.gov/vuln/detail/{CVE}` when NVD returned the CVE
- `https://osv.dev/vulnerability/{OSV id}` for every OSV entry merged into the record
- `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` when `in_kev`

---

## 8. Caching, rate limiting and retries

### 8.1 `SqliteCache(path, ttl_seconds=86400, clock=time.time)`
```sql
CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT NOT NULL, fetched_at REAL NOT NULL);
```
| Method | Behaviour |
|--------|-----------|
| `get(key)` | the value if it is younger than the TTL, else `None` |
| `get_stale(key)` | the value however old it is, else `None` |
| `set(key, value)` | stores the JSON with `fetched_at = clock()` (insert or replace) |

Keys: `osv:query:{ecosystem}:{name}:{version or *}`, `osv:vuln:{id}`, `nvd:cve:{id}`, `kev:catalog`.
Default path: `cache/retrieval.sqlite3`, can be overridden with `CVE_CACHE_PATH`. `cache/` is git-ignored.

### 8.2 `cached_fetch(cache, key, fetch) -> (value, is_stale)`
1. Fresh cache hit → `(value, False)`, no network call.
2. Otherwise call `fetch()`. On success, store the value and return `(value, False)`.
3. If `fetch()` raises `RetrievalError` and `get_stale(key)` has a value → `(stale, True)`.
4. Otherwise re-raise `RetrievalError`.

### 8.3 `RateLimiter(max_calls, window_seconds, clock, sleep)`
A sliding window over the timestamps of recent calls. `acquire()` drops timestamps older than the window.
If `max_calls` are still left, it sleeps until the oldest one expires, then records the new call.
NVD: `RateLimiter(50, 30)` with a key, `RateLimiter(5, 30)` without one.

### 8.4 `with_retries(call, sleep, retries=3, base_delay=1.0)`
- Retryable: `requests.ConnectionError`, `requests.Timeout`, HTTP 429, HTTP 5xx.
- Delays: `base_delay * 2**attempt` → 1, 2, 4 s.
- Any other 4xx, or running out of retries → `RetrievalError` with the cause attached.
- Every HTTP call uses `timeout=10`.

---

## 9. Test plan (written before code)

Unit tests live in `tests/unit/` and use no network. Fixtures in `tests/fixtures/t2/` are real API responses,
saved once and trimmed. A `FakeSession` returns the queued responses (or raises) and records each call.
Clocks and `sleep` are fakes, so no test actually waits.

### 9.1 `test_vulnerability_models.py`
| ID | Case | Expect | Req |
|----|------|--------|-----|
| M1 | `severity_from_score` at 0.0 / 0.1 / 3.9 / 4.0 / 6.9 / 7.0 / 8.9 / 9.0 / 10.0 | NONE, LOW, LOW, MEDIUM, MEDIUM, HIGH, HIGH, CRITICAL, CRITICAL | FR10 |
| M2 | score `None` | PENDING | FR10 |
| M3 | score -1 or 10.5 | `ValueError` | FR10 |
| M4 | `severity_from_label("MODERATE")`, `"high"`, `None` | MEDIUM, HIGH, PENDING | FR10 |
| M5 | build a `VulnerabilityRecord`, then `model_dump()` | round-trips to a dict | §4.2 |

### 9.2 `test_version_matcher.py`
| ID | Case | Expect | Req |
|----|------|--------|-----|
| V1 | PyPI `2.10` vs `2.9` | 2.10 > 2.9 (numeric, not string) | FR7 |
| V2 | PyPI 2.10 in `[introduced 0, fixed 2.10.1]` | True; 2.10.1 → False | FR7 |
| V3 | Maven 2.14.1 in `[introduced 2.0-beta9, fixed 2.15.0]` | True; 2.15.0 → False; 2.17.1 → False | FR7 |
| V4 | Maven `2.0-beta9` < `2.0`; `2.0` == `2.0.0` | True | FR7 |
| V5 | npm 4.17.15 in `[introduced 0, fixed 4.17.21]` | True; 4.17.21 → False | FR7 |
| V6 | npm `1.0.0-rc.1` < `1.0.0` | True | FR7 |
| V7 | `last_affected: 1.5` | 1.5 → True, 1.6 → False | FR7 |
| V8 | explicit `versions: ["1.2.3"]`, no ranges | 1.2.3 → True, 1.2.4 → False | FR7 |
| V9 | `introduced` with no closing event | every later version → True | FR7 |
| V10 | two ranges `[1.0,1.5)` and `[2.0,2.5)` | 1.7 → False, 2.1 → True | FR7 |
| V11 | `GIT` range only | False | FR7 |
| V12 | `lowest_fix` for the Log4j entries (§6.3), from 2.14.1 and from 2.11.0 | `"2.17.1"`, `"2.12.4"` | FR8 |
| V13 | `lowest_fix` where no vuln has a fix above installed | `None` | FR8 |
| V14 | `fixed_versions(entry)` | every `fixed` event value | FR8 |
| V15 | events listed out of order (`introduced 1.0, introduced 2.0, fixed 2.5, fixed 1.5`) | 1.2 → True, 1.7 → False | FR7 |
| V16 | `lowest_fix` where the smallest fix of one vuln (2.13.1) is inside another vuln's `[2.13.0, 2.15.0)` | `"2.15.0"` | FR8 |

### 9.3 `test_cache.py`
| ID | Case | Expect | Req |
|----|------|--------|-----|
| C1 | `set` then `get` | same value | NFR1 |
| C2 | `get` of a missing key | `None` | NFR1 |
| C3 | fake clock moves past the TTL | `get` → None, `get_stale` → value | NFR1/2 |
| C4 | close, reopen the same file, `get` | value still there | NFR1 |
| C5 | `cached_fetch` fresh hit | `fetch` not called, `is_stale=False` | NFR1 |
| C6 | `cached_fetch` miss | `fetch` called once, value stored | NFR1 |
| C7 | `cached_fetch`, fetch fails, stale value exists | `(stale, True)` | NFR2 |
| C8 | `cached_fetch`, fetch fails, nothing cached | `RetrievalError` | NFR2 |

### 9.4 `test_rate_limiter.py`
| ID | Case | Expect | Req |
|----|------|--------|-----|
| R1 | 5 calls with a limit of 5 per 30 s | no sleeps | NFR3 |
| R2 | 6th call at t=0 | sleeps 30 s | NFR3 |
| R3 | 6th call at t=31 | no sleep (window expired) | NFR3 |
| R4 | `with_retries`: 503, 503, 200 | returns the 200; sleeps `[1, 2]` | NFR4 |
| R5 | `with_retries`: ConnectionError ×4 | `RetrievalError`; sleeps `[1, 2, 4]` | NFR4 |
| R6 | `with_retries`: 404 | `RetrievalError` straight away, no sleeps | NFR4 |
| R7 | `with_retries`: 429 then 200 | retried once | NFR4 |

### 9.5 `test_osv_client.py`
| ID | Case | Expect | Req |
|----|------|--------|-----|
| O1 | `query_package("…log4j-core", "Maven", "2.14.1")` | POST body has name, ecosystem, version | FR2 |
| O2 | `version=None` | body has no `version` key | FR3 |
| O3 | log4j fixture | vulns with aliases incl. CVE-2021-44228 | FR2 |
| O4 | `next_page_token` on page 1 | page 2 fetched, results combined | FR2 |
| O5 | same query twice | one HTTP call (cache hit) | NFR1 |
| O6 | HTTP fails, stale cache exists | stale data, `is_stale=True` | NFR2 |
| O7 | `get_vuln("GHSA-jfh8-c2jp-5v3q")` | GET `/v1/vulns/GHSA-jfh8-c2jp-5v3q`, aliases incl. CVE-2021-44228 | FR4 |

### 9.6 `test_nvd_client.py`
| ID | Case | Expect | Req |
|----|------|--------|-----|
| N1 | `api_key="k"` | `apiKey: k` header sent | NFR3 |
| N2 | no key | no `apiKey` header | NFR3 |
| N3 | CVE-2021-44228 fixture | score 10.0, `cwes` contains `CWE-502`, English summary | FR5 |
| N4 | metrics only V30 / only V2 | V30 / V2 score used | FR5 |
| N5 | Primary and Secondary V31 metrics | Primary used | FR5 |
| N6 | no metrics | score `None` | FR5/FR10 |
| N7 | `NVD-CWE-noinfo` weakness | filtered out | FR5 |
| N8 | `totalResults: 0` | `None` | FR5 |
| N9 | limiter `acquire()` called on each request | yes | NFR3 |

### 9.7 `test_kev_client.py`
| ID | Case | Expect | Req |
|----|------|--------|-----|
| K1 | CVE-2021-44228 | True | FR6 |
| K2 | CVE-0000-0000 | False | FR6 |
| K3 | ten lookups | one download (cached) | FR6/NFR1 |
| K4 | download fails, nothing cached | `RetrievalError` (the service treats it as not in KEV and warns) | NFR2 |

### 9.8 `test_vulnerability_service.py` (fake clients)
| ID | Case | Expect | Req |
|----|------|--------|-----|
| S1 | Log4Shell extraction (proposal §4.3) | records 44228, 45046, 45105, 44832; all `affected=True` | FR2 |
| S2 | same | 44228: `in_kev=True`, `cvss_score=10.0`, `severity=CRITICAL` | FR5/6/10 |
| S3 | same | `recommended_upgrades["org.apache.logging.log4j:log4j-core"] == "2.17.1"` | FR8 |
| S4 | OSV returns a vuln whose range excludes the version | dropped | FR2 |
| S5 | `version: null` | records have `affected=None` | FR3 |
| S6 | `advisory_ids=["GHSA-jfh8-c2jp-5v3q"]` | record id `CVE-2021-44228`, GHSA in aliases | FR4 |
| S7 | `cve_ids=["CVE-2021-44228"]` alone | record enriched from NVD and KEV | FR5 |
| S8 | same CVE through a package **and** `cve_ids` | exactly one record | FR9 |
| S9 | GHSA and PYSEC entries with the same CVE alias | one record, aliases merged | FR9 |
| S10 | OSV vuln with no CVE alias | record id is the GHSA ID, no NVD call | FR9 |
| S11 | NVD raises | OSV severity label used, `incomplete=True`, warning | NFR2 |
| S12 | OSV returns stale data | `incomplete=True`, warning | NFR2 |
| S13 | ecosystem `unknown` | skipped, warning, no OSV call | §7.2 |
| S14 | empty extraction | empty result, zero client calls | §7.2 |
| S15 | every output ID (`id` + `aliases`) is in the input or in a fake response | True | FR11 |
| S16 | records sorted by score, highest first, `None` last | True | §4.2 |
| S17 | `sources` includes the NVD and OSV URLs, plus the KEV URL when `in_kev` | True | §7.4 |

### 9.9 `tests/integration/test_live.py` (`@pytest.mark.live`, skipped by default)
| ID | Case | Expect |
|----|------|--------|
| L1 | `retrieve()` on the Log4Shell extraction with the real APIs | the 4 CVEs present, 44228 CVSS 10.0 and in KEV, upgrade 2.17.1 |
| L2 | PyPI `jinja2==2.10` | at least one CVE, `affected=True` |

### 9.10 Build order (one Red-Green-Refactor cycle each, two commits per cycle)
models → version_matcher → cache → rate_limiter → osv_client → nvd_client → kev_client → vulnerability_service → `retrieve()` + live tests → `scripts/warm_cache.py`.

---

## 10. Configuration and project files
| Item | Value |
|------|-------|
| `.env` | `NVD_API_KEY=` (optional), `CVE_CACHE_PATH=cache/retrieval.sqlite3` (optional) |
| `requirements.txt` | `requests`, `pydantic>=2`, `packaging`, `python-dotenv`, `pytest` |
| `pytest.ini` | `pythonpath = .`, marker `live`, `addopts = -m "not live"` |
| `.gitignore` | `.env`, `cache/`, `__pycache__/`, `.pytest_cache/` |
| `scripts/warm_cache.py` | runs `retrieve()` over the demo inputs to fill the cache before the demo |

---

## 11. Risks and known limitations
| Risk (proposal ID) | Handling |
|---|---|
| NVD throttling or outage (T2-R1) | API key, rate limiter, backoff, 24 h cache, stale fallback, OSV stays the primary source |
| Wrong range matching (T2-R2) | `packaging` for PyPI; tests V1–V16 cover the demo packages. Maven/npm parsing is simplified: pre-release labels compare as text (`beta10` < `beta9`), `sp` is not ordered after the release, npm build metadata (`+build`) is treated as a pre-release, and Maven variant suffixes like Guava's `-jre`/`-android` are treated as pre-releases, so OSV's own filtering is kept as the first line of defence |
| No CVSS yet (T2-R3) | OSV label fallback, then `PENDING` |
| Backport branches confuse "lowest fix" | only fixed versions above the installed version count, and each candidate is checked against every vulnerability's full ranges (§6.3) |
| Contract drift with Task 1 / Task 3 | the Pydantic models are the contract; Nibir and Fouzi review this spec |
