# Task 2 – Implementation Tasks

Tracks the work in [task2-design-spec.md](task2-design-spec.md). Test IDs (M1, V3, …) refer to spec §9.

**Every cycle follows Red → Green → Refactor:**
1. **Red** – write the tests, run `python -m pytest`, and confirm they fail for the right reason (not just a syntax or import error).
   Commit: `test(<module>): <what> (red)`
2. **Green** – write the least code that makes the tests pass, then run the full suite.
   Commit: `feat(<module>): <what> (green)`
3. **Refactor** – clean up names and remove duplication while everything stays green.
   Commit: `refactor(<module>): <what>`, only if something changed.

Mark a box only when its tests are green and committed.

---

## 0. Setup
- [x] Create the `brian` branch
- [x] Write the design spec (`docs/task2-design-spec.md`)
- [x] Write this task list
- [x] Add `requirements.txt` (`requests`, `pydantic>=2`, `packaging`, `python-dotenv`, `pytest`)
- [x] Add `pytest.ini` (`pythonpath = .`, `live` marker, `addopts = -m "not live"`)
- [x] Add `.gitignore` (`.env`, `cache/`, `__pycache__/`, `.pytest_cache/`) and `.env.example`
- [x] Create the empty packages `src/__init__.py`, `src/retrieval/__init__.py` and the folders `tests/unit/`, `tests/fixtures/t2/`
- [x] Add `tests/unit/fakes.py` with `FakeSession`, `FakeResponse`, `FakeClock` and a fake `sleep` that records its calls
- [x] Commit: `chore: project scaffold for task 2`

## 1. Models – `vulnerability_models.py`
- [x] Red: `test_vulnerability_models.py`, cases M1–M5
- [x] Green: `Severity`, `severity_from_score()`, `severity_from_label()`, `VulnerabilityRecord`, `RetrievalResult`
- [x] Refactor (nothing needed: code already small and clear)

## 2. Version matcher – `version_matcher.py`
- [x] Red: parsing, cases V1, V4, V6
- [x] Green: `parse_version()` for PyPI, npm and Maven
- [x] Red: ranges, cases V2, V3, V5, V7–V11
- [x] Green: `is_affected()`
- [x] Red: fixes, cases V12–V14
- [x] Green: `fixed_versions()`, `lowest_fix()`
- [x] Refactor (shared range filter and sort key)
- [x] Review fix, Red: unsorted events (V15), safe `lowest_fix` picks (V16)
- [x] Review fix, Green: sort events per the OSV algorithm; `lowest_fix` takes OSV entries and checks each candidate

## 3. Cache – `cache.py`
- [x] Red: `test_cache.py`, cases C1–C4
- [x] Green: `SqliteCache` (`get`, `get_stale`, `set`)
- [x] Red: cases C5–C8
- [x] Green: `cached_fetch()` and `RetrievalError` (the error lives in `rate_limiter.py` and is imported here)
- [x] Refactor (named TTL constant, documented None = not cached)

## 4. Rate limiter and retries – `rate_limiter.py`
- [x] Red: `test_rate_limiter.py`, cases R1–R3
- [x] Green: `RateLimiter.acquire()`
- [x] Red: cases R4–R7
- [x] Green: `with_retries()`
- [x] Refactor (build the HTTP error once, clearer names)
- [x] Review fix, Red: early wake-up (R8), shared between threads (R9)
- [x] Review fix, Green: re-check after sleeping (`while`), lock around `acquire()`

## 5. Fixtures (real API responses, saved once)
- [x] `osv_query_log4j_core_2.14.1.json`: OSV query for Maven `org.apache.logging.log4j:log4j-core` 2.14.1
- [x] `osv_vuln_GHSA-jfh8-c2jp-5v3q.json`: OSV vuln lookup
- [x] `osv_query_jinja2_2.10.json`: OSV query for PyPI `jinja2` 2.10
- [x] `nvd_CVE-2021-44228.json`: NVD CVE lookup
- [x] `nvd_not_found.json`: NVD response with `totalResults: 0`
- [x] `kev_excerpt.json`: KEV feed trimmed to a few entries, including CVE-2021-44228
- [x] Trim large fields so each file stays readable; sources and trimming rules in `tests/fixtures/t2/README.md`
- [x] Red/Green: `test_fixtures.py` sanity checks (9 tests), incl. real OSV data → 2.14.1 affected, 2.17.1 fixes the 4 demo CVEs, 2.25.4 fixes all 8
- [x] Review fix: `scripts/refresh_fixtures.py` (download + trim, 5 tests); reproduces the committed fixtures exactly

## 6. OSV client – `osv_client.py`
- [x] Red: `test_osv_client.py`, cases O1–O3, O5, O7
- [x] Green: `OsvClient.query_package()`, `OsvClient.get_vuln()` with caching
- [x] Red/Green: paging (O4)
- [x] Red/Green: `RetrievalError.status_code` in `rate_limiter.py` (R10)
- [x] Red/Green: stale fallback (O6), bad JSON → `RetrievalError` (O8), unknown advisory → `None` (O9)
- [x] Refactor (`_post`/`_get` helpers, plainer paging loop)
- [x] Review fixes, Red/Green: empty version = unknown (O10), escaped advisory IDs (O11), paging stops on a repeated token or after 20 pages (O12)

## 7. NVD client – `nvd_client.py`
- [x] Red/Green: request, parsing, cache (N1–N3, N8, N12); a cache hit does not use the rate limit
- [x] Red/Green: score order v3.1 → v4.0 → v3.0 → v2, Primary before Secondary, CWE placeholders dropped (N4–N7, N13)
- [x] Red/Green: limiter on every attempt incl. retries (N9), bad JSON → `RetrievalError` (N10), stale fallback
- [x] N11 decided from NVD's docs: 403 is not retried (status kept); the docs don't name the rate-limit status
- [x] Refactor (shared `read_json()` for OSV and NVD)
- [x] Review fix, Red/Green: parse replies before caching; an unexpected shape → `RetrievalError`, never cached (N14)

## 8. KEV client – `kev_client.py`
- [x] Red/Green: lookup (also lower-case IDs) and daily caching (K1–K3)
- [x] Red/Green: bad JSON and a changed feed format → `RetrievalError`; K4 and stale fallback (K5)
- [x] Refactor (download in its own method)

## 9. Service – `vulnerability_service.py`
- [x] Red/Green: happy path from the real Log4Shell fixture (S1–S3, S16, S17, S20, S21): 8 records, upgrade 2.25.4, per-branch entries merged, PEP 503 names
- [x] Red/Green: advisory IDs, CVE IDs, record keys (S4–S10): one record per vulnerability per package
- [x] Red/Green: failures (S11–S15, S18, S19, S22–S26): stale data, outages skip a source for the request, 4xx = bad input, unknown IDs and versions skipped with warnings
- [x] Refactor: fixture checks use the service's `package_entry` (one merge helper)
- [x] Review fixes, Red/Green: records grouped by ecosystem and version (S27, S28), malformed package entries skipped (S29)

## 10. Entry point – `src/retrieval/__init__.py`
- [ ] Red: `retrieve()` builds the real clients (check the wiring with a fake session, no network)
- [ ] Green: read `.env` (`NVD_API_KEY`, `CVE_CACHE_PATH`), build cache, limiter and clients, call the service. One shared NVD limiter per process; default cache path resolved from the project root
- [ ] Refactor

## 11. Live checks and demo prep
- [ ] `tests/integration/test_live.py`, cases L1–L2 (`python -m pytest -m live`)
- [ ] `scripts/warm_cache.py`: runs the demo inputs to fill the cache
- [ ] Offline check: warm the cache, disconnect from the network, run again, and confirm the results match with `incomplete` set correctly

## 12. Hand-off
- [ ] Every unit test green: `python -m pytest -v`
- [ ] Write the README section "Task 2 – Retrieval" covering usage, `.env` and how to run the tests

---

## Progress
| Module | Tests | Status |
|--------|-------|--------|
| models | M1–M5 | ☑ 24 passing |
| version_matcher | V1–V16 | ☑ 34 passing |
| cache | C1–C8 | ☑ 10 passing |
| rate_limiter | R1–R10 | ☑ 15 passing |
| osv_client | O1–O12 | ☑ 19 passing |
| nvd_client | N1–N14 | ☑ 21 passing |
| kev_client | K1–K5 | ☑ 9 passing |
| vulnerability_service | S1–S29 | ☑ 35 passing |
| fixtures | sanity + refresh script | ☑ 14 passing |
| live | L1–L2 | ☐ |
