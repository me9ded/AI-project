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
- [ ] `nvd_CVE-2021-44228.json`: NVD CVE lookup
- [ ] `nvd_not_found.json`: NVD response with `totalResults: 0`
- [ ] `kev_excerpt.json`: KEV feed trimmed to a few entries, including CVE-2021-44228
- [ ] Trim large fields so each file stays readable. Commit: `test: add task 2 API fixtures`

## 6. OSV client – `osv_client.py`
- [ ] Red: `test_osv_client.py`, cases O1–O8 (O8: bad JSON → `RetrievalError`)
- [ ] Green: `OsvClient.query_package()` (with paging), `OsvClient.get_vuln()`
- [ ] Refactor

## 7. NVD client – `nvd_client.py`
- [ ] Red: `test_nvd_client.py`, cases N1–N11 (N10: bad JSON; N11: confirm NVD's 403 rate-limit answer, retry it)
- [ ] Green: `NvdClient.get_cve()` → `NvdCve(id, summary, cvss_score, cwes)`
- [ ] Refactor

## 8. KEV client – `kev_client.py`
- [ ] Red: `test_kev_client.py`, cases K1–K4
- [ ] Green: `KevClient.is_exploited()`
- [ ] Refactor

## 9. Service – `vulnerability_service.py`
- [ ] Red: happy path, cases S1–S3, S16, S17 (Log4Shell)
- [ ] Green: package flow, NVD/KEV enrichment, severity, sources, upgrades, sorting
- [ ] Red: matching and keys, cases S4–S10
- [ ] Green: version double-check, advisory and CVE inputs, merge/de-duplicate
- [ ] Red: failures and edge cases, cases S11–S15, S18 (stop calling NVD after it gives up), S19 (unparsable version)
- [ ] Green: stale/missing data warnings, skips, empty input, FR11 check
- [ ] Refactor: keep `retrieve()` a short list of named steps

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
- [ ] Share the spec §4.2 record format with Fouzi (Task 3) and the §4.1 input with Nibir (Task 1)
- [ ] Push `brian` and open a PR to `main`, with Mariam reviewing and merging

---

## Progress
| Module | Tests | Status |
|--------|-------|--------|
| models | M1–M5 | ☑ 24 passing |
| version_matcher | V1–V16 | ☑ 34 passing |
| cache | C1–C8 | ☑ 10 passing |
| rate_limiter | R1–R9 | ☑ 12 passing |
| osv_client | O1–O8 | ☐ |
| nvd_client | N1–N11 | ☐ |
| kev_client | K1–K4 | ☐ |
| vulnerability_service | S1–S19 | ☐ |
| live | L1–L2 | ☐ |
