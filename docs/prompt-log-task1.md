# Task 1 – Prompt log (Nibir Nandi Dibbo)

Evidence for the final report: every prompt given to Claude Code, what it produced, and how it was checked.
Spec: `docs/task1-brief.md`.

---

## Step 1 – Regex + schema (2026-11-28)

**Prompt**
> Read docs/task1-brief.md. On a new branch nibir, build src/parser/schema.py and src/parser/patterns.py
> (rules 1, 2 and 5). Create the fixtures log4shell.log, pip_audit.txt (real pip-audit output, see the brief)
> and the extras, write tests, run them and fix failures. Then append to docs/prompt-log-task1.md and commit.
> PROCEED consider all angles about this task since i have no background knowledge about this, and make sure
> you finish it in a way that doesn't contradict future improvements and other codes.

**Files**
- `src/parser/schema.py` – `Package`, `Extraction` (+ `to_dict()`): the output contract shared with Task 2.
- `src/parser/patterns.py` – `find_ids`, `find_packages`, `maven_name`, `name_appears_in`.
- `src/parser/__init__.py` – package docstring; `extract()` comes in Prompt 5.
- `tests/fixtures/t1/` – `log4shell.log` (proposal 4.3), `pip_audit.txt` + `pip_audit.json` (real pip-audit 2.10.1
  output for `jinja2==2.10`), `jackson_note.txt`, `requirements.txt`, `npm_note.txt`, `cve_only.txt`,
  `java_stacktrace.log`, `README.md`.
- `tests/unit/test_parser.py` – 23 tests.
- `docs/task1-brief.md` – updated with what this step found (below).

**Checks**
- The demo outputs are compared with Task 2's own `DEMO_INPUTS` (`scripts/warm_cache.py`), so Task 1 cannot drift
  from what Task 2 expects.
- Full suite: **234 passed** (211 Task 2 + 23 Task 1).

**What had to be fixed or decided**
- Real pip-audit output repeats some rows → results are de-duplicated (6 unique PYSEC IDs from 12 rows).
- GHSA IDs keep a lower-case body (`GHSA-jfh8-c2jp-5v3q`); upper-casing them would break OSV lookups. Brief corrected.
- A line like `Fixed 2.0 CVE-2021-1234` looked like a pip-audit row → rows are trusted only with the table header or a
  PYSEC ID.
- Edge-case probe: `requests[security]==2.19.0` was missed → pin regexes accept extras. The JAR regex was tightened so
  long junk input cannot make it slow (test: < 1 s).
- Known limitation: `dev@1.2.3` is read as an npm package (genuinely ambiguous); Maven `group:artifact:version`
  coordinates are not recognised yet (future work).
- Follow-up for Task 2: the real jinja2 scan includes 6 advisory IDs while `DEMO_INPUTS` has none (see brief,
  "Integration notes").
