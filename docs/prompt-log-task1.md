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

---

## Step 2 – pip-audit JSON reader (2026-11-28)

**Prompt**
> Using docs/task1-brief.md, build src/parser/detect.py and src/parser/scanners.py (rule 3). Add pip_audit.json
> from a real pip-audit run, test it, log the step and commit. PROCEED consider all angles about this task since i
> have no background knowledge about this, and make sure you finish it in a way that doesn't contradict future
> improvements and other codes, and remember this before all of the future tasks.

**Files**
- `src/parser/detect.py` – `detect(text)`: pip-audit JSON, npm audit JSON (npm 6 and 7+) or plain text. Never raises.
- `src/parser/scanners.py` – `parse_pip_audit(data)`: packages with vulns, CVE IDs and advisory IDs from the JSON.
- `tests/unit/test_parser.py` – 23 new tests (46 for Task 1).
- `docs/task1-brief.md` – rule 3 and integration notes updated.
- `pip_audit.json` was already added in step 1 from the same real pip-audit 2.10.1 run, so both fixtures describe
  the same scan.

**Checks**
- The JSON gives exactly Task 2's demo packages (jinja2 2.10) and the same 6 PYSEC IDs as the table version.
- Full suite: **257 passed** (211 Task 2 + 46 Task 1).

**What had to be fixed or decided**
- Read Task 2's `retrieve()` first: CVE IDs merge into existing records at no cost, but each advisory ID costs one
  OSV call. GHSA aliases add no new information (OSV returns them), so only each vuln's own ID is kept: 6 advisory
  IDs instead of 12, and the JSON and screenshot paths now agree.
- The JSON also lists `markupsafe` with no vulns → only packages with vulns are findings.
- Robustness: JSON pasted after the `$ pip-audit ...` command line, the older list format, `skip_reason` entries,
  unknown ID types (SNYK) and broken entries are all handled without crashing.
- npm audit JSON: detected but not parsed (stretch item). Decided for Prompt 5: keep only its IDs and never send
  it to the LLM.
- Saved the "consider all angles, stay compatible" instruction to Claude's memory and to CLAUDE.md.

---

## Step 3 – Screenshot OCR (2026-11-28)

**Prompt**
> Using docs/task1-brief.md, build src/parser/ocr.py (rule 6) and add EasyOCR to requirements.txt. I will add
> tests/fixtures/t1/pip_audit_dark.png. Test it, log the step and commit.

**Files**
- `src/parser/ocr.py` – `image_to_text()`: greyscale → upscale small images → invert dark mode → EasyOCR →
  drop low-confidence boxes → rebuild table lines → fix O/0 and l/1 inside versions and IDs.
- `tests/fixtures/t1/pip_audit_dark.png` – Nibir's dark-mode terminal screenshot of `pip_audit.txt` (demo input 2).
- `requirements.txt` – `easyocr`, `Pillow`, `numpy` (no `opencv-python`, which would clash with EasyOCR's copy).
- `tests/unit/test_parser.py` – 15 new tests (61 for Task 1).

**Checks**
- The screenshot gives exactly the text path's result: jinja2 2.10 (= Task 2's demo input) and the same 6 PYSEC IDs,
  mean confidence 0.90.
- Full suite: **272 passed** (211 Task 2 + 61 Task 1). The real-OCR tests skip automatically on machines without
  EasyOCR models.

**What had to be fixed or decided**
- Measured speed on CPU: model load ~20 s once, then 13 s per screenshot with the proposal's "upscale below
  1,500 px" vs 7 s without, with the same accuracy. A half-size (698 px) copy failed completely without upscaling.
  → threshold lowered to 1,000 px: normal screenshots stay fast, small ones are still rescued.
- The half-size test also misread one row as `jinja2 2.18`. Recorded for Prompt 5: keep the most frequent version
  per package for screenshots, with a warning.
- The digit fix originally skipped versions after a dash (`log4j-core-2.l4.1.jar`) → fixed and tested. GHSA IDs are
  never "fixed", because their letters are real.
- EasyOCR and PyTorch load only when a screenshot is read, so other tasks importing `src.parser` stay fast (tested).
- Team note: `pip install -r requirements.txt` now takes several minutes (PyTorch).
