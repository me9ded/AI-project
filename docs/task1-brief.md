# Task 1 – Input Parsing & Extraction (brief for Claude Code)

**Project:** AI-Powered CVE Tracker, CST8327 Group 5 · **Repo:** `me9ded/AI-project`
**Owner:** Nibir Nandi Dibbo · **Branch:** `nibir` · **Folder:** `src/parser/`
**Source of truth:** the group proposal, sections 2.2.1, 2.2.3, 4.2 (Table 9) and 4.3.
Build the smallest version that does what those sections promise. Do not add anything else.
**Never push to GitHub or open pull requests unless Nibir asks.** Local commits only.

## What Task 1 does
Takes **pasted text** or a **screenshot** and returns a dict with the package names, versions and
vulnerability IDs found in it. Task 2 (`src/retrieval/`, already built by Brian) consumes it with
`retrieve(extraction)`. Task 4 calls `extract()` from `POST /analyze`. Task 3 reuses `find_ids()`.

## Output contract (do not change – Task 2 already depends on it)
```json
{
  "source_type": "pip-audit | npm-audit | raw-log | screenshot",
  "packages": [{"name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "ecosystem": "Maven"}],
  "cve_ids": [],
  "advisory_ids": [],
  "extraction_method": "parser | regex | llm | ocr+regex | ocr+llm",
  "raw_text": "...",
  "ocr_confidence": null,
  "warnings": []
}
```
- `ecosystem` is `PyPI`, `npm`, `Maven` or `unknown` (Task 2 skips `unknown` with a warning).
- `version` may be `null`. PyPI names are lower-case. Lists are de-duplicated, in order of first appearance.
- `ocr_confidence` (0–1, screenshots only) and `warnings` are extra fields for the UI; Task 2 ignores them.
- Pasted text uses `source_type` `pip-audit`, `npm-audit` or `raw-log`; any image uses `screenshot`.

## Files (match proposal Table 9)
| File | Job |
|---|---|
| `src/parser/__init__.py` | `extract(text=None, image=None) -> dict`. `image` may be a file path or raw bytes (FastAPI upload). |
| `src/parser/schema.py` | Pydantic models for the contract above |
| `src/parser/patterns.py` | All regexes, `find_ids(text) -> (cve_ids, advisory_ids)`, `find_packages(text)`, Maven lookup |
| `src/parser/detect.py` | Says if text is pip-audit JSON, npm audit JSON, or free text |
| `src/parser/scanners.py` | Reads pip-audit JSON field by field |
| `src/parser/llm_fallback.py` | Ollama call for messy text |
| `src/parser/ocr.py` | Screenshot → text + mean confidence (EasyOCR) |
| `tests/unit/test_parser.py` | pytest tests |
| `tests/fixtures/t1/` | sample inputs (below) |

Add to `requirements.txt`: `easyocr`, `Pillow`, `numpy`, `ollama`. Do **not** add `opencv-python`
(EasyOCR already installs `opencv-python-headless`; having both breaks imports).

## Rules
1. **Regex first** (`patterns.py`, case-insensitive; CVE/PYSEC IDs in upper case, GHSA as `GHSA-` + lower-case body, because OSV IDs are case-sensitive):
   - CVE: `\bCVE-\d{4}-\d{4,7}\b`
   - GHSA: `\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b` · PYSEC: `\bPYSEC-\d{4}-\d+\b`
   - Python pin: `^\s*([A-Za-z0-9][\w.-]*)\s*==\s*([0-9][^\s;#]*)` → PyPI
   - npm: `((?:@[\w.-]+/)?[\w.-]+)@(\d+\.\d+\.\d+[\w.-]*)` → npm
   - Java JAR: `([A-Za-z][\w.-]*?)-(\d+(?:\.\d+)+)\.jar` → Maven (via the lookup below)
   - pip-audit table row (needed for the screenshot demo): a line `name  version  ID ...` where ID is
     a PYSEC/GHSA/CVE ID, e.g. `jinja2 2.10 PYSEC-... 2.10.1` → PyPI. Skip the header and `---` lines.
     Trust a row only if the `Name Version ID` header is present or the ID is a PYSEC ID (so a random log line is not a row).
     pip-audit prints some rows twice: de-duplicate.
2. **Maven lookup** (JAR artifact → OSV name). Only these are required:
   `log4j-core`, `log4j-api` → `org.apache.logging.log4j:<artifact>`;
   `jackson-databind`, `jackson-core`, `jackson-annotations` → `com.fasterxml.jackson.core:<artifact>`.
   Anything else: keep the artifact name, set ecosystem `unknown`, add a warning.
3. **pip-audit JSON** (`scanners.py`): each item in `dependencies` → package (`name`, `version`, PyPI);
   each `vulns[].id` and `vulns[].aliases` → `cve_ids` / `advisory_ids` (check with the regexes).
   `extraction_method` = `parser`. Include only dependencies that have at least one vuln (the JSON also lists
   clean ones such as `markupsafe`), so the JSON and table versions of a scan give the same packages.
   npm audit JSON is a stretch item: detect it, return regex results,
   and add the warning "npm audit JSON is not supported yet".
4. **LLM only if regex/parser found no packages** (`llm_fallback.py`):
   - `ollama.chat(model=MODEL, format=<JSON schema of {packages:[{name, version, ecosystem}]}>, options={"temperature": 0})`
   - `MODEL` comes from env var `OLLAMA_MODEL`, default `llama3.1:8b`.
   - System prompt: extract only packages and versions that literally appear in the text; use `null`
     for a missing version; for Java libraries give the artifact name (e.g. `jackson-databind`).
   - Validate with Pydantic. If invalid, retry once with the error appended. If it fails again, or Ollama
     is not running, return no packages and add a "low confidence" warning. Never crash.
5. **Guardrails (the most important part):**
   - CVE/GHSA/PYSEC IDs come **only** from the regexes on the original text. The LLM schema has no ID field.
     An incomplete ID like `CVE-2017-something` must not match.
   - Drop any LLM package whose name does not appear in the text. Compare after lower-casing and
     removing spaces, `-`, `_` and `.` (so "Jackson databind" matches `jackson-databind`).
     Do this check **before** the Maven lookup adds the group ID.
6. **OCR** (`ocr.py`): greyscale; upscale ×2 if narrower than 1,500 px; invert if mean brightness < 100;
   `easyocr.Reader(["en"], gpu=False)` created once and reused; `readtext(img, detail=1)`;
   drop boxes with confidence < 0.4; rebuild lines by each box's vertical centre, left to right;
   fix `O→0` and `l/I→1` only inside version-like or ID-like tokens (`2.l4.1 → 2.14.1`).
   Return `(text, mean_confidence)`. Then run rules 1–5 on the text with `extraction_method` `ocr+regex` / `ocr+llm`.
   Add a warning if mean confidence < 0.5.

## Acceptance tests (must pass)
The expected packages are exactly `DEMO_INPUTS` in `scripts/warm_cache.py` (Task 2). Compare against it.

| Fixture in `tests/fixtures/t1/` | Expected |
|---|---|
| `log4shell.log` – the log from proposal 4.3 (JNDI string + `log4j-core-2.14.1.jar`, `log4j-api-2.14.1.jar`) | = DEMO_INPUTS "Log4Shell log line"; no CVE IDs |
| `pip_audit.txt` – real `pip-audit` table output for `jinja2==2.10` | jinja2 2.10 PyPI; advisory IDs = the IDs printed; method `regex` |
| `pip_audit.json` – real `pip-audit -f json` output for the same project | same packages; method `parser` |
| `jackson_note.txt` – "we still run an old Jackson databind, 2.9.8, I think there was a CVE-2017-something" | = DEMO_INPUTS "Jackson databind note"; `cve_ids` empty (skip if Ollama is down) |
| `pip_audit_dark.png` – dark-mode screenshot of `pip_audit.txt` (Nibir adds it) | = DEMO_INPUTS "pip-audit screenshot" |
| 5 small extras: `requirements.txt`, an npm note with `lodash@4.17.15`, a CVE-only line, empty text, a fake package the LLM invents (mocked) | sensible results; the invented package is dropped |
| Integration: `extract(log4shell.log)` fed into `src.retrieval.retrieve` using Task 2's offline fixtures | runs without errors – proves Tasks 1 and 2 fit |

Make real pip-audit output with a throwaway venv: `pip install jinja2==2.10 pip-audit`, then
`pip-audit` and `pip-audit -f json`. Never type advisory IDs by hand.
Tests that need Ollama or EasyOCR models are skipped automatically when they are not available.

## Integration notes
- The real jinja2 scan gives 6 PYSEC `advisory_ids`, but Task 2's `DEMO_INPUTS` has `advisory_ids: []`, so
  `warm_cache.py` does not cache those lookups. After Prompt 5, ask Brian to copy the real `extract()` output
  into `DEMO_INPUTS`, otherwise the offline demo misses them.
- Already built (Prompt 1): `find_ids`, `find_packages`, `maven_name`, `name_appears_in` in `patterns.py`;
  `Package`, `Extraction` (+ `to_dict()`) in `schema.py`. Reuse them; do not duplicate the regexes.

## Recording (required for the report)
After every prompt, append to `docs/prompt-log-task1.md`: the prompt, files changed, test result, and
anything that had to be corrected. Commit after each step on `nibir`, e.g. `feat(parser): regex extractor`.

---

## Prompts for Nibir to paste into Claude Code (one at a time)

**0 – Setup (once).** Install Ollama's model and the libraries:
`ollama pull llama3.1:8b` (on this laptop `llama3.2:3b` is already installed; set `OLLAMA_MODEL=llama3.2:3b` if 8B is too slow).

**Prompt 1 – Regex + schema (~1 h)**
> Read docs/task1-brief.md. On a new branch `nibir`, build src/parser/schema.py and src/parser/patterns.py
> (rules 1, 2 and 5). Create the fixtures log4shell.log, pip_audit.txt (real pip-audit output, see the brief)
> and the extras, write tests, run them and fix failures. Then append to docs/prompt-log-task1.md and commit.

**Prompt 2 – pip-audit JSON (~30 min)**
> Using docs/task1-brief.md, build src/parser/detect.py and src/parser/scanners.py (rule 3).
> Add pip_audit.json from a real pip-audit run, test it, log the step and commit.

**Prompt 3 – Screenshot OCR (~45 min)**
> Using docs/task1-brief.md, build src/parser/ocr.py (rule 6) and add EasyOCR to requirements.txt.
> I will add tests/fixtures/t1/pip_audit_dark.png. Test it, log the step and commit.

**Prompt 4 – LLM fallback (~45 min)**
> Using docs/task1-brief.md, build src/parser/llm_fallback.py (rules 4 and 5) with jackson_note.txt and a
> mocked test where the LLM invents a package. Test it, log the step and commit.

**Prompt 5 – Put it together (~45 min)**
> Using docs/task1-brief.md, build extract() in src/parser/__init__.py: OCR if an image is given, then
> detect → parser or regex → LLM only if no packages. Check every acceptance test against DEMO_INPUTS in
> scripts/warm_cache.py, add the integration test, run the whole test suite (Task 2's tests must still
> pass), log the step and commit. Do not push.
