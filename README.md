# AI-Powered CVE Tracker

CST8327 Section 011, Group 5. A web app that turns scanner output, logs and screenshots
into a grounded vulnerability report (see the group proposal for the full design).

Each task documents its own component below.

---

## Task 1 – Input Parsing & Extraction

Reads pasted text (scanner output, logs, notes) or a **screenshot** and returns the packages,
versions and vulnerability IDs in it, in the format Task 2's `retrieve()` reads.

- Code: [`src/parser/`](src/parser/) · Spec: [`docs/task1-brief.md`](docs/task1-brief.md) ·
  Prompt log: [`docs/prompt-log-task1.md`](docs/prompt-log-task1.md)
- Pipeline: screenshot → EasyOCR → pip-audit JSON parser **or** regex → local LLM (Ollama) only if no
  packages were found. Vulnerability IDs only ever come from the regexes, never from the LLM.

### Setup

```bash
pip install -r requirements.txt        # includes EasyOCR + PyTorch: takes a few minutes
ollama pull llama3.1:8b                # or llama3.2:3b, then set OLLAMA_MODEL in .env
```

`OLLAMA_MODEL`, `OLLAMA_HOST` and `OLLAMA_TIMEOUT` are optional `.env` settings (see `.env.example`).
EasyOCR downloads its models (~100 MB, `~/.EasyOCR`) on first use: run one screenshot online before the demo.

### Usage (Task 4)

```python
from src.parser import extract
from src.parser.ocr import get_reader
from src.retrieval import retrieve

get_reader()                                   # once at start-up: loads the OCR models (~20 s)

extraction = extract(text=pasted_text)         # or text=<uploaded file bytes>
extraction = extract(image=upload_bytes)       # a PNG/JPG path or bytes (~5–10 s on CPU)
result = retrieve(extraction)
```

`extract()` never raises for bad input. Show `extraction["warnings"]` in the UI (e.g. unreadable image,
low OCR confidence via `ocr_confidence`, AI fallback unavailable) and a "nothing found" message when
`packages`, `cve_ids` and `advisory_ids` are all empty.

---

## Task 2 – Retrieval

Looks up the packages and IDs found by Task 1 in **OSV.dev**, **NVD** and the
**CISA KEV** catalog, checks whether the installed version is really affected, and
returns one record per vulnerability for Task 3's Neo4j graph.

- Code: [`src/retrieval/`](src/retrieval/)
- Design and test plan: [`docs/task2-design-spec.md`](docs/task2-design-spec.md)

### Setup

Python 3.11 or newer.

1. Create a virtual environment:
   ```
   python -m venv .venv
   ```
2. Activate it, with the line for your shell:

   | Shell | Command |
   |-------|---------|
   | PowerShell | `.venv\Scripts\Activate.ps1` |
   | Command Prompt | `.venv\Scripts\activate.bat` |
   | Git Bash | `source .venv/Scripts/activate` |
   | macOS / Linux | `source .venv/bin/activate` |

3. Install the dependencies:
   ```
   pip install -r requirements.txt
   ```

Copy `.env.example` to `.env` and fill it in. `.env` is never committed.

| Variable | Default | What it does |
|----------|---------|--------------|
| `NVD_API_KEY` | none | Free key from <https://nvd.nist.gov/developers/request-an-api-key>. Raises NVD's limit from 5 to 50 requests per 30 seconds. |
| `CVE_CACHE_PATH` | `cache/retrieval.sqlite3` | Where the SQLite cache lives. A relative path is resolved from the project folder; `~` means your home folder. |

Real environment variables win over `.env`. Settings are read once per process, so
**restart the app after editing `.env`**.

### Usage

```python
from src.retrieval import retrieve, NVD_NOTICE

extraction = {                      # Task 1's output
    "packages": [{"name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "ecosystem": "Maven"}],
    "cve_ids": [],
    "advisory_ids": [],
}
result = retrieve(extraction)       # RetrievalResult (Pydantic)

for record in result.records:       # highest CVSS score first
    print(record.id, record.severity, record.cvss_score, record.in_kev)
print(result.recommended_upgrades)  # {"org.apache.logging.log4j:log4j-core": "2.25.4"} as of November 2026
print(result.incomplete, result.warnings)

data = result.model_dump()          # plain dict for Task 3 or the API
```

- The record fields and how they map onto the graph are in the spec, section 4.2.
- There is **one record per vulnerability per package version**. CVE and advisory IDs
  only ever come from the input or from OSV/NVD/KEV; nothing is invented.
- `incomplete` is `True` when an API was down and old cached data was used (or an item
  could not be looked up); `warnings` explains what happened.
- **UI (Task 4):** NVD asks apps that use its API to show `NVD_NOTICE`:
  "This product uses data from the NVD API but is not endorsed or certified by the NVD."

### Before the demo: fill the cache

```bash
python scripts/warm_cache.py --check-offline
```

This runs the three demo inputs (Log4Shell log line, pip-audit screenshot with jinja2,
Jackson databind note), stores every API answer in the cache, then runs them again with
no network and checks the answers match. It exits with code 1 and says
"Cache NOT fully filled" if an API failed; run it again when online.

- Cache entries are fresh for 24 hours. After that the app still uses them when the
  network is down, but marks results as incomplete, so **run this on demo day**.
- **Get an NVD key first.** Without one, the Jackson input (about 60 CVEs) takes about
  6 minutes because of NVD's rate limit; with one, about 40 seconds.

### Tests

```bash
python -m pytest            # unit tests: no network, no real waiting (about 5 seconds)
python -m pytest -m live    # live checks against the real APIs (about 1 minute without a key)
```

The unit tests use saved API responses in [`tests/fixtures/t2/`](tests/fixtures/t2/).
To refresh them from the real APIs, run `python scripts/refresh_fixtures.py` and then the
tests; answers that depend on the date (such as the recommended Log4j upgrade) may change.

The component was built test-first (Red → Green → Refactor); the commit history on the
`brian` branch shows each failing test before the code that made it pass.
