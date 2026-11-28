"""Tests for Task 1 - src/parser (spec: docs/task1-brief.md).

Prompt 1 covers schema.py and patterns.py (the regex layer, no AI).
The expected packages for the demo inputs come from Task 2's DEMO_INPUTS, so these
tests fail if Task 1's output ever stops matching what Task 2 expects.
"""

from pathlib import Path

import pytest
from pydantic import ValidationError

from scripts.warm_cache import DEMO_INPUTS
from src.parser.patterns import find_ids, find_packages, maven_name, name_appears_in
from src.parser.schema import Extraction, Package

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "t1"


def read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def as_dicts(packages: list[Package]) -> list[dict]:
    return [p.model_dump() for p in packages]


# ---------------------------------------------------------------------------
# Schema (the output contract shared with Task 2)
# ---------------------------------------------------------------------------

def test_contract_has_exactly_the_agreed_keys():
    assert set(Extraction().to_dict()) == {
        "source_type", "packages", "cve_ids", "advisory_ids",
        "extraction_method", "raw_text", "ocr_confidence", "warnings",
    }


def test_schema_rejects_values_task2_cannot_use():
    with pytest.raises(ValidationError):
        Package(name="x", version="1", ecosystem="Go")          # unsupported ecosystem
    with pytest.raises(ValidationError):
        Extraction(extraction_method="guess")                    # unknown method
    with pytest.raises(ValidationError):
        Extraction(confidence=0.9)                                # typo'd field is not silently ignored


# ---------------------------------------------------------------------------
# Demo inputs (must match Task 2's DEMO_INPUTS)
# ---------------------------------------------------------------------------

def test_log4shell_log_matches_task2_demo_input():
    text = read("log4shell.log")
    packages, warnings = find_packages(text)
    assert as_dicts(packages) == DEMO_INPUTS["Log4Shell log line"]["packages"]
    assert find_ids(text) == ([], [])          # the log has no CVE number, and none is invented
    assert warnings == []


def test_pip_audit_table_matches_task2_demo_input():
    text = read("pip_audit.txt")
    packages, _ = find_packages(text)
    assert as_dicts(packages) == DEMO_INPUTS["pip-audit screenshot"]["packages"]
    cve_ids, advisory_ids = find_ids(text)
    assert cve_ids == []
    # pip-audit prints some rows twice; each ID appears once, in order of first appearance
    assert advisory_ids == [
        "PYSEC-2021-66", "PYSEC-2019-217", "PYSEC-2026-1473",
        "PYSEC-2026-1474", "PYSEC-2026-1475", "PYSEC-2026-1471",
    ]


def test_jackson_note_needs_the_llm():
    text = read("jackson_note.txt")
    assert find_packages(text) == ([], [])     # regex finds nothing, so Prompt 4's LLM fallback runs
    assert find_ids(text) == ([], [])          # "CVE-2017-something" is not a complete ID


# ---------------------------------------------------------------------------
# Extra cases
# ---------------------------------------------------------------------------

def test_requirements_file_pins():
    packages, _ = find_packages(read("requirements.txt"))
    assert as_dicts(packages) == [
        {"name": "jinja2", "version": "2.10", "ecosystem": "PyPI"},
        {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI"},
    ]                                           # "Flask>=2.0" is a range, not a version: skipped


def test_npm_note_with_scoped_package_and_cve():
    text = read("npm_note.txt")
    packages, _ = find_packages(text)
    assert as_dicts(packages) == [
        {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
        {"name": "@angular/core", "version": "11.0.0", "ecosystem": "npm"},
    ]
    assert find_ids(text) == (["CVE-2020-8203"], [])


def test_ids_only_text():
    text = read("cve_only.txt")
    assert find_packages(text) == ([], [])
    assert find_ids(text) == (["CVE-2021-44228", "CVE-2021-45046"], ["GHSA-jfh8-c2jp-5v3q"])


def test_unknown_java_library_is_kept_but_flagged():
    packages, warnings = find_packages(read("java_stacktrace.log"))
    assert as_dicts(packages) == [
        {"name": "com.fasterxml.jackson.core:jackson-databind", "version": "2.9.8", "ecosystem": "Maven"},
        {"name": "commons-text", "version": "1.9", "ecosystem": "unknown"},
    ]
    assert len(warnings) == 1 and "commons-text" in warnings[0]


@pytest.mark.parametrize("text", ["", None, "   \n  "])
def test_empty_input(text):
    assert find_packages(text) == ([], [])
    assert find_ids(text) == ([], [])


def test_ids_are_normalised():
    cve_ids, advisory_ids = find_ids("cve-2021-44228 ghsa-JFH8-C2JP-5V3Q pysec-2021-66 CVE-2021-44228")
    assert cve_ids == ["CVE-2021-44228"]
    assert advisory_ids == ["GHSA-jfh8-c2jp-5v3q", "PYSEC-2021-66"]  # GHSA body stays lower-case for OSV


def test_random_log_line_is_not_a_pip_audit_row():
    # looks like "name version ID" but has no pip-audit header and no PYSEC ID
    assert find_packages("Fixed 2.0 CVE-2021-1234 last week") == ([], [])


@pytest.mark.parametrize("text, expected", [
    ("requests[security]==2.19.0", ("requests", "2.19.0", "PyPI")),               # pip extras
    (r"C:\app\lib\log4j-core-2.14.1.jar", ("org.apache.logging.log4j:log4j-core", "2.14.1", "Maven")),
    ("lib/log4j-api-2.17.1-SNAPSHOT.jar", ("org.apache.logging.log4j:log4j-api", "2.17.1-SNAPSHOT", "Maven")),
    ("jinja2 2.10 PYSEC-2019-217 2.10.1", ("jinja2", "2.10", "PyPI")),              # OCR'd row, header lost
    ("jinja2==2.10\r\n", ("jinja2", "2.10", "PyPI")),                              # Windows line endings
])
def test_single_package_variants(text, expected):
    packages, _ = find_packages(text)
    assert [(p.name, p.version, p.ecosystem) for p in packages] == [expected]


def test_long_junk_input_is_fast():
    import time
    junk = "a-" + ".1" * 5000 + " " + "x" * 100_000 + " lib-" + "1." * 3000 + "1x"
    start = time.perf_counter()
    find_packages(junk)
    find_ids(junk)
    assert time.perf_counter() - start < 1.0


def test_version_at_end_of_sentence():
    packages, _ = find_packages("Please upgrade from jinja2==2.10.")
    assert as_dicts(packages) == [{"name": "jinja2", "version": "2.10", "ecosystem": "PyPI"}]


def test_maven_lookup():
    assert maven_name("log4j-core") == "org.apache.logging.log4j:log4j-core"
    assert maven_name("Jackson-Databind") == "com.fasterxml.jackson.core:jackson-databind"
    assert maven_name("commons-text") is None


# ---------------------------------------------------------------------------
# Guardrail helper (used by the LLM fallback in Prompt 4)
# ---------------------------------------------------------------------------

def test_name_appears_in_text():
    note = read("jackson_note.txt")
    assert name_appears_in("jackson-databind", note)
    assert name_appears_in("com.fasterxml.jackson.core:jackson-databind", note)
    assert not name_appears_in("spring-core", note)   # an invented package is rejected
    assert not name_appears_in("", note)


# ---------------------------------------------------------------------------
# Prompt 2: format detection (detect.py) and the pip-audit JSON reader (scanners.py)
# ---------------------------------------------------------------------------

import json  # noqa: E402

from src.parser.detect import detect  # noqa: E402
from src.parser.scanners import parse_pip_audit  # noqa: E402

JINJA2_PYSEC_IDS = [
    "PYSEC-2021-66", "PYSEC-2019-217", "PYSEC-2026-1473",
    "PYSEC-2026-1474", "PYSEC-2026-1475", "PYSEC-2026-1471",
]


@pytest.mark.parametrize("fixture, kind", [
    ("pip_audit.json", "pip-audit-json"),
    ("pip_audit.txt", "text"),
    ("log4shell.log", "text"),
    ("jackson_note.txt", "text"),
    ("npm_note.txt", "text"),
])
def test_detect_fixtures(fixture, kind):
    assert detect(read(fixture)).kind == kind


@pytest.mark.parametrize("text", ["", None, "  ", "{not json", '{"a": 1}', "[1, 2, 3]", '"just a string"'])
def test_detect_non_scanner_input_is_text(text):
    assert detect(text) == ("text", None)


@pytest.mark.parametrize("report", [
    {"auditReportVersion": 2, "vulnerabilities": {"lodash": {"name": "lodash", "range": "<=4.17.20"}}},  # npm 7+
    {"advisories": {"1523": {"module_name": "lodash"}}, "actions": []},                                 # npm 6
])
def test_detect_npm_audit(report):
    assert detect(json.dumps(report)).kind == "npm-audit-json"


def test_detect_json_pasted_after_the_command():
    pasted = "$ pip-audit -r requirements.txt -f json\n" + read("pip_audit.json")
    assert detect(pasted).kind == "pip-audit-json"


def test_detect_old_pip_audit_list_format():
    old = [{"name": "jinja2", "version": "2.10", "vulns": [{"id": "PYSEC-2019-217", "aliases": []}]}]
    found = detect(json.dumps(old))
    assert found.kind == "pip-audit-json" and found.data == {"dependencies": old}


def test_pip_audit_json_matches_task2_demo_input():
    result = parse_pip_audit(detect(read("pip_audit.json")).data)
    assert as_dicts(result.packages) == DEMO_INPUTS["pip-audit screenshot"]["packages"]  # markupsafe (no vulns) left out
    assert result.source_type == "pip-audit" and result.extraction_method == "parser"
    assert result.advisory_ids == JINJA2_PYSEC_IDS          # same IDs as the table: no GHSA/SNYK aliases
    assert result.cve_ids == [
        "CVE-2020-28493", "CVE-2019-10906", "CVE-2024-22195",
        "CVE-2024-34064", "CVE-2024-56326", "CVE-2025-27516",
    ]
    assert result.warnings == []


def test_json_and_table_versions_of_a_scan_agree():
    from_json = parse_pip_audit(detect(read("pip_audit.json")).data)
    table = read("pip_audit.txt")
    assert from_json.packages == find_packages(table)[0]
    assert from_json.advisory_ids == find_ids(table)[1] == JINJA2_PYSEC_IDS


def test_pip_audit_json_odd_entries_do_not_crash():
    data = {"dependencies": [
        "not a dict",
        {"version": "1.0", "vulns": []},                                          # no name
        {"name": "privatepkg", "skip_reason": "Dependency not found on PyPI"},     # pip-audit could not check it
        {"name": "Clean-Pkg", "version": "1.0", "vulns": []},                     # no vulns: not a finding
        {"name": "Odd", "version": "2.0", "vulns": [
            {"id": "SNYK-PYTHON-ODD-1", "aliases": ["GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"]},
            "not a dict",
        ]},
        {"name": "noversion", "vulns": [{"id": "PYSEC-2020-1", "aliases": None}]},
    ]}
    result = parse_pip_audit(data)
    assert as_dicts(result.packages) == [
        {"name": "odd", "version": "2.0", "ecosystem": "PyPI"},
        {"name": "noversion", "version": None, "ecosystem": "PyPI"},
    ]
    assert result.cve_ids == ["CVE-2021-44228"]
    assert result.advisory_ids == ["GHSA-jfh8-c2jp-5v3q", "PYSEC-2020-1"]  # GHSA alias used: SNYK ID not recognised
    assert any("privatepkg" in w for w in result.warnings)
    assert any("without a package name" in w for w in result.warnings)


@pytest.mark.parametrize("data", [None, [], {}, {"dependencies": "oops"}])
def test_pip_audit_json_without_dependencies(data):
    result = parse_pip_audit(data)
    assert result.packages == [] and result.cve_ids == [] and result.advisory_ids == []
    assert result.warnings


# ---------------------------------------------------------------------------
# Prompt 3: screenshot OCR (ocr.py)
# The pure helpers are tested without EasyOCR; the real-screenshot test runs only when
# EasyOCR and its downloaded models are available (about 10 s on CPU).
# ---------------------------------------------------------------------------

import importlib.util  # noqa: E402
import io  # noqa: E402

from PIL import Image  # noqa: E402

from src.parser import ocr  # noqa: E402

EASYOCR_READY = importlib.util.find_spec("easyocr") is not None and all(
    (Path.home() / ".EasyOCR" / "model" / name).exists() for name in ("craft_mlt_25k.pth", "english_g2.pth")
)


def test_importing_the_parser_does_not_load_easyocr():
    import subprocess
    import sys
    code = "import sys, src.parser, src.parser.ocr; print('easyocr' in sys.modules or 'torch' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"   # heavy libraries load only when a screenshot is read


def test_preprocess_inverts_dark_mode_and_upscales_small_images():
    dark_small = Image.new("RGB", (500, 100), (12, 12, 12))
    prepared = ocr.preprocess(dark_small)
    assert prepared.mode == "L" and prepared.size == (1000, 200)   # greyscale, x2
    assert prepared.getpixel((0, 0)) > 200                         # dark background became light
    light_large = Image.new("RGB", (1200, 100), (250, 250, 250))
    assert ocr.preprocess(light_large).size == (1200, 100)        # wide enough: not upscaled


def test_load_image_accepts_path_bytes_and_pil():
    path = FIXTURES / "pip_audit_dark.png"
    assert ocr.load_image(path).size == ocr.load_image(path.read_bytes()).size
    pil = Image.new("L", (10, 10))
    assert ocr.load_image(pil) is pil


@pytest.mark.parametrize("bad", [b"not an image", 42, FIXTURES / "log4shell.log"])
def test_load_image_rejects_non_images(bad):
    with pytest.raises(ValueError):
        ocr.load_image(bad)


def test_rebuild_lines_orders_boxes_like_the_screen():
    def box(x, y, text):                       # a 40 x 20 px box at (x, y)
        return ([[x, y], [x + 40, y], [x + 40, y + 20], [x, y + 20]], text, 0.9)
    boxes = [box(120, 52, "PYSEC-2021-66"), box(0, 0, "Name"), box(0, 50, "jinja2"), box(60, 1, "Version"),
             box(60, 49, "2.10")]
    assert ocr.rebuild_lines(boxes) == "Name Version\njinja2 2.10 PYSEC-2021-66"


@pytest.mark.parametrize("raw, fixed", [
    ("jinja2 2.l0 PYSEC-2O19-2l7", "jinja2 2.10 PYSEC-2019-217"),
    ("see CVE-2O21-44228", "see CVE-2021-44228"),
    ("log4j-core-2.l4.1.jar", "log4j-core-2.14.1.jar"),
    ("GHSA-jfh8-c2jp-5v3q", "GHSA-jfh8-c2jp-5v3q"),         # GHSA letters are real: untouched
    ("Hello world. Look at lol.", "Hello world. Look at lol."),  # ordinary words: untouched
])
def test_fix_lookalikes(raw, fixed):
    assert ocr.fix_lookalikes(raw) == fixed


def test_missing_easyocr_gives_a_clear_error(monkeypatch):
    import sys
    ocr.get_reader.cache_clear()
    monkeypatch.setitem(sys.modules, "easyocr", None)    # makes `import easyocr` fail
    try:
        with pytest.raises(ocr.OcrUnavailable, match="pip install"):
            ocr.get_reader()
    finally:
        ocr.get_reader.cache_clear()


@pytest.mark.skipif(not EASYOCR_READY, reason="EasyOCR or its models are not installed")
def test_dark_screenshot_matches_the_text_version():
    text, confidence = ocr.image_to_text(FIXTURES / "pip_audit_dark.png")
    assert confidence >= ocr.LOW_CONFIDENCE
    packages, _ = find_packages(text)
    assert as_dicts(packages) == DEMO_INPUTS["pip-audit screenshot"]["packages"]
    assert find_ids(text) == find_ids(read("pip_audit.txt")) == ([], JINJA2_PYSEC_IDS)


@pytest.mark.skipif(not EASYOCR_READY, reason="EasyOCR or its models are not installed")
def test_blank_image_gives_no_text():
    buffer = io.BytesIO()
    Image.new("RGB", (400, 100), (255, 255, 255)).save(buffer, format="PNG")
    assert ocr.image_to_text(buffer.getvalue()) == ("", 0.0)


# ---------------------------------------------------------------------------
# Prompt 4: LLM fallback (llm_fallback.py)
# Most tests replace Ollama with a fake `chat` function, so they are fast and always run.
# One test uses the real local model and is skipped when Ollama or the model is missing.
# ---------------------------------------------------------------------------

from src.parser import llm_fallback  # noqa: E402
from src.parser.llm_fallback import find_packages_with_llm  # noqa: E402


class FakeChat:
    """Plays back prepared model replies and records what was sent."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, messages, schema):
        self.calls.append((messages, schema))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply if isinstance(reply, str) else json.dumps(reply)


JACKSON_REPLY = {"packages": [{"name": "jackson-databind", "version": "2.9.8", "ecosystem": "Maven"}]}


def test_llm_finds_jackson_and_maps_the_maven_name():
    packages, warnings = find_packages_with_llm(read("jackson_note.txt"), chat=FakeChat(JACKSON_REPLY))
    assert as_dicts(packages) == DEMO_INPUTS["Jackson databind note"]["packages"]
    assert warnings == []


def test_llm_invented_package_is_dropped():
    reply = {"packages": [
        {"name": "jackson-databind", "version": "2.9.8", "ecosystem": "Maven"},
        {"name": "spring-core", "version": "5.0.0", "ecosystem": "Maven"},   # not in the note: invented
    ]}
    packages, warnings = find_packages_with_llm(read("jackson_note.txt"), chat=FakeChat(reply))
    assert as_dicts(packages) == DEMO_INPUTS["Jackson databind note"]["packages"]
    assert any("spring-core" in w and "does not appear" in w for w in warnings)


def test_llm_cannot_add_vulnerability_ids():
    # the model sneaks in IDs: they are ignored, because the answer schema has no ID field
    reply = {"packages": JACKSON_REPLY["packages"], "cve_ids": ["CVE-2017-7525"], "advisory_ids": ["GHSA-x"]}
    chat = FakeChat(reply)
    packages, _ = find_packages_with_llm(read("jackson_note.txt"), chat=chat)
    assert as_dicts(packages) == DEMO_INPUTS["Jackson databind note"]["packages"]
    schema = chat.calls[0][1]
    assert set(schema["properties"]) == {"packages"}          # what Ollama is forced to follow


@pytest.mark.parametrize("version, kept", [("2.9.9", None), ("2019", None), ("2.9.8", "2.9.8")])
def test_llm_versions_must_be_real_versions_from_the_text(version, kept):
    text = "old Jackson databind 2.9.8 from 2019"
    reply = {"packages": [{"name": "jackson-databind", "version": version, "ecosystem": "maven"}]}
    packages, warnings = find_packages_with_llm(text, chat=FakeChat(reply))
    assert packages[0].version == kept
    assert (warnings != []) == (kept is None)


def test_llm_bad_answer_is_retried_once_with_the_error():
    chat = FakeChat("this is not json", JACKSON_REPLY)
    packages, warnings = find_packages_with_llm(read("jackson_note.txt"), chat=chat)
    assert len(chat.calls) == 2 and "not valid JSON" in chat.calls[1][0][-1]["content"]
    assert as_dicts(packages) == DEMO_INPUTS["Jackson databind note"]["packages"] and warnings == []


def test_llm_two_bad_answers_give_low_confidence():
    packages, warnings = find_packages_with_llm("some old jackson", chat=FakeChat("nope", '{"packages": "x"}'))
    assert packages == [] and "Low confidence" in warnings[0]


def test_llm_unavailable_does_not_crash():
    packages, warnings = find_packages_with_llm("some old jackson", chat=FakeChat(ConnectionError("refused")))
    assert packages == [] and "unavailable (ConnectionError)" in warnings[0]


def test_llm_normalises_names_ecosystems_and_unknown_java_libraries():
    text = "We use Django 2.2.1, LODASH 4.17.15 and the commons-text library 1.9."
    reply = {"packages": [
        {"name": "Django", "version": "2.2.1", "ecosystem": "python"},
        {"name": "LODASH", "version": "4.17.15", "ecosystem": "JavaScript"},
        {"name": "commons-text", "version": "1.9", "ecosystem": "Java"},
        {"name": "Django", "version": "2.2.1", "ecosystem": "PyPI"},            # duplicate
    ]}
    packages, warnings = find_packages_with_llm(text, chat=FakeChat(reply))
    assert as_dicts(packages) == [
        {"name": "django", "version": "2.2.1", "ecosystem": "PyPI"},
        {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
        {"name": "commons-text", "version": "1.9", "ecosystem": "unknown"},
    ]
    assert any("commons-text" in w for w in warnings)


def test_llm_is_not_called_for_empty_text():
    chat = FakeChat()
    assert find_packages_with_llm("   ", chat=chat) == ([], []) and chat.calls == []


def test_llm_long_input_is_cut():
    chat = FakeChat({"packages": []})
    _, warnings = find_packages_with_llm("x" * 10_000, chat=chat)
    assert len(chat.calls[0][0][1]["content"]) == llm_fallback.MAX_INPUT_CHARS and warnings


def _ollama_model_ready() -> bool:
    try:
        import ollama
        env = llm_fallback.settings()
        model = env.get("OLLAMA_MODEL") or llm_fallback.DEFAULT_MODEL
        client = ollama.Client(host=env.get("OLLAMA_HOST") or None, timeout=5)
        return model in {m.model for m in client.list().models}
    except Exception:
        return False


@pytest.mark.skipif(not _ollama_model_ready(), reason="Ollama is not running or OLLAMA_MODEL is not pulled")
def test_real_llm_reads_the_jackson_note():
    text = read("jackson_note.txt")
    packages, _ = find_packages_with_llm(text)
    assert as_dicts(packages) == DEMO_INPUTS["Jackson databind note"]["packages"]
    assert find_ids(text) == ([], [])       # "CVE-2017-something" never becomes an ID


# ---------------------------------------------------------------------------
# Prompt 5: extract() - the whole pipeline (src/parser/__init__.py)
# The LLM and OCR are replaced by fakes except in the tests marked as needing them.
# ---------------------------------------------------------------------------

from src.parser import extract  # noqa: E402

CONTRACT_KEYS = ["source_type", "packages", "cve_ids", "advisory_ids", "extraction_method"]


@pytest.fixture
def fake_llm(monkeypatch):
    """Replace Ollama: every call returns `reply` and is recorded in `calls`."""
    class Llm:
        reply = {"packages": []}
        calls = []

        def __call__(self, messages, schema):
            self.calls.append(messages)
            return json.dumps(self.reply)
    llm = Llm()
    monkeypatch.setattr(llm_fallback, "ollama_chat", llm)
    return llm


@pytest.fixture
def fake_ocr(monkeypatch):
    """Replace EasyOCR: image_to_text returns (`text`, `confidence`) or raises `error`."""
    class Ocr:
        text, confidence, error = "", 0.9, None

        def __call__(self, image):
            if self.error:
                raise self.error
            return self.text, self.confidence
    fake = Ocr()
    monkeypatch.setattr(ocr, "image_to_text", fake)
    return fake


def test_extract_log4shell_equals_task2_demo_input(fake_llm):
    out = extract(text=read("log4shell.log"))
    assert {k: out[k] for k in CONTRACT_KEYS} == {k: DEMO_INPUTS["Log4Shell log line"][k] for k in CONTRACT_KEYS}
    assert fake_llm.calls == []                       # regex found packages: the LLM is not used


def test_extract_jackson_note_equals_task2_demo_input(fake_llm):
    fake_llm.reply = JACKSON_REPLY
    out = extract(text=read("jackson_note.txt"))
    assert {k: out[k] for k in CONTRACT_KEYS} == {k: DEMO_INPUTS["Jackson databind note"][k] for k in CONTRACT_KEYS}
    assert len(fake_llm.calls) == 1


@pytest.mark.skipif(not EASYOCR_READY, reason="EasyOCR or its models are not installed")
def test_extract_screenshot_equals_task2_demo_input(fake_llm):
    out = extract(image=FIXTURES / "pip_audit_dark.png")
    demo = DEMO_INPUTS["pip-audit screenshot"]
    for key in ["source_type", "packages", "cve_ids", "extraction_method"]:
        assert out[key] == demo[key]
    # The screenshot also shows its advisory IDs; Task 2's DEMO_INPUTS lists none yet (see brief, integration notes).
    assert out["advisory_ids"] == JINJA2_PYSEC_IDS
    assert out["ocr_confidence"] >= ocr.LOW_CONFIDENCE and out["warnings"] == []


@pytest.mark.parametrize("fixture, source_type, method", [
    ("pip_audit.txt", "pip-audit", "regex"),
    ("pip_audit.json", "pip-audit", "parser"),
    ("requirements.txt", "raw-log", "regex"),
    ("npm_note.txt", "raw-log", "regex"),
    ("java_stacktrace.log", "raw-log", "regex"),
])
def test_extract_text_inputs(fake_llm, fixture, source_type, method):
    out = extract(text=read(fixture))
    assert (out["source_type"], out["extraction_method"]) == (source_type, method)
    assert out["packages"] and out["raw_text"] == read(fixture)
    Extraction.model_validate(out)                    # always a valid contract
    assert fake_llm.calls == []


def test_extract_ids_only_text_tries_the_llm_and_keeps_the_ids(fake_llm):
    out = extract(text=read("cve_only.txt"))
    assert len(fake_llm.calls) == 1                   # no packages, so the LLM was asked (and found none)
    assert out["packages"] == [] and out["extraction_method"] == "regex"
    assert out["cve_ids"] == ["CVE-2021-44228", "CVE-2021-45046"]


def test_extract_npm_audit_json_uses_ids_only_and_never_the_llm(fake_llm):
    report = {"auditReportVersion": 2, "vulnerabilities": {"lodash": {
        "name": "lodash", "range": "<=4.17.20",
        "via": [{"title": "Prototype Pollution", "url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"}]}}}
    out = extract(text=json.dumps(report))
    assert out["source_type"] == "npm-audit" and out["packages"] == []
    assert out["advisory_ids"] == ["GHSA-jfh8-c2jp-5v3q"]
    assert "not supported yet" in out["warnings"][0] and fake_llm.calls == []


def test_extract_uploaded_text_files_in_any_encoding(fake_llm):
    expected = extract(text=read("log4shell.log"))["packages"]
    raw = read("log4shell.log")
    for data in (raw.encode("utf-8"), raw.encode("utf-8-sig"), raw.encode("utf-16")):   # utf-16: PowerShell `>`
        assert extract(text=data)["packages"] == expected


def test_extract_with_nothing_given():
    out = extract()
    assert out["packages"] == [] and out["warnings"] == ["No text or screenshot was given."]


def test_extract_bad_image_gives_a_warning_not_a_crash():
    out = extract(image=b"definitely not a picture")
    assert out["source_type"] == "screenshot" and out["packages"] == []
    assert "not a readable PNG or JPG" in out["warnings"][0]


def test_extract_without_easyocr_gives_a_warning(fake_ocr):
    fake_ocr.error = ocr.OcrUnavailable("EasyOCR is not installed. Run: pip install -r requirements.txt")
    out = extract(image=b"png bytes")
    assert out["packages"] == [] and "could not be read" in out["warnings"][0]


def test_extract_low_confidence_screenshot_is_flagged(fake_ocr, fake_llm):
    fake_ocr.text, fake_ocr.confidence = "jinja2 2.10 PYSEC-2019-217 2.10.1", 0.3
    out = extract(image=b"png bytes")
    assert out["packages"] == [{"name": "jinja2", "version": "2.10", "ecosystem": "PyPI"}]
    assert out["ocr_confidence"] == 0.3 and "Low-quality screenshot" in out["warnings"][0]


def test_extract_screenshot_keeps_the_most_common_version(fake_ocr, fake_llm):
    # a real OCR slip seen on a half-size screenshot: one row read as 2.18 instead of 2.10
    fake_ocr.text = read("pip_audit.txt").replace("jinja2 2.10    PYSEC-2019-217", "jinja2 2.18    PYSEC-2019-217", 1)
    out = extract(image=b"png bytes")
    assert out["packages"] == [{"name": "jinja2", "version": "2.10", "ecosystem": "PyPI"}]
    assert any("kept 2.10" in w and "2.18" in w for w in out["warnings"])
    assert out["extraction_method"] == "ocr+regex"


def test_extract_screenshot_falls_back_to_the_llm(fake_ocr, fake_llm):
    fake_ocr.text = read("jackson_note.txt")
    fake_llm.reply = JACKSON_REPLY
    out = extract(image=b"png bytes")
    assert out["extraction_method"] == "ocr+llm"
    assert out["packages"] == DEMO_INPUTS["Jackson databind note"]["packages"]


def test_extract_screenshot_and_text_together(fake_ocr, fake_llm):
    fake_ocr.text = "jinja2 2.10 PYSEC-2019-217 2.10.1"
    out = extract(text="also lodash@4.17.15", image=b"png bytes")
    assert [p["name"] for p in out["packages"]] == ["jinja2", "lodash"]


# Integration: Task 1's real output goes through Task 2's real retrieval code (network answers are faked
# from Task 2's saved fixtures), proving the two tasks fit together.
def test_extract_output_feeds_task2_retrieve(tmp_path, fake_llm):
    from src.retrieval import build_service
    from tests.unit.test_retrieve import RoutingSession, fake_time

    extraction = extract(text=read("log4shell.log"))
    service = build_service(RoutingSession(), {"CVE_CACHE_PATH": str(tmp_path / "c.sqlite3")}, **fake_time())
    result = service.retrieve(extraction)
    records = {record.id: record for record in result.records}
    assert records["CVE-2021-44228"].cvss_score == 10.0 and records["CVE-2021-44228"].in_kev is True
    assert result.recommended_upgrades == {"org.apache.logging.log4j:log4j-core": "2.25.4"}
    assert result.warnings == []
