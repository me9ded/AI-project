"""LLM fallback for messy text (docs/task1-brief.md, rules 4 and 5; proposal section 2.2.1).

find_packages_with_llm(text) -> (packages, warnings)

Used by extract() only when the regex layer and the scanner parsers found no packages.
The model (Llama via Ollama, run locally) is asked for packages ONLY:
- its JSON schema has no field for CVE/GHSA/PYSEC IDs, and any extra fields it adds are ignored;
- every package name must appear in the input text, otherwise it is dropped (anti-hallucination);
- a version that does not appear in the text is removed (set to None);
- if Ollama is not running or answers badly twice, the result is empty with a warning. It never crashes.

Settings (from `.env` or real environment variables, like Task 2):
    OLLAMA_MODEL    default "llama3.1:8b" (e.g. "llama3.2:3b" on a slower laptop)
    OLLAMA_HOST     default http://localhost:11434 (point it at the shared hosted model if needed)
    OLLAMA_TIMEOUT  seconds, default 120
"""

import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from src.parser.patterns import maven_name, name_appears_in
from src.parser.schema import Package

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL = "llama3.1:8b"
MAX_INPUT_CHARS = 4000   # keeps a CPU-only answer to tens of seconds
_YEAR = re.compile(r"(19|20)\d\d")   # "lodash from 2019": the model once returned the year as the version

SYSTEM_PROMPT = """You extract software dependencies from text for a security tool.
Return JSON that matches the schema. Rules:
1. List only packages whose name is written in the text. Never guess or add packages.
2. "version" is the exact version string written for that package in the text, or null if none is written.
   Never invent, complete or correct a version. A year or date (e.g. "from 2019") is not a version.
3. "ecosystem" is "PyPI" for Python, "npm" for JavaScript/Node.js, "Maven" for Java, otherwise "unknown".
4. For Java libraries give only the artifact name in lower case with hyphens, e.g. "jackson-databind".
5. Do not output vulnerability identifiers such as CVE or GHSA numbers.
6. If the text names no packages, return {"packages": []}.

Example
Text: our api still runs Flask 0.12 and the requests lib
JSON: {"packages": [{"name": "flask", "version": "0.12", "ecosystem": "PyPI"},
                    {"name": "requests", "version": null, "ecosystem": "PyPI"}]}"""

ChatFn = Callable[[list[dict], dict], str]   # (messages, json_schema) -> the model's reply text


# ---------------------------------------------------------------------------
# What the model may answer (no ID fields, extra fields ignored)
# ---------------------------------------------------------------------------

_ECOSYSTEMS = {"pypi": "PyPI", "python": "PyPI", "npm": "npm", "node": "npm", "javascript": "npm",
               "maven": "Maven", "java": "Maven"}


class LlmPackage(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    version: str | None = None
    ecosystem: Literal["PyPI", "npm", "Maven", "unknown"] = "unknown"

    @field_validator("ecosystem", mode="before")
    @classmethod
    def _normalise_ecosystem(cls, value):
        return _ECOSYSTEMS.get(str(value or "").strip().lower(), "unknown")

    @field_validator("version", mode="before")
    @classmethod
    def _blank_version_is_none(cls, value):
        if value is None:
            return None
        value = str(value).strip()
        return value if value and value.lower() not in {"null", "none", "unknown", "n/a"} else None


class LlmAnswer(BaseModel):
    model_config = ConfigDict(extra="ignore")

    packages: list[LlmPackage] = []


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------

def settings() -> dict:
    """`.env` values, with real environment variables winning (same rule as Task 2)."""
    from dotenv import dotenv_values

    return {**dotenv_values(PROJECT_ROOT / ".env"), **os.environ}


def ollama_chat(messages: list[dict], schema: dict) -> str:
    """Send one chat request to Ollama with a JSON-schema answer format. Imported lazily."""
    import ollama

    env = settings()
    client = ollama.Client(host=env.get("OLLAMA_HOST") or None, timeout=float(env.get("OLLAMA_TIMEOUT") or 120))
    response = client.chat(
        model=env.get("OLLAMA_MODEL") or DEFAULT_MODEL,
        messages=messages,
        format=schema,
        options={"temperature": 0},
    )
    return response.message.content or ""


def _ask(text: str, chat: ChatFn) -> LlmAnswer:
    """Ask once; if the answer is not valid, ask again with the error appended. Raises after two bad answers."""
    schema = LlmAnswer.model_json_schema()
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": text}]
    reply = chat(messages, schema)
    try:
        return LlmAnswer.model_validate_json(reply)
    except ValidationError as error:
        messages += [
            {"role": "assistant", "content": reply},
            {"role": "user", "content": f"That answer was not valid JSON for the schema: {error.errors()[:3]}. "
                                        "Reply again with only JSON that matches the schema."},
        ]
    return LlmAnswer.model_validate_json(chat(messages, schema))


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def find_packages_with_llm(text: str, chat: ChatFn | None = None) -> tuple[list[Package], list[str]]:
    """Return (packages, warnings). `chat` can be replaced in tests; by default it calls Ollama."""
    warnings: list[str] = []
    if not text or not text.strip():
        return [], warnings
    prompt_text = text
    if len(text) > MAX_INPUT_CHARS:
        prompt_text = text[:MAX_INPUT_CHARS]
        warnings.append(f"Only the first {MAX_INPUT_CHARS} characters were sent to the AI fallback.")

    try:
        answer = _ask(prompt_text, chat or ollama_chat)
    except ValidationError:
        warnings.append("Low confidence: the AI fallback gave an invalid answer twice, so no packages were added.")
        return [], warnings
    except ImportError:
        warnings.append("Low confidence: the 'ollama' package is not installed, so the AI fallback was skipped.")
        return [], warnings
    except Exception as error:  # Ollama not running, model missing, timeout, ...
        warnings.append(f"Low confidence: the AI fallback is unavailable ({type(error).__name__}), "
                        "so no packages were added.")
        return [], warnings

    packages: list[Package] = []
    seen: set[tuple[str, str, str | None]] = set()
    for item in answer.packages:
        raw_name = item.name.strip()
        # Guardrail: the package must be written in the input (checked before the Maven group is added).
        if not raw_name or not name_appears_in(raw_name, prompt_text):
            warnings.append(f"Dropped '{raw_name}' from the AI fallback: it does not appear in the input text.")
            continue
        version = item.version
        if version and version not in prompt_text:
            warnings.append(f"Removed version '{version}' of '{raw_name}': it does not appear in the input text.")
            version = None
        elif version and _YEAR.fullmatch(version):
            warnings.append(f"Removed version '{version}' of '{raw_name}': it looks like a year, not a version.")
            version = None

        name, ecosystem = raw_name.lower(), item.ecosystem
        if ecosystem == "Maven":
            artifact = name.rsplit(":", 1)[-1]
            full_name = maven_name(artifact)
            if full_name:
                name = full_name
            else:
                name, ecosystem = artifact, "unknown"
                warnings.append(f"Unknown Java library '{artifact}': its Maven group is not in the lookup table, "
                                "so it is not looked up.")
        key = (ecosystem, name, version)
        if key not in seen:
            seen.add(key)
            packages.append(Package(name=name, version=version, ecosystem=ecosystem))
    return packages, warnings


if __name__ == "__main__":   # quick manual check: python -m src.parser.llm_fallback "some messy text"
    import sys

    found, notes = find_packages_with_llm(" ".join(sys.argv[1:]) or sys.stdin.read())
    print(json.dumps([p.model_dump() for p in found], indent=2))
    for note in notes:
        print("warning:", note)
