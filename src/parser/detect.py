"""Format detection for Task 1 (docs/task1-brief.md, rule 3).

detect(text) -> Detected(kind, data)
    kind "pip-audit-json"  pip-audit -f json   (data = parsed JSON)
    kind "npm-audit-json"  npm audit --json     (data = parsed JSON; not parsed field by field yet)
    kind "text"            anything else        (data = None) -> regex layer, then LLM fallback

Never raises: input that is not valid JSON is simply "text".
"""

import json
from typing import Any, Literal, NamedTuple

Kind = Literal["pip-audit-json", "npm-audit-json", "text"]


class Detected(NamedTuple):
    kind: Kind
    data: Any = None


def _load_json(text: str) -> Any:
    """Parse JSON, also when it is pasted after a command line such as '$ pip-audit -f json'."""
    stripped = text.strip().lstrip("﻿")
    try:
        return json.loads(stripped)
    except ValueError:
        pass
    # Pasted terminal output: start at the first line that begins with { or [
    offset = 0
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith(("{", "[")):
            try:
                data, _ = json.JSONDecoder().raw_decode(text[offset:].lstrip())
                return data
            except ValueError:
                return None
        offset += len(line)
    return None


def _is_pip_audit_dependency(item: Any) -> bool:
    return isinstance(item, dict) and "name" in item and ("vulns" in item or "skip_reason" in item)


def detect(text: str | None) -> Detected:
    if not text or not text.strip():
        return Detected("text")
    data = _load_json(text)
    if isinstance(data, dict):
        # pip-audit 2.x: {"dependencies": [...], "fixes": [...]}
        if isinstance(data.get("dependencies"), list):
            return Detected("pip-audit-json", data)
        # npm 7+: {"auditReportVersion": 2, "vulnerabilities": {...}}; npm 6: {"advisories": {...}, "actions": [...]}
        if ("auditReportVersion" in data and isinstance(data.get("vulnerabilities"), dict)) or (
            isinstance(data.get("advisories"), dict) and "actions" in data
        ):
            return Detected("npm-audit-json", data)
    # older pip-audit: a bare list of dependencies
    if isinstance(data, list) and data and all(_is_pip_audit_dependency(item) for item in data):
        return Detected("pip-audit-json", {"dependencies": data})
    return Detected("text")
