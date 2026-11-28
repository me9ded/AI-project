"""Task 1 - Input Parsing & Extraction (spec: docs/task1-brief.md; proposal sections 2.2.1 and 2.2.3).

    from src.parser import extract
    extraction = extract(text="...")              # pasted text
    extraction = extract(image=upload_bytes)      # a screenshot (path, bytes or PIL image)
    result = retrieve(extraction)                 # Task 2

extract() returns the plain dict agreed with Task 2 (see src/parser/schema.py) and never raises
for bad input: problems become entries in "warnings". The pipeline is:

    image -> OCR (ocr.py) -> detect (detect.py) -> pip-audit JSON parser (scanners.py)
                                               or regex layer (patterns.py)
                                               -> LLM fallback only if no packages (llm_fallback.py)

Heavy libraries (EasyOCR, PyTorch, Ollama) are imported only when they are needed.
"""

import re
from collections import Counter
from typing import Any

from src.parser.detect import detect
from src.parser.patterns import PIP_AUDIT_HEADER_RE, find_ids, find_packages
from src.parser.scanners import NPM_AUDIT_NOT_SUPPORTED, parse_pip_audit
from src.parser.schema import Extraction, Package

__all__ = ["extract"]


def _add(target: list[str], values: list[str]) -> None:
    for value in values:
        if value not in target:
            target.append(value)


def _as_text(text: Any) -> str:
    """Accept str or uploaded file bytes. Files saved with PowerShell's `>` are UTF-16, so check the BOM."""
    if text is None:
        return ""
    if isinstance(text, (bytes, bytearray)):
        data = bytes(text)
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return data.decode("utf-16", errors="replace")
        return data.decode("utf-8-sig", errors="replace")
    return str(text)


def _read_screenshot(image: Any) -> tuple[str, float | None, list[str]]:
    """OCR the image. Returns (text, confidence, warnings); problems become warnings, not exceptions."""
    from src.parser import ocr

    try:
        text, confidence = ocr.image_to_text(image)
    except ValueError as error:
        return "", None, [str(error)]
    except ocr.OcrUnavailable as error:
        return "", None, [f"The screenshot could not be read: {error}"]
    warnings = []
    if not text:
        warnings.append("No text was found in the screenshot.")
    elif confidence < ocr.LOW_CONFIDENCE:
        warnings.append(f"Low-quality screenshot (OCR confidence {confidence:.0%}): please check the results.")
    return text, confidence, warnings


def _vote_ocr_versions(packages: list[Package], text: str) -> tuple[list[Package], list[str]]:
    """OCR can misread one row (e.g. 'jinja2 2.18' among many 'jinja2 2.10'). When a screenshot shows the
    same package with several versions, keep the version written most often next to its name."""
    by_package: dict[tuple[str, str], list[Package]] = {}
    for package in packages:
        by_package.setdefault((package.ecosystem, package.name), []).append(package)

    kept: list[Package] = []
    warnings: list[str] = []
    lines = text.lower().splitlines()
    for (_, name), group in by_package.items():
        if len(group) == 1:
            kept.append(group[0])
            continue
        artifact = re.escape(name.rsplit(":", 1)[-1])
        counts = Counter()
        for package in group:
            version = re.escape((package.version or "").lower())
            pattern = re.compile(rf"{artifact}\W+{version}(?![\w.])") if version else None
            counts[package.version] = sum(1 for line in lines if pattern and pattern.search(line))
        best = max(group, key=lambda p: counts[p.version])   # ties keep the first one seen
        kept.append(best)
        others = ", ".join(f"{p.version} ({counts[p.version]}x)" for p in group if p is not best)
        warnings.append(f"The screenshot shows {name} with different versions; kept {best.version} "
                        f"({counts[best.version]}x), ignored {others} as likely OCR misreads.")
    return kept, warnings


def extract(text: str | bytes | None = None, image: Any = None) -> dict:
    """Find packages, versions and vulnerability IDs in pasted text and/or a screenshot.

    `text` may be a string or the bytes of an uploaded text file. If both text and an image are
    given, the screenshot text and the pasted text are read together.
    """
    text = _as_text(text)
    warnings: list[str] = []
    confidence: float | None = None
    source_type = "raw-log"

    if image is not None:
        source_type = "screenshot"
        ocr_text, confidence, ocr_warnings = _read_screenshot(image)
        _add(warnings, ocr_warnings)
        text = "\n".join(part for part in (ocr_text, text) if part and part.strip())
    text = text or ""
    if not text.strip():
        if image is None:
            warnings.append("No text or screenshot was given.")
        return Extraction(source_type=source_type, raw_text=text, ocr_confidence=confidence,
                          warnings=warnings).to_dict()

    found = detect(text)
    prefix = "ocr+" if source_type == "screenshot" else ""

    # 1. Scanner JSON: read field by field
    if found.kind == "pip-audit-json":
        result = parse_pip_audit(found.data)
        _add(warnings, result.warnings)
        return result.model_copy(update={
            "source_type": source_type if source_type == "screenshot" else "pip-audit",
            "raw_text": text, "ocr_confidence": confidence, "warnings": warnings,
        }).to_dict()

    cve_ids, advisory_ids = find_ids(text)
    if found.kind == "npm-audit-json":
        # Stretch item: only the IDs are used, and a big JSON report is never sent to the LLM.
        _add(warnings, [NPM_AUDIT_NOT_SUPPORTED])
        return Extraction(source_type="npm-audit", cve_ids=cve_ids, advisory_ids=advisory_ids,
                          extraction_method="regex", raw_text=text, warnings=warnings).to_dict()

    # 2. Free text: regex layer
    packages, regex_warnings = find_packages(text)
    _add(warnings, regex_warnings)
    method = prefix + "regex"
    if source_type == "screenshot":
        packages, vote_warnings = _vote_ocr_versions(packages, text)
        _add(warnings, vote_warnings)
    elif PIP_AUDIT_HEADER_RE.search(text):
        source_type = "pip-audit"

    # 3. LLM fallback, only when the regex layer found no packages
    if not packages:
        from src.parser.llm_fallback import find_packages_with_llm

        llm_packages, llm_warnings = find_packages_with_llm(text)
        _add(warnings, llm_warnings)
        if llm_packages:
            packages, method = llm_packages, prefix + "llm"

    return Extraction(
        source_type=source_type,
        packages=packages,
        cve_ids=cve_ids,
        advisory_ids=advisory_ids,
        extraction_method=method,
        raw_text=text,
        ocr_confidence=confidence,
        warnings=warnings,
    ).to_dict()
