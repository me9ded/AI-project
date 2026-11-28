"""The output contract of Task 1 (proposal section 2.2.1, design brief docs/task1-brief.md).

Task 2 (`src.retrieval.retrieve`) reads this dict, so field names and allowed values
must not change. `Extraction(...).to_dict()` gives the plain dict the other tasks use.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Ecosystem = Literal["PyPI", "npm", "Maven", "unknown"]
SourceType = Literal["pip-audit", "npm-audit", "raw-log", "screenshot"]
ExtractionMethod = Literal["parser", "regex", "llm", "ocr+regex", "ocr+llm"]


class Package(BaseModel):
    """One package found in the input. Maven names are `groupId:artifactId`."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    version: str | None = None  # None when the input names a package without a version
    ecosystem: Ecosystem


class Extraction(BaseModel):
    """Everything Task 1 found in one input."""

    model_config = ConfigDict(extra="forbid")

    source_type: SourceType = "raw-log"
    packages: list[Package] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)       # e.g. "CVE-2021-44228"
    advisory_ids: list[str] = Field(default_factory=list)  # e.g. "GHSA-jfh8-c2jp-5v3q", "PYSEC-2021-66"
    extraction_method: ExtractionMethod = "regex"
    raw_text: str = ""
    ocr_confidence: float | None = Field(default=None, ge=0.0, le=1.0)  # screenshots only, for the UI
    warnings: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict:
        """Plain dict for Task 2 (`retrieve`), Task 4 (the API) and the tests."""
        return self.model_dump()
