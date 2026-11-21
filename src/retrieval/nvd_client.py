"""NVD API 2.0 client (design spec section 5).

NVD adds what OSV lacks: the CVSS base score, CWE weakness IDs and the official
description. Replies are parsed before caching, so only the few fields we use are
stored and a reply with an unexpected shape is never cached.
"""

import time
from dataclasses import asdict, dataclass

from src.retrieval.cache import SqliteCache, cached_fetch
from src.retrieval.rate_limiter import RetrievalError, read_json, with_retries

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT_SECONDS = 10

# CVSS versions, best first (design spec FR5). Other metric keys (e.g. "ssvcV203")
# are not scores. v4.0 uses the same rating bands as v3.x.
SCORE_KEYS = ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2")

# NVD placeholders meaning "no CWE known"; they are not real weaknesses.
CWE_PLACEHOLDERS = {"NVD-CWE-noinfo", "NVD-CWE-Other"}


@dataclass(frozen=True)
class NvdCve:
    id: str
    summary: str
    cvss_score: float | None
    cwes: list[str]


class NvdClient:
    def __init__(self, session, cache: SqliteCache, limiter, api_key: str | None = None, sleep=time.sleep):
        self.session = session
        self.cache = cache
        self.limiter = limiter  # shared RateLimiter: 5 or 50 requests per 30 s
        self.headers = {"apiKey": api_key} if api_key else {}
        self.sleep = sleep

    def get_cve(self, cve_id: str) -> tuple[NvdCve | None, bool]:
        """NVD's record for `cve_id`, or None if NVD has none. Returns (cve, is_stale)."""

        def fetch():
            response = with_retries(lambda: self._request(cve_id), sleep=self.sleep)
            data = read_json(response, "NVD")
            try:
                cve = _parse_cve(data)
            except (KeyError, IndexError, TypeError) as error:  # NVD's format changed
                raise RetrievalError(f"NVD reply for {cve_id} has an unexpected format: {error!r}") from error
            # Cache a small dict, never None ("not cached"): found or not found.
            return {"found": False} if cve is None else {"found": True, **asdict(cve)}

        cached, is_stale = cached_fetch(self.cache, f"nvd:cve:{cve_id}", fetch)
        if not cached["found"]:
            return None, is_stale
        fields = {key: value for key, value in cached.items() if key != "found"}
        return NvdCve(**fields), is_stale

    def _request(self, cve_id: str):
        """One HTTP attempt. Every attempt, retries included, counts against NVD's limit."""
        self.limiter.acquire()
        return self.session.get(NVD_URL, params={"cveId": cve_id}, headers=self.headers, timeout=TIMEOUT_SECONDS)


def _parse_cve(data: dict) -> NvdCve | None:
    if not data.get("vulnerabilities"):
        return None  # NVD answers an unknown CVE with HTTP 200 and no results
    cve = data["vulnerabilities"][0]["cve"]
    return NvdCve(
        id=cve["id"],
        summary=_english_description(cve),
        cvss_score=_base_score(cve.get("metrics", {})),
        cwes=_cwe_ids(cve),
    )


def _english_description(cve: dict) -> str:
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return description.get("value", "")
    return ""


def _base_score(metrics: dict) -> float | None:
    """The first CVSS version present wins; within it NVD's own (Primary) score
    is preferred over a CNA's (Secondary) score."""
    for key in SCORE_KEYS:
        entries = metrics.get(key)
        if entries:
            primary = [entry for entry in entries if entry.get("type") == "Primary"]
            return (primary or entries)[0]["cvssData"]["baseScore"]
    return None


def _cwe_ids(cve: dict) -> list[str]:
    found = []
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if value and value not in CWE_PLACEHOLDERS and value not in found:
                found.append(value)
    return found
