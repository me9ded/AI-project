"""OSV.dev client (design spec section 5).

OSV answers "which vulnerabilities affect this exact package version?" and maps
advisory IDs (GHSA, PYSEC) to CVE aliases. Responses are returned as the raw OSV
dicts; the service decides what to keep.
"""

import time

from src.retrieval.cache import SqliteCache, cached_fetch
from src.retrieval.rate_limiter import with_retries

QUERY_URL = "https://api.osv.dev/v1/query"
VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
TIMEOUT_SECONDS = 10


class OsvClient:
    def __init__(self, session, cache: SqliteCache, sleep=time.sleep):
        self.session = session
        self.cache = cache
        self.sleep = sleep  # used between retries; tests pass a fake

    def query_package(self, name: str, ecosystem: str, version: str | None) -> tuple[list[dict], bool]:
        """Vulnerabilities affecting `name` at `version` (all versions if None).
        Returns (vulns, is_stale)."""
        body = {"package": {"name": name, "ecosystem": ecosystem}}
        if version is not None:
            body["version"] = version
        key = f"osv:query:{ecosystem}:{name}:{version or '*'}"

        def fetch():
            vulns = []
            page_body = body
            while True:  # OSV pages long results; follow next_page_token until it is gone
                response = with_retries(
                    lambda: self.session.post(QUERY_URL, json=page_body, timeout=TIMEOUT_SECONDS), sleep=self.sleep
                )
                page = response.json()
                vulns.extend(page.get("vulns", []))
                token = page.get("next_page_token")
                if not token:
                    return {"vulns": vulns}
                page_body = {**body, "page_token": token}

        data, is_stale = cached_fetch(self.cache, key, fetch)
        return data["vulns"], is_stale

    def get_vuln(self, vuln_id: str) -> tuple[dict, bool]:
        """One OSV entry by ID (GHSA-…, PYSEC-…, CVE-…). Returns (vuln, is_stale)."""
        url = VULN_URL.format(id=vuln_id)

        def fetch():
            response = with_retries(lambda: self.session.get(url, timeout=TIMEOUT_SECONDS), sleep=self.sleep)
            return response.json()

        return cached_fetch(self.cache, f"osv:vuln:{vuln_id}", fetch)
