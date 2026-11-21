"""OSV.dev client (design spec section 5).

OSV answers "which vulnerabilities affect this exact package version?" and maps
advisory IDs (GHSA, PYSEC) to CVE aliases. Responses are returned as the raw OSV
dicts; the service decides what to keep.
"""

import time
from urllib.parse import quote

from src.retrieval.cache import SqliteCache, cached_fetch
from src.retrieval.rate_limiter import RetrievalError, with_retries

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
        version = version or None  # "" means unknown too, so request and cache key agree
        body = {"package": {"name": name, "ecosystem": ecosystem}}
        if version is not None:
            body["version"] = version
        key = f"osv:query:{ecosystem}:{name}:{version or '*'}"

        def fetch():
            vulns = []
            page = self._post(body)
            vulns.extend(page.get("vulns", []))
            while page.get("next_page_token"):  # OSV pages long results
                page = self._post({**body, "page_token": page["next_page_token"]})
                vulns.extend(page.get("vulns", []))
            return {"vulns": vulns}

        data, is_stale = cached_fetch(self.cache, key, fetch)
        return data["vulns"], is_stale

    def get_vuln(self, vuln_id: str) -> tuple[dict | None, bool]:
        """One OSV entry by ID (GHSA-…, PYSEC-…, CVE-…). Returns (vuln, is_stale).
        An ID OSV does not know gives (None, False): a typo, not an outage."""
        try:
            url = VULN_URL.format(id=quote(vuln_id, safe=""))  # escape / ? # so the ID stays one path segment
            return cached_fetch(self.cache, f"osv:vuln:{vuln_id}", lambda: self._get(url))
        except RetrievalError as error:
            if error.status_code == 404:
                return None, False
            raise

    def _post(self, body: dict) -> dict:
        response = with_retries(
            lambda: self.session.post(QUERY_URL, json=body, timeout=TIMEOUT_SECONDS), sleep=self.sleep
        )
        return _read_json(response)

    def _get(self, url: str) -> dict:
        response = with_retries(lambda: self.session.get(url, timeout=TIMEOUT_SECONDS), sleep=self.sleep)
        return _read_json(response)


def _read_json(response) -> dict:
    """The response body as JSON. A body that is not JSON counts as a failed
    request, so cached_fetch can still fall back to stale data."""
    try:
        return response.json()
    except ValueError as error:  # requests' JSONDecodeError is a ValueError
        raise RetrievalError(f"OSV sent a body that is not JSON: {error}") from error
