"""CISA KEV client (design spec section 5).

The Known Exploited Vulnerabilities catalog lists CVEs that attackers are using
right now. It is one JSON file (about 1.8 MB), so it is downloaded at most once a
day and only the CVE IDs are cached.
"""

import time

from src.retrieval.cache import SqliteCache, cached_fetch
from src.retrieval.rate_limiter import RetrievalError, read_json, with_retries

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"  # human-readable page
TIMEOUT_SECONDS = 30  # a larger file than the other APIs return
CACHE_KEY = "kev:catalog"


class KevClient:
    def __init__(self, session, cache: SqliteCache, sleep=time.sleep):
        self.session = session
        self.cache = cache
        self.sleep = sleep

    def is_exploited(self, cve_id: str) -> tuple[bool, bool]:
        """Whether `cve_id` is in the KEV catalog. Returns (exploited, is_stale)."""

        def fetch():
            response = with_retries(lambda: self.session.get(KEV_URL, timeout=TIMEOUT_SECONDS), sleep=self.sleep)
            catalog = read_json(response, "CISA KEV")
            try:
                return {"cve_ids": [entry["cveID"] for entry in catalog["vulnerabilities"]]}
            except (KeyError, TypeError) as error:  # the feed's format changed
                raise RetrievalError(f"CISA KEV feed has an unexpected format: {error!r}") from error

        data, is_stale = cached_fetch(self.cache, CACHE_KEY, fetch)
        return cve_id.upper() in data["cve_ids"], is_stale
