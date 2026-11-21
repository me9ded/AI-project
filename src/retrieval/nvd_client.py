"""NVD API 2.0 client (design spec section 5). Stub: not implemented yet."""

from dataclasses import dataclass


@dataclass(frozen=True)
class NvdCve:
    id: str
    summary: str
    cvss_score: float | None
    cwes: list


class NvdClient:
    def __init__(self, session, cache, limiter, api_key=None, sleep=None):
        pass

    def get_cve(self, cve_id):
        raise NotImplementedError
