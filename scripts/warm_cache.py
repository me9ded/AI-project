"""Fill the vulnerability cache with the demo inputs before the demo.

Run from the project root:

    python scripts/warm_cache.py                  # fill the cache (settings from .env)
    python scripts/warm_cache.py --check-offline  # then prove the demo works with no network

(`python -m scripts.warm_cache` works too.) It exits 1 if the cache could not be fully
filled, for example because an API was down. Without an NVD_API_KEY, NVD allows 5
requests per 30 seconds, so the Jackson input (about 60 CVEs) takes several minutes.

The cache entries stay fresh for 24 hours; after that the app still uses them when
the network is down, but marks the results as possibly incomplete.
"""

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):  # run as a file: make the project folder importable
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests  # noqa: E402  (after the path fix above)

from src.retrieval import build_service, load_env  # noqa: E402

# The demo inputs from the proposal (section 4.3), as Task 1 would extract them.
DEMO_INPUTS = {
    "Log4Shell log line": {
        "source_type": "raw-log",
        "packages": [
            {"name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "ecosystem": "Maven"},
            {"name": "org.apache.logging.log4j:log4j-api", "version": "2.14.1", "ecosystem": "Maven"},
        ],
        "cve_ids": [],
        "advisory_ids": [],
        "extraction_method": "regex",
    },
    "pip-audit screenshot": {
        "source_type": "screenshot",
        "packages": [{"name": "jinja2", "version": "2.10", "ecosystem": "PyPI"}],
        "cve_ids": [],
        "advisory_ids": [],
        "extraction_method": "ocr+regex",
    },
    "Jackson databind note": {
        "source_type": "raw-log",
        "packages": [{"name": "com.fasterxml.jackson.core:jackson-databind", "version": "2.9.8", "ecosystem": "Maven"}],
        "cve_ids": [],
        "advisory_ids": [],
        "extraction_method": "llm",
    },
}


class OfflineSession:
    """Every request fails, like a laptop with no network."""

    def post(self, url, **kwargs):
        raise requests.ConnectionError("offline check: no network")

    def get(self, url, **kwargs):
        raise requests.ConnectionError("offline check: no network")


def warm(service, inputs: dict) -> dict:
    """Run every input once; the clients cache what they fetch. Returns results by label."""
    return {label: service.retrieve(extraction) for label, extraction in inputs.items()}


def summarise(label: str, result) -> str:
    """One line per input, e.g. 'Log4Shell log line: 8 vulnerabilities, upgrade ... | complete | 0 warnings'."""
    upgrades = ", ".join(f"{name} -> {version}" for name, version in result.recommended_upgrades.items()) or "none"
    status = "INCOMPLETE" if result.incomplete else "complete"
    return (f"{label}: {_plural(len(result.records), 'vulnerability', 'vulnerabilities')}, "
            f"upgrade {upgrades} | {status} | {_plural(len(result.warnings), 'warning', 'warnings')}")


def _plural(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def check_offline(offline_service, inputs: dict, expected: dict) -> list[str]:
    """Run every input again with no network; list the inputs whose answer changed."""
    return [
        f"{label}: the offline answer differs from the online one"
        for label, extraction in inputs.items()
        if offline_service.retrieve(extraction) != expected[label]
    ]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Fill the vulnerability cache with the demo inputs.")
    parser.add_argument("--check-offline", action="store_true",
                        help="afterwards, run the inputs again with no network and compare")
    args = parser.parse_args(argv)

    env = load_env()
    results = warm(build_service(requests.Session(), env), DEMO_INPUTS)
    for label, result in results.items():
        print(summarise(label, result))
        for warning in result.warnings:
            print(f"    warning: {warning}")

    # An incomplete warm-up means an API failed, so some answers are missing from the
    # cache. The offline check alone cannot see that: it compares against this run.
    filled = not any(result.incomplete for result in results.values())
    if not filled:
        print("Cache NOT fully filled: an API failed during the warm-up (see the warnings). Run again when online.")

    problems = []
    if args.check_offline:
        problems = check_offline(build_service(OfflineSession(), env), DEMO_INPUTS, results)
        print("Offline check:", "OK, every input gives the same answer with no network" if not problems else "FAILED")
        for problem in problems:
            print(f"    {problem}")
    return 0 if filled and not problems else 1


if __name__ == "__main__":
    sys.exit(main())
