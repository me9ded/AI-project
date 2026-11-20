"""Download real OSV/NVD/KEV responses and trim them into tests/fixtures/t2/. Stub."""


def shorten(text, limit=300):
    raise NotImplementedError


def trim_osv_vuln(vuln, package):
    raise NotImplementedError


def trim_nvd_response(response):
    raise NotImplementedError


def trim_kev_catalog(catalog, wanted, extra=3):
    raise NotImplementedError
