"""OSV.dev client (design spec section 5). Stub: not implemented yet."""


class OsvClient:
    def __init__(self, session, cache, sleep=None):
        pass

    def query_package(self, name, ecosystem, version):
        raise NotImplementedError

    def get_vuln(self, vuln_id):
        raise NotImplementedError
