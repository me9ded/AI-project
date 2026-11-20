"""SQLite cache for API responses (design spec section 8.1-8.2). Stub: not implemented yet."""


class SqliteCache:
    def __init__(self, path, ttl_seconds=86400, clock=None):
        pass

    def get(self, key):
        raise NotImplementedError

    def get_stale(self, key):
        raise NotImplementedError

    def set(self, key, value):
        raise NotImplementedError
