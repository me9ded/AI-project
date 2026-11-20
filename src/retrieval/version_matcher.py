"""Version matching for OSV affected ranges (design spec section 6). Stub: not implemented yet."""


def parse_version(version, ecosystem):
    raise NotImplementedError


def is_affected(version, affected_entry, ecosystem):
    raise NotImplementedError


def fixed_versions(affected_entry):
    raise NotImplementedError


def lowest_fix(installed, fixed_lists, ecosystem):
    raise NotImplementedError
