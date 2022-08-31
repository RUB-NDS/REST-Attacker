# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
HTTP method names and categories.
"""

# Non-destructive (or read-only)
SAFE_METHODS = [
    "get",
    "head",
    "options",

    # unsupported by requests module?
    "trace",
]

# Potentially destructive
UNSAFE_METHODS = [
    "post",
    "put",
    "patch",
    "delete",

    # unsupported by requests module?
    "connect",
]

# Multiple identical requests => same result on the server
IDEMPOTENT_METHODS = [
    "put",
    "delete",
]

# All methods
METHODS = list(set(SAFE_METHODS + UNSAFE_METHODS))
