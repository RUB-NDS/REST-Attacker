# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Errors and exceptions raised by REST-Attacker.
"""


class RestrictedOperationError(Exception):
    """
    Should be raised when the tool tries to execute an API endpoint operation that
    is not allowlisted (e.g. DELETE when using safemode).
    """
    pass


class RateLimitException(Exception):
    """
    Should be raised when the tool detects that the tool reached some kind of
    rate limit when communicating with an API.
    """
    pass
