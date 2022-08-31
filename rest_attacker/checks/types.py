# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Test case type enums.
"""

import enum


@enum.unique
class TestCaseType(enum.Enum):
    """
    Test case types. Used to classify test cases to interpret their results.
    """
    ANALYTICAL = "analytical"
    SECURITY   = "security"
    COMPARISON = "comparison"   # unused; originally intended for comparing checks between runs
    META       = "meta"
    # TODO: instead of "meta" being a test case type
    #       it could be a different class. like
    #       the TestSuite class in unittest


@enum.unique
class AuthType(enum.Enum):
    """
    Specifies whether access control data is required for this test case.
    """
    NOPE        = "nope"         # no access control data used
    OPTIONAL    = "optional"     # access control data can be used but is not required
    RECOMMENDED = "recommended"  # access control data should be used but is not required
    REQUIRED    = "required"     # access control data must be used


@enum.unique
class LiveType(enum.Enum):
    """
    Specifies whether a test case requires live access to the API.
    """
    ONLINE  = "online"      # sends API requests
    OFFLINE = "offline"     # does not send API requests
