# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Enumerate the test cases provided by the tool.
"""

import argparse
import pkgutil
import inspect
import sys
from rest_attacker.checks.generic import TestCase
import rest_attacker.checks as checks


def get_test_cases():
    """
    Enumerate all test cases in the 'checks' submodule.
    """
    test_cases = {}

    name_prefix = checks.__name__ + "."
    for _, modname, ispkg in pkgutil.iter_modules(checks.__path__):
        if ispkg:
            continue

        abs_modname = f"{name_prefix}{modname}"

        if abs_modname == "rest_attacker.checks.generic":
            # Ignore the ABC class
            continue

        # Needs non-empty 'fromlist' to import the actual module
        module = __import__(abs_modname, fromlist=" ")
        for m_cls in inspect.getmembers(module, inspect.isclass):
            mod_cls = m_cls[1]
            test_case_cls = TestCase
            if mod_cls == test_case_cls:
                continue

            if issubclass(mod_cls, test_case_cls):
                test_cases[mod_cls.get_test_case_id()] = mod_cls

    return test_cases


class GetTestCases(argparse.Action):
    """
    Enumerate all test cases in the 'checks' submodule.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        print("List of available test cases:")

        test_cases = get_test_cases()
        for test_case in test_cases.keys():
            print(f"  {test_case}")

        sys.exit(0)
