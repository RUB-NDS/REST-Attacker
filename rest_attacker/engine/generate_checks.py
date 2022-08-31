# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Generate checks for a run.
"""

from __future__ import annotations
import typing

import logging

from rest_attacker.checks.types import TestCaseType

if typing.TYPE_CHECKING:
    from rest_attacker.checks.generic import TestCase
    from rest_attacker.engine.config import EngineConfig


def generate_checks(
    config: EngineConfig,
    test_cases: dict[str, TestCase],
    filters: dict = None
) -> list[TestCase]:
    """
    Generate checks for a set of test cases from a service configuration.

    :param config: Configuration for the service.
    :type config: EngineConfig
    :param test_cases: Test case classes that are used for the generation. Maps test case IDs to test case classes.
    :type test_cases: dict[str, TestCase]
    :param filters: Only generate test cases with a specific type. The input dict must
                   have strings of the name of the class type member as keys and
                   a list of the allowed types as values. If a type is not specified
                   in the keys, all variants of this type are allowed.
    :type filters: dict
    """
    index = 0
    checks = []

    # Check if test case conforms to filter
    if filters:
        filtered_test_cases = {}
        if "test_cases" in filters.keys():
            # Check if IDs given here are valid test case IDs
            for allowed_type in filters["test_cases"]:
                if allowed_type not in test_cases.keys():
                    raise Exception(
                        f"Could not find test case with ID '{allowed_type}' "
                        "in available test cases.")

        for test_case_id, test_case in test_cases.items():
            allowed = True
            for filter_type, allowed_types in filters.items():
                if filter_type in ("test_type", "auth_type", "live_type"):
                    case_type = getattr(test_case, filter_type)

                    if case_type not in allowed_types:
                        allowed = False
                        break

                elif filter_type == "test_cases":
                    if test_case_id not in allowed_types:
                        allowed = False
                        break

            if allowed:
                logging.debug(f"Added test case: {test_case_id}")
                filtered_test_cases.update({
                    test_case_id: test_case
                })

    else:
        filtered_test_cases = test_cases.copy()

    # Search for meta test cases that generate checks for their subcases
    # The subcases can be removed from the generation
    dedupl_test_cases = filtered_test_cases.copy()
    for test_case in filtered_test_cases.values():
        if test_case.test_type is TestCaseType.META:
            if test_case.generates_for:
                for test_case_cls in test_case.generates_for:
                    test_case_id = test_case_cls.get_test_case_id()
                    dedupl_test_cases.pop(test_case_id, None)

    for test_case in dedupl_test_cases.values():
        new_checks = test_case.generate(config, check_id_start=index)
        checks.extend(new_checks)
        index += len(new_checks)

    return checks
