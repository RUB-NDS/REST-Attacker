# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Implementation of test result objects.
"""
from __future__ import annotations
import typing

import enum
import logging

if typing.TYPE_CHECKING:
    from rest_attacker.checks.generic import TestCase


class CheckStatus(enum.Enum):
    """
    Status of the check.
    """
    QUEUED = "queued"    # test result is waiting for check to execute
    RUNNING = "running"   # check was started
    FINISHED = "finished"  # check finished successfully
    SKIPPED = "skipped"   # check was skipped
    ABORTED = "aborted"   # check was aborted because run finished early
    ERROR = "error"     # check failed with error


class IssueType(enum.Enum):
    """
    Type of issue found by the check. Depends on the test case type.
    """
    # Analytical
    CANDIDATE = "analysis_candidate"  # Found what the check was looking for
    NO_CANDIDATE = "analysis_none"       # Found nothing unusual

    # Security check
    OKAY = "security_okay"     # intended (secure) behaviour
    PROBLEM = "security_problem"  # unintended or undocumented behaviour
    FLAW = "security_flaw"     # insecure behaviour

    # Comparision check
    MATCH = "comparison_match"      # check result values are equal
    DIFFERENT = "comparison_different"  # check result values are different


class TestResult:
    """
    Stores the result of a check.
    """

    def __init__(self, check: TestCase) -> None:
        """
        Create a new TestResult object.

        :param check: Reference to the check the result is created for.
        :type check: TestCase
        """
        self.issue_type: IssueType = None
        self.status = CheckStatus.QUEUED
        self.error: Exception = None
        self.check: TestCase = check

        # Result value of the check. Should be a dict.
        self.value: dict = None

        self.last_response = None

    def dump(self, verbosity: int = 2) -> dict[str, typing.Any]:
        """
        Generate a dictionary with information from the test result.

        :param verbosity: Verbosity of the exported results.
                          0 -> check_id, status, issue type
                          1 -> 0 + error
                          2 -> 1 + value (default)
        :type verbosity: int
        """
        if self.status is CheckStatus.QUEUED:
            logging.warning(f"{self}: Dumping test result for unfinished check.")

        output = {
            "check_id": self.check.check_id,
            "test_type": self.check.test_type.value,
            "test_case": self.check.get_test_case_id(),
            "status": self.status.value,
        }

        if self.status not in (CheckStatus.SKIPPED, CheckStatus.ABORTED, CheckStatus.ERROR):
            if not self.issue_type:
                logging.warning(f"{self}: Dumping test result with unspecified issue type.")

            output["issue"] = self.issue_type.value

        if verbosity >= 1:
            if self.error:
                output["error"] = str(self.error)

        if verbosity >= 2:
            if self.value is not None:
                output["value"] = self.value

        return output
