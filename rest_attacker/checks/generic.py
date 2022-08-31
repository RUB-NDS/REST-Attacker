# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Implementation of the generic test case super class.
"""
from __future__ import annotations
import typing

from abc import ABC, abstractmethod

from rest_attacker.util.test_result import CheckStatus, TestResult

if typing.TYPE_CHECKING:
    from rest_attacker.engine.config import EngineConfig
    from rest_attacker.report.report import Report
    from rest_attacker.checks.types import AuthType, LiveType, TestCaseType


class TestCase(ABC):
    """
    Interface for test cases.
    """
    test_type: TestCaseType = None
    auth_type: AuthType = None
    live_type: LiveType = None
    generates_for: tuple[typing.Type[TestCase], ...] | None = None

    def __init__(self, check_id: int) -> None:
        """
        Create a new check from the test case.

        :param check_id: Unique identifier of the check generated from the test case.
        :type check_id: int
        """
        self.check_id = check_id

        # Stores the result of a run.
        self.result = TestResult(self)

    @abstractmethod
    def run(self) -> None:
        """
        Execute the check instance for this test case.
        """

    @abstractmethod
    def report(self, verbosity: int = 2) -> Report:
        """
        Generate a report for the check instance.

        :param verbosity: Verbosity of the exported results.
        :type verbosity: int
        """

    @abstractmethod
    def propose(self, config: EngineConfig, check_id_start: int) -> list[TestCase]:
        """
        Propose checks for the test case based on the results of the check.

        :param config: Engine configuration for a service
        :type config: EngineConfig
        :param check_id_start: Starting index for assigning the check IDs.
        :type check_id_start: int
        """
        if self.result.status is not CheckStatus.FINISHED:
            raise Exception(f"Cannot propose checks for {self}. Check is not finished.")

    @classmethod
    @abstractmethod
    def generate(cls, config: EngineConfig, check_id_start: int = 0) -> list[TestCase]:
        """
        Generate checks for the test case from information at load-time.

        :param config: Engine configuration for a service
        :type config: EngineConfig
        :param check_id_start: Starting index for assigning the check IDs.
        :type check_id_start: int
        """

    @abstractmethod
    def serialize(self) -> dict | None:
        """
        Serialize a check to a JSON-compatible dict.

        :return: A JSON-compatible dict if the check/test case is serializable, else None.
        :rtype: dict | None
        """

    @classmethod
    @abstractmethod
    def deserialize(cls, serialized: dict, config: EngineConfig, check_id: int = 0) -> TestCase | None:
        """
        Deserialize a check from a JSON-compatible dict to a TestCase object.

        :param serialized: Serialized representation of the check.
        :type serialized: dict
        :param config: Engine configuration for a service
        :type config: EngineConfig
        :param check_id_start: Starting index for assigning the check IDs.
        :type check_id_start: int
        :return: A check of the test case if the check/test case is deserializable, else None.
        :rtype: TestCase | None
        """

    @classmethod
    def get_test_case_id(cls) -> str:
        """
        Get the identifier of the test case.
        """
        return f"{cls.__module__.rsplit('.',maxsplit=1)[-1]}.{cls.__name__}"

    def __repr__(self):
        return f"<{type(self).__name__}<{self.check_id}>>"
