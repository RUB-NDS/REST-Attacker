# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Implementation of the generic test case super class.
"""

import typing

from datetime import datetime
import json
import logging
import sys
import time

from rest_attacker.checks.generic import TestCase
from rest_attacker.checks.types import LiveType, TestCaseType
from rest_attacker.engine.config import EngineConfig
from rest_attacker.engine.internal_state import EngineStatus, InternalState
from rest_attacker.util.errors import RestrictedOperationError
from rest_attacker.util.test_result import CheckStatus, TestResult


class Engine:
    """
    Test engine for a test run.
    """

    def __init__(self, config: EngineConfig, checks: list[TestCase], handlers=[]) -> None:
        """
        Create a new engine for a test run.

        :param config: Configuration for the service.
        :type config: EngineConfig
        :param checks: Ordered list of checks that should be executed in the run.
        :type checks: list
        :param handlers: Handlers for tracking rate limits imposed by the service.
        :type handlers: list
        """
        self.checks = checks
        self.config = config
        self.state = InternalState()
        self.index = 0

        # Initialize statistics
        self.state.planned_check_count = len(self.checks)

        for check in self.checks:
            if check.test_type == TestCaseType.ANALYTICAL:
                self.state.analytical_check_count += 1

            elif check.test_type == TestCaseType.SECURITY:
                self.state.security_check_count += 1

        # Setup handlers
        for handler in handlers:
            self.state.set_limit_handler(handler)

    def run(self) -> None:
        """
        Run all checks of the test run.
        """
        self.state.status = EngineStatus.RUNNING
        logging.info("Starting: Engine run.")
        while self.index < len(self.checks):
            self.current_check()

            # Check if rate/access limits are reached
            self.update_handlers()

            self.status()
            self.index += 1

        if not self.state.status is EngineStatus.ABORTED:
            logging.info("Finished: Engine run.")
            self.state.status = EngineStatus.FINISHED

        self.state.end_time = time.time()

    def current_check(self) -> None:
        """
        Execute the check at the current index.
        """
        logging.debug(f"Starting: Check {self.checks[self.index].check_id} "
                      f"({self.checks[self.index].get_test_case_id()}).")

        current_check = self.checks[self.index]
        try:
            current_check.run()

        except RestrictedOperationError as err:
            current_check.result.status = CheckStatus.SKIPPED
            current_check.result.error = err
            logging.warning((f"Check {current_check.check_id} did not execute: "
                             "API operation is restricted"))

        except Exception as err:
            current_check.result.status = CheckStatus.ERROR
            current_check.result.error = err
            logging.warning(
                f"Check {current_check.check_id} ({current_check.get_test_case_id()}) "
                f"produced the following error:\n{err}")

        # Update statistics
        if current_check.result.status is CheckStatus.FINISHED:
            self.state.finished_check_count += 1
            if self.config.cli_args:
                if self.config.cli_args.propose:
                    for check in current_check.propose(self.config, len(self.checks)):
                        self.checks.insert(self.index + 1, check)

        elif current_check.result.status is CheckStatus.SKIPPED:
            self.state.skipped_check_count += 1

        elif current_check.result.status is CheckStatus.ERROR:
            self.state.error_check_count += 1

        logging.debug(f"Finished: Check {self.checks[self.index].check_id} ({current_check.get_test_case_id()}) "
                      " with status: "
                      f"{self.checks[self.index].result.status.value}")

    def export(self, output_dir) -> None:
        """
        Export the results of a run to file.

        :param output_dir: Directory the report files are exported to.
        :type output_dir: pathlib.Path
        """
        output: dict[str, typing.Any] = {}

        if self.state.status is EngineStatus.ABORTED:
            output["type"] = "partial"

        else:
            output["type"] = "report"

        # Service info
        if self.config.meta:
            output["meta"] = self.config.meta

        # Run statistics
        output["stats"] = self.state.dump()

        # Run args
        if self.config.cli_args:
            output["args"] = sys.argv[1:]

        reports = []
        for check in self.checks:
            try:
                report = check.report().dump()
                reports.append(report)

            except Exception as exc:
                logging.exception(
                    f"Report for check {check.check_id} could not be generated.", exc_info=exc)

        output["reports"] = reports

        output_str = json.dumps(output, indent=4)

        report_file = output_dir / "report.json"
        with report_file.open('w') as repf:
            repf.write(output_str)

        logging.info(f"Exported results to: {report_file}")

    def update_handlers(self):
        """
        Execute response handlers assigned to the run.
        """
        current_check = self.checks[self.index]

        # Currently only online checks are relevant here
        if current_check.live_type is LiveType.ONLINE:
            if self.state.rate_limit:
                rl_limit_reached = self.state.rate_limit.update(current_check.result.last_response)

                if rl_limit_reached:
                    reset_time = self.state.rate_limit.get_reset_wait_time()
                    logging.warning(
                        f"Rate limit reached: Next check possible in {reset_time} seconds.")
                    self.pause(time.time() + reset_time)

                    self.state.rate_limit.reset()

            if self.state.access_limit:
                # Check interval
                if self.state.access_limit.current_pos >= self.state.access_limit.interval:
                    acc_limit_reached = self.state.access_limit.update()

                    if acc_limit_reached:
                        logging.warning("Access limit reached.")
                        # TODO: Idea: Switch to a different client/user and resume run
                        #             may affect the remaining preconfigured checks?

                        # Roll back to last successful check
                        while (self.checks[self.index].check_id != self.state.access_limit.last_check_id
                               and self.index > -1):
                            # Clear test result
                            self.checks[self.index].result = TestResult(self.checks[self.index])
                            self.index -= 1

                            # TODO: This currently also rolls back offline checks. Maybe only roll
                            # back online checks that actively make requests

                            # TODO: What if any checks were proposed based on the results of the checks
                            # that were faulty and are now rolled back?

                        # abort the run
                        self.abort()
                        return

                    else:
                        self.state.access_limit.last_check_id = self.checks[self.index].check_id
                        self.state.access_limit.reset()

                else:
                    self.state.access_limit.current_pos += 1

    def pause(self, until: int):
        """
        Pause a run until a point in time.

        :param until: UNIX timestamp of the time when the run should resume.
        :type until: int
        """
        logging.warning(f"Pausing run until {datetime.fromtimestamp(until)}.")
        print("Press CTRL + C to abort run.")
        time.sleep(until)

    def abort(self):
        """
        Abort a run. This skips all remaining checks and immediately end the run.
        Already gathered results can be exported. The run can be resumed if the check
        params were exported.
        """
        for idx in range(self.index, len(self.checks)):
            self.checks[idx].result.status = CheckStatus.ABORTED

        self.state.aborted_check_count = len(self.checks) - self.index

        self.index = len(self.checks)
        self.state.status = EngineStatus.ABORTED
        self.state.end_time = time.time()

        logging.warning("Run successfully aborted.")

    def status(self):
        """
        Print the current status to CLI.
        """
        sys.stdout.write(f"Executed {self.index + 1}/{len(self.checks)} checks\r")
