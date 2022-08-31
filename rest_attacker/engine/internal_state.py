# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Keeps track of the internal state of the engine.
"""

import enum
import time
from datetime import datetime

from rest_attacker.util.response_handler import AccessLimitHandler, RateLimitHandler


class EngineStatus(enum.Enum):
    """
    Status of the engine.
    """
    QUEUED   = "queued"    # run is configured and queued
    RUNNING  = "running"   # run was started
    FINISHED = "finished"  # run finished successfully
    ABORTED  = "aborted"   # run was aborted by engine or user
    ERROR    = "error"     # run failed with error


class InternalState:
    """
    Keeps track of dynamic information about the internal state of the test run.
    """

    def __init__(self) -> None:
        """
        Create a new internal state for an engine.
        """
        # Unix time when the run was started
        self.status = EngineStatus.QUEUED

        # Unix time when the run was started
        self.start_time = time.time()

        # Unix time when the run ended
        self.end_time: float = -1.0

        # Current rate limit
        self.rate_limit = None

        # Current rate limit
        self.access_limit = None

        # Number of planned checks (when the run started)
        self.planned_check_count = 0

        # Number of already executed checks
        self.finished_check_count = 0

        # Statistics for checks
        self.analytical_check_count = 0
        self.security_check_count = 0
        self.error_check_count = 0
        self.skipped_check_count = 0
        self.aborted_check_count = 0

    def set_limit_handler(self, handler):
        """
        Set rate/access limit handlers for the test rub.

        :param handler: Handler used for analyzing the internal state.
        :type handler: RateLimitHandler|AccessLimitHandler
        """
        if isinstance(handler, RateLimitHandler):
            self.rate_limit = handler

        elif isinstance(handler, AccessLimitHandler):
            self.access_limit = handler

    def dump(self) -> dict:
        """
        Generate a dictionary with information from the internal state.
        """
        return {
            "start": datetime.utcfromtimestamp(self.start_time).strftime('%Y-%m-%dT%H-%M-%SZ'),
            "end": datetime.utcfromtimestamp(self.end_time).strftime('%Y-%m-%dT%H-%M-%SZ'),
            "planned": self.planned_check_count,
            "finished": self.finished_check_count,
            "skipped": self.skipped_check_count,
            "aborted": self.aborted_check_count,
            "errors": self.error_check_count,
            "analytical_checks": self.analytical_check_count,
            "security_checks": self.security_check_count,
        }
