# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Handles responses to HTTP requests made by checks for the main engine.
"""

import time
from requests import Response

from rest_attacker.util.request.request_info import AuthRequestInfo, RequestInfo


class RateLimitHandler:
    """
    Manages the rate limit from the last response.
    """

    def __init__(
            self,
            max_limit=1000,
            remaining=1000,
            reset_time: int = 3600,
            headers: dict[str, str] = {}
    ) -> None:
        """
        Create a new RateLimitHandler.

        :param max_limit: Maximum number of requests until the rate limit must be reset.
        :type max_limit: int
        :param remaining: Remaining requests until max rate limit is reached.
        :type remaining: int
        :param reset_time: Seconds to wait until next request can be made after rate limit has been reached.
        :type reset_time: int
        :param headers: Identifiers for response headers indicating the current rate limit status.
                        Hints for max, remaining and reset time can be given.
        :type headers: dict[str,str]
        """
        self.max_limit = max_limit
        self.remaining = remaining

        self.reset_time = reset_time

        self.header_id_max = headers.get("rate_limit_max", None)
        self.header_id_cur = headers.get("rate_limit_remaining", None)
        self.header_id_reset = headers.get("rate_limit_reset", None)

    def setup(self, response: Response) -> None:
        """
        Initialize the handle from the first response.
        """
        if self.header_id_max and self.header_id_max in response.headers.keys():
            self.max_limit = int(response.headers[self.header_id_max])

        if self.header_id_cur and self.header_id_cur in response.headers.keys():
            self.remaining = int(response.headers[self.header_id_cur])

        if self.header_id_reset and self.header_id_reset in response.headers.keys():
            self.reset_time = int(response.headers[self.header_id_reset])

    def reset(self, response: Response = None) -> None:
        """
        Reset the limit to the max limit or use the header values from the response.
        """
        if self.header_id_max and response:
            self.max_limit = int(response.headers[self.header_id_max])

        if self.header_id_cur and response:
            self.remaining = int(response.headers[self.header_id_cur])

        else:
            self.remaining = self.max_limit

        if self.header_id_reset and response:
            self.reset_time = int(response.headers[self.header_id_reset])

    def update(self, response: Response) -> bool:
        """
        Update the handler from a response. Return True if limit has been reached.
        """
        if response.status_code == 429:
            return False

        if self.header_id_cur and self.header_id_cur in response.headers.keys():
            self.remaining = int(response.headers[self.header_id_cur])

        else:
            self.remaining -= 1

        if self.header_id_reset and self.header_id_reset in response.headers.keys():
            self.reset_time = int(response.headers[self.header_id_reset])

        return self.remaining <= 0

    def get_reset_wait_time(self):
        """
        Get the time required until the rate limit resets.
        """
        current_time = time.time()
        required_time = int(self.reset_time - current_time) + 1

        return required_time


class AccessLimitHandler:
    """
    Manages responses to reaching the access limit of a service.
    """

    def __init__(
        self,
        test_request: RequestInfo,
        auth_info: AuthRequestInfo,
        interval: int = 10
    ) -> None:
        """
        Create a new AccessLimitHandler.

        :param test_request: Request that is used to test whether the access limit has been reached.
                             This should ideally be a GET operation to an endpoint that is protected
                             with access control measures. The resource should be accessible by the
                             currently active user.
        :type test_request: RequestInfo
        :param auth_info: Auth information for authenticating/authorizing the request.
        :type auth_info: AuthRequestInfo
        :param interval: Number of (online) checks that can be executed before the test request is sent.
        :type interval: int
        """
        self.test_request = test_request
        self.auth_info = auth_info

        self.interval = interval

        # Current position in the interval
        self.current_pos = interval

        # ID of the check before the last successful AccessLimitHandler check.
        self.last_check_id = None

    def reset(self) -> None:
        """
        Reset the interval.
        """
        self.current_pos = 0

    def update(self) -> bool:
        """
        Check if the endpoint specified in the test request is still accessible. Return True if limit has been reached
        """
        auth_data = self.auth_info.auth_gen.get_auth(
            scheme_ids=self.auth_info.scheme_ids,
            scopes=self.auth_info.scopes,
            policy=self.auth_info.policy
        )
        response = self.test_request.send(auth_data=auth_data)

        if response.status_code == 429:
            # Handled by RateLimitHandler
            # TODO: More verbose return values than bool types may be helpful here
            return False

        if 200 <= response.status_code < 300:
            return False

        return True
