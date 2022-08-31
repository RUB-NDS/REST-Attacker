# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Test cases for miscellaneous getting resource values via the API.
"""

from rest_attacker.checks.generic import TestCase
from rest_attacker.checks.types import AuthType, LiveType, TestCaseType
from rest_attacker.report.report import Report
from rest_attacker.util.request.request_info import AuthRequestInfo, RequestInfo
from rest_attacker.util.test_result import CheckStatus, IssueType


class GetHeaders(TestCase):
    """
    Get value of a specified HTTP header in a HTTP response.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.RECOMMENDED
    live_type = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        request_info: RequestInfo,
        auth_info: AuthRequestInfo = None,
        headers=[]
    ) -> None:
        """
        Creates a new check for GetHeaders.

        :param request_info: RequestInfo object that stores data to make the request.
        :type request_info: RequestInfo
        :param auth_info: AuthRequestInfo object that is used for authentication if specified.
        :type auth_info: AuthRequestInfo
        :param parameters: List of header IDs to fetch.
        :type parameters: list[tuple[str]]
        """
        super().__init__(check_id)

        self.request_info = request_info
        self.auth_info = auth_info

        self.headers = headers

    def run(self):
        self.result.status = CheckStatus.RUNNING

        auth_data = None
        if self.auth_info:
            auth_data = self.auth_info.auth_gen.get_auth(
                scheme_ids=self.auth_info.scheme_ids,
                scopes=self.auth_info.scopes,
                policy=self.auth_info.policy
            )

        response = self.request_info.send(auth_data)
        self.result.last_response = response

        self.result.value = {}
        for header_id in self.headers:
            self.result.value.update({
                header_id: response.headers[header_id]
            })

        self.result.issue_type = IssueType.CANDIDATE
        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Curl request
        if self.auth_info:
            # TODO: Save used auth payload somewhere
            # auth_data = self.auth_info.auth_gen.get_auth()
            report["curl"] = self.request_info.get_curl_command()

        else:
            report["curl"] = self.request_info.get_curl_command()

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start):
        return []

    @ classmethod
    def generate(cls, config, check_id_start=0):
        # No checks generated
        return []

    def serialize(self) -> dict:
        serialized = {
            "request_info": self.request_info.serialize(),
            "headers": self.headers
        }

        if self.auth_info:
            serialized.update({
                "auth_info": self.auth_info.serialize(),
            })

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        request_info = RequestInfo.deserialize(serialized.pop("request_info"))
        auth_info = AuthRequestInfo.deserialize(serialized.pop("auth_info"), config.auth)

        return GetParameters(check_id, request_info, auth_info, **serialized)


class GetParameters(TestCase):
    """
    Get value of a specified JSON key in a HTTP response body.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.RECOMMENDED
    live_type = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        request_info: RequestInfo,
        auth_info: AuthRequestInfo = None,
        parameters=[]
    ) -> None:
        """
        Creates a new check for GetParameters.

        :param request_info: RequestInfo object that stores data to make the request.
        :type request_info: RequestInfo
        :param auth_info: AuthRequestInfo object that is used for authentication if specified.
        :type auth_info: AuthRequestInfo
        :param parameters: List of parameter paths to fetch. Parameter paths are
                           passed as string tuples..
        :type parameters: list[tuple[str]]
        """
        super().__init__(check_id)

        self.request_info = request_info
        self.auth_info = auth_info

        self.parameters = parameters

    def run(self):
        self.result.status = CheckStatus.RUNNING

        auth_data = None
        if self.auth_info:
            auth_data = self.auth_info.auth_gen.get_auth(
                scheme_ids=self.auth_info.scheme_ids,
                scopes=self.auth_info.scopes,
                policy=self.auth_info.policy
            )

        response = self.request_info.send(auth_data)
        self.result.last_response = response

        if 400 <= response.status_code < 500:
            self.result.status = CheckStatus.ERROR
            return

        response_body = response.json()

        self.result.value = {}
        for param in self.parameters:
            current_item = response_body
            for param_part in param:
                current_item = current_item[param_part]

            self.result.value.update({
                "/".join(param): current_item
            })

        self.result.issue_type = IssueType.CANDIDATE
        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Curl request
        if self.auth_info:
            # TODO: Save used auth payload somewhere
            # auth_data = self.auth_info.auth_gen.get_auth()
            report["curl"] = self.request_info.get_curl_command()

        else:
            report["curl"] = self.request_info.get_curl_command()

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start):
        return []

    @ classmethod
    def generate(cls, config, check_id_start=0):
        # No checks generated
        return []

    def serialize(self) -> dict:
        serialized = {
            "request_info": self.request_info.serialize(),
            "parameters": self.parameters
        }

        if self.auth_info:
            serialized.update({
                "auth_info": self.auth_info.serialize(),
            })

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        request_info = RequestInfo.deserialize(serialized.pop("request_info"))
        auth_info = AuthRequestInfo.deserialize(serialized.pop("auth_info"), config.auth)

        return GetParameters(check_id, request_info, auth_info, **serialized)
