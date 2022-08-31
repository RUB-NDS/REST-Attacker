# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Test cases for analyzing HTTP headers.
"""

import logging

from rest_attacker.checks.generic import TestCase
from rest_attacker.checks.types import AuthType, LiveType, TestCaseType
from rest_attacker.report.report import Report
from rest_attacker.util.auth.token_generator import AccessLevelPolicy
from rest_attacker.util.request.request_info import AuthRequestInfo, RequestInfo
from rest_attacker.util.test_result import CheckStatus, IssueType


class FindCustomHeaders(TestCase):
    """
    Searches a response for custom (= non-standardized) HTTP headers.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.RECOMMENDED
    live_type = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        request_info: RequestInfo,
        auth_info: AuthRequestInfo = None
    ) -> None:
        """
        Creates a new check for FindCustomHeaders.

        :param request_info: RequestInfo object that stores data to make the request.
        :type request_info: RequestInfo
        :param auth_info: AuthRequestInfo object that is used for authentication if specified.
        :type auth_info: AuthRequestInfo
        """
        super().__init__(check_id)

        self.request_info = request_info
        self.auth_info = auth_info

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

        response_headers = response.headers

        unique_headers = {}
        for header_id, header in response_headers.items():
            if header_id.lower() in STANDARD_HEADERS or header_id.lower() in COMMON_HEADERS:
                continue

            unique_headers.update({
                header_id: header
            })

        if len(unique_headers) > 0:
            self.result.issue_type = IssueType.CANDIDATE

        else:
            self.result.issue_type = IssueType.NO_CANDIDATE

        self.result.value = unique_headers

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

    @classmethod
    def generate(cls, config, check_id_start=0):
        if not config.descriptions:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for descr in config.descriptions.values():
            for server in descr["servers"]:
                nonauth_request = RequestInfo(
                    server["url"],
                    "/",  # TODO: better default path
                    "get"
                )
                test_cases.append(FindCustomHeaders(cur_check_id, nonauth_request))
                cur_check_id += 1

                if config.auth:
                    auth_request = RequestInfo(
                        server["url"],
                        "/",  # TODO: better default path
                        "get"
                    )
                    auth_info = AuthRequestInfo(
                        config.auth,
                        policy=AccessLevelPolicy.MAX
                    )
                    test_cases.append(FindCustomHeaders(cur_check_id, auth_request, auth_info))
                    cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "request_info": self.request_info.serialize(),
        }

        if self.auth_info:
            serialized.update({
                "auth_info": self.auth_info.serialize(),
            })

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        request_info = RequestInfo.deserialize(serialized.pop("request_info"))
        auth_info = None
        if "auth_info" in serialized:
            auth_info = AuthRequestInfo.deserialize(serialized.pop("auth_info"), config.auth)

        return FindCustomHeaders(check_id, request_info, auth_info)


class FindSecurityHeaders(TestCase):
    """
    Searches a response for security-related HTTP headers.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.RECOMMENDED
    live_type = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        request_info: RequestInfo,
        auth_info: AuthRequestInfo = None
    ) -> None:
        """
        Creates a new check for FindSecurityHeaders.

        :param request_info: RequestInfo object that stores data to make the request.
        :type request_info: RequestInfo
        :param auth_info: AuthRequestInfo object that is used for authentication if specified.
        :type auth_info: AuthRequestInfo
        """
        super().__init__(check_id)

        self.request_info = request_info
        self.auth_info = auth_info

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

        response_headers = response.headers

        security_headers = {}
        for header_id, header in response_headers.items():
            if header_id.lower() in SECURITY_HEADERS:
                security_headers.update({
                    header_id: header
                })

        if len(security_headers) > 0:
            self.result.issue_type = IssueType.CANDIDATE

        else:
            self.result.issue_type = IssueType.NO_CANDIDATE

        self.result.value = security_headers

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

    @classmethod
    def generate(cls, config, check_id_start=0):
        if not config.descriptions:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for descr in config.descriptions.values():
            for server in descr["servers"]:
                nonauth_request = RequestInfo(
                    server["url"],
                    "/",  # TODO: better default path
                    "get"
                )
                test_cases.append(FindSecurityHeaders(cur_check_id, nonauth_request))
                cur_check_id += 1

                if config.auth:
                    auth_request = RequestInfo(
                        server["url"],
                        "/",  # TODO: better default path
                        "get"
                    )
                    auth_info = AuthRequestInfo(
                        config.auth
                    )
                    test_cases.append(FindSecurityHeaders(cur_check_id, auth_request, auth_info))
                    cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "request_info": self.request_info.serialize(),
        }

        if self.auth_info:
            serialized.update({
                "auth_info": self.auth_info.serialize(),
            })

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        request_info = RequestInfo.deserialize(serialized.pop("request_info"))
        auth_info = None
        if "auth_info" in serialized:
            auth_info = AuthRequestInfo.deserialize(serialized.pop("auth_info"), config.auth)

        return FindSecurityHeaders(check_id, request_info, auth_info, **serialized)


class MetaCompareHeaders(TestCase):
    """
    Compare the custom HTTP headers found in two checks of either FindCustomHeaders
    or FindSecurityHeaders.
    """
    test_type = TestCaseType.META
    auth_type = AuthType.NOPE
    live_type = LiveType.OFFLINE
    generates_for = (FindCustomHeaders, FindSecurityHeaders)

    def __init__(self, check_id, check_left: TestCase, check_right: TestCase) -> None:
        """
        Creates a new check for MetaCompareHeaders.

        :param check_left: Left comparison check.
        :type check_left: TestCase
        :param check_right: Right comparison check.
        :type check_right: TestCase
        """
        super().__init__(check_id)

        self.check_left = check_left
        self.check_right = check_right

    def run(self):
        self.result.status = CheckStatus.RUNNING

        if not (self.check_left.result.status is CheckStatus.FINISHED and
                self.check_right.result.status is CheckStatus.FINISHED):
            raise Exception(f"Cannot run meta check {self}. Dependent checks are not finished.")

        unique_headers_left = set()
        unique_headers_right = set()
        common_headers = set()

        for header in self.check_left.result.value:
            if header in self.check_right.result.value:
                common_headers.add(header)

            else:
                unique_headers_left.add(header)

        for header in self.check_right.result.value:
            if header in self.check_left.result.value:
                common_headers.add(header)

            else:
                unique_headers_right.add(header)

        if len(unique_headers_left) == len(unique_headers_right) == 0:
            self.result.issue_type = IssueType.MATCH

        else:
            self.result.issue_type = IssueType.DIFFERENT

        self.result.status = CheckStatus.FINISHED

        self.result.value = {
            "left": list(unique_headers_left),
            "right": list(unique_headers_right),
            "common": list(common_headers),
        }

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start):
        return []

    @classmethod
    def generate(cls, config, check_id_start=0):
        if not config.descriptions:
            return []

        cur_check_id = check_id_start
        test_cases = []
        new_checks = FindCustomHeaders.generate(
            config,
            check_id_start
        )
        test_cases.extend(new_checks)
        cur_check_id += len(new_checks)

        if len(new_checks) >= 2:
            # Only compare if there are enough checks
            test_cases.append(MetaCompareHeaders(cur_check_id, new_checks[0], new_checks[1]))
            cur_check_id += 1

        new_checks = FindSecurityHeaders.generate(
            config,
            check_id_start
        )
        test_cases.extend(new_checks)
        cur_check_id += len(new_checks)

        if len(new_checks) >= 2:
            # same here as above
            test_cases.append(MetaCompareHeaders(cur_check_id, new_checks[0], new_checks[1]))
            cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "check_left_id": self.check_left.check_id,
            "check_right_id": self.check_right.check_id,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        # TODO: Reference checks from deserialized config

        # return MetaCompareHeaders(check_id, **serialized)
        return None


# Standard headers defined in HTTP
# from https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#Response_fields
# and https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
STANDARD_HEADERS = {
    "accept-ch",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-max-age",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "accept-patch",
    "accept-ranges",
    "age",
    "allow",
    "alt-svc",
    "cache-control",
    "connection",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-length",
    "content-location",
    "content-md5",
    "content-range",
    "content-type",
    "date",
    "delta-base",
    "etag",
    "expires",
    "im",
    "last-modified",
    "link",
    "location",
    "p3p",
    "pragma",
    "preference-applied",
    "proxy-authenticate",
    "public-key-pins",
    "referrer-policy",              # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
    "retry-after",
    "server",
    "set-cookie",
    "strict-transport-security",
    "trailer",
    "transfer-encoding",
    "tk",
    "upgrade",
    "vary",
    "via",
    "warning",
    "www-authenticate",
    "x-frame-options",
}

# Common non-standard headers in HTTP
# from https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#Common_non-standard_response_fields
COMMON_HEADERS = {
    "cache-control",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "content-security-policy",
    "content-security-policy-report-only",
    "expect-ct",
    "nel",
    "permissions-policy",
    "refresh",
    "report-to",
    "status",
    "timing-allow-origin",
    "x-content-duration",
    "x-content-security-policy",
    "x-content-type-options",
    "x-correlation-id",
    "x-powered-by",
    "x-redirect-by",
    "x-request-id",
    "x-ua-compatible",
    "x-webkit-csp",
    "x-xss-protection",
}

# Deprecated interesting headers in HTTP
# from https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
# DEPRECATED_HEADERS = {
#     "expect-ct",
#     "set-cookie2",
# }

# Security headers in HTTP
# either used for setting security policy or containing security info
SECURITY_HEADERS = {
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-max-age",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "content-security-policy",
    "content-security-policy-report-only",
    "referrer-policy",
    "set-cookie",
    "strict-transport-security",
    "warning",
    "www-authenticate",
    "x-content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-webkit-csp",
    "x-xss-protection",
}
