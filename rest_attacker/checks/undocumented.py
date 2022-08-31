# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Test cases for analyzing undocumented behaviour.
"""

import logging
from rest_attacker.util.request.request_info import AuthRequestInfo, RequestInfo
from rest_attacker.util.test_result import CheckStatus, IssueType
from rest_attacker.checks.types import AuthType, LiveType, TestCaseType
from rest_attacker.checks.generic import TestCase
from rest_attacker.report.report import Report


class TestOptionsHTTPMethod(TestCase):
    """
    Checks which HTTP methods are allowed for a path using the OPTIONS HTTP method.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.RECOMMENDED
    live_type = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        request_info: RequestInfo,
        auth_info: AuthRequestInfo = None,
        claims=None
    ) -> None:
        """
        Creates a new check for TestOptionsHTTPMethod.

        :param request_info: RequestInfo object that stores data to make the request.
        :type request_info: RequestInfo
        :param auth_info: AuthRequestInfo object that is used for authentication if specified.
        :type auth_info: AuthRequestInfo
        :param claims: Methods that the endpoint claims to support.
        :type claims: list[str]
        """
        super().__init__(check_id)

        self.request_info = request_info
        self.auth_info = auth_info

        self.claims = claims

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

        # if response.status_code != 204:
        #     self.result.status = CheckStatus.ERROR
        #     self.result.error = Exception(
        #         "Could not retrieve allowed methods "
        #         f"for endpoint {self.request_info.endpoint_url} using OPTIONS method")
        #     return

        self.result.value = {
            "path": self.request_info.path,
            "status_code": response.status_code,
        }

        if "allow" in response.headers.keys():
            allowed_methods = response.headers["allow"].lower().split(", ")
            self.result.value["allowed_methods"] = allowed_methods

        elif "access-control-allow-methods" in response.headers.keys():
            # CORS sometimes reveals same info
            allowed_methods = response.headers["access-control-allow-methods"].lower().split(", ")
            self.result.value["allowed_methods_cors"] = allowed_methods

        else:
            self.result.status = CheckStatus.ERROR
            self.result.error = Exception(
                "Could not retrieve allowed methods "
                f"for path {self.request_info.path} using OPTIONS method")
            return

        if len(allowed_methods) == 1 and "OPTIONS" in allowed_methods:
            # only method is OPTIONS
            self.result.issue_type = IssueType.NO_CANDIDATE

        else:
            self.result.issue_type = IssueType.CANDIDATE

            if self.claims:
                # Check if claims and results match up
                wrong_claims = list(set(self.claims) - set(allowed_methods))
                missing_claims = list(set(allowed_methods) - set(self.claims))

                self.result.value.update({
                    "claims": {
                        "claimed": self.claims,
                        "wrong_claims": sorted(wrong_claims),
                        "missing_claims": sorted(missing_claims),
                    }
                })

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
            server_urls = []
            for server in descr["servers"]:
                server_urls.append(server["url"])

            for path_id, path_item in descr.endpoints.items():
                claims = list(path_item.keys())
                for server_url in server_urls:
                    auth_request = RequestInfo(
                        server_url,
                        path_id,
                        "options"
                    )

                    if config.auth:
                        auth_info = AuthRequestInfo(config.auth)

                    else:
                        auth_info = None

                    test_cases.append(TestOptionsHTTPMethod(cur_check_id,
                                                            auth_request,
                                                            auth_info,
                                                            claims=claims))
                    cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "request_info": self.request_info.serialize(),
            "claims": self.claims,
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

        return TestOptionsHTTPMethod(check_id, request_info, auth_info, **serialized)


class MetaTestOptionsHTTPMethod(TestCase):
    """
    Aggregate the results of TestOptionsHTTPMethod. This only aggregates results
    of checks for which 'claims' where defined.
    """
    test_type = TestCaseType.META
    auth_type = AuthType.NOPE
    live_type = LiveType.OFFLINE
    generates_for = (TestOptionsHTTPMethod,)

    def __init__(self, check_id, checks=[]) -> None:
        """
        Creates a new check for MetaTestOptionsHTTPMethod.

        :param checks: List of checks investigated.
        :type checks: list[TestOptionsHTTPMethod]
        """
        super().__init__(check_id)

        self.checks = checks

    def run(self):
        self.result.status = CheckStatus.RUNNING

        if any(check.result.status == CheckStatus.QUEUED for check in self.checks):
            self.result.status = CheckStatus.ERROR
            self.result.error = Exception(
                f"Cannot run meta check {self}. Some checks are not finished.")
            return

        # Sort out error and skipped checks
        checks = []
        for check in self.checks:
            if check.result.status == CheckStatus.FINISHED:
                checks.append(check)

        self.result.value = {
            "affected_paths": 0,
            "skipped_paths": 0,     # Skipped because of no claims set
            "total_wrong_claims": 0,
            "total_missing_claims": 0,
            "paths": []
        }
        for check in checks:
            if check.result.issue_type == IssueType.CANDIDATE:
                if not "claims" in check.result.value.keys():
                    # Only aggregate if claims exists
                    self.result.value["skipped_paths"] += 1
                    continue

                path = check.result.value["path"]
                claims = check.result.value["claims"]

                if path not in self.result.value["paths"]:
                    self.result.value["affected_paths"] += 1

                self.result.value["paths"].append(path)
                self.result.value["total_wrong_claims"] += len(claims["wrong_claims"])
                self.result.value["total_missing_claims"] += len(claims["missing_claims"])

        if self.result.value["affected_paths"] > 0:
            self.result.issue_type = IssueType.CANDIDATE

        else:
            self.result.issue_type = IssueType.NO_CANDIDATE

        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start):
        return []

    @ classmethod
    def generate(cls, config, check_id_start=0):
        subchecks = TestOptionsHTTPMethod.generate(config, check_id_start)

        test_cases = []
        test_cases.extend(subchecks)
        check_id_start += len(subchecks)

        test_cases.append(MetaTestOptionsHTTPMethod(check_id_start, subchecks))

        check_id_start += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "check_ids": [check.check_id for check in self.checks],
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        # TODO: Reference checks from deserialized config

        # return MetaTestOptionsHTTPMethod(check_id, **serialized)
        return None


class TestAllowedHTTPMethod(TestCase):
    """
    Checks if a defined path supports a specified HTTP method/API operation.
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
        Creates a new check for TestAllowedHTTPMethod.

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

        self.result.value = {
            "path": self.request_info.path,
            "http_method": self.request_info.operation,
            "status_code": response.status_code
        }
        if response.status_code == 405:
            # 405: Method not allowed
            self.result.issue_type = IssueType.NO_CANDIDATE

        else:
            # Anything else might indicate access
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

    @classmethod
    def generate(cls, config, check_id_start=0):
        if not config.descriptions:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for descr in config.descriptions.values():
            server_urls = []
            for server in descr["servers"]:
                server_urls.append(server["url"])

            for path_id, path in descr.endpoints.items():
                op_names = path.keys()

                for op in HTTP_REQUEST_METHODS:
                    if op in op_names:
                        continue

                    for server_url in server_urls:
                        auth_request = RequestInfo(
                            server_url,
                            path_id,
                            op
                        )

                        if config.auth:
                            auth_info = AuthRequestInfo(config.auth)

                        else:
                            auth_info = None

                        test_cases.append(TestAllowedHTTPMethod(cur_check_id,
                                                                auth_request,
                                                                auth_info))
                        cur_check_id += 1

                # This also check for WebDAV which is unnecessary in most cases
                # for op in COMMON_WEBDAV_REQUEST_METHODS:
                #     if op in op_names:
                #         continue

                #     _, auth_header = generate_auth(config)
                #     for server_url in server_urls:
                #         test_cases.append(TestAllowedHTTPMethod(cur_check_id,
                #                                                 server_url,
                #                                                 path_name,
                #                                                 op,
                #                                                 headers=auth_header))

                #         cur_check_id += 1

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
        auth_info = AuthRequestInfo.deserialize(serialized.pop("auth_info"), config.auth)

        return TestAllowedHTTPMethod(check_id, request_info, auth_info, **serialized)


class MetaTestAllowedHTTPMethod(TestCase):
    """
    Aggregate the results of TestAllowedHTTPMethod.
    """
    test_type = TestCaseType.META
    auth_type = AuthType.NOPE
    live_type = LiveType.OFFLINE
    generates_for = (TestAllowedHTTPMethod,)

    def __init__(self, check_id, checks: list[TestCase] = []) -> None:
        """
        Creates a new check for MetaTestAllowedHTTPMethod.

        :param checks: List of checks investigated.
        :type checks: list[TestAllowedHTTPMethod]
        """
        super().__init__(check_id)

        self.checks = checks

    def run(self):
        self.result.status = CheckStatus.RUNNING

        if not all(check.result.status == CheckStatus.FINISHED for check in self.checks):
            raise Exception(f"Cannot run meta check {self}. Dependent checks are not finished.")

        self.result.value = {
            "affected_paths": 0,
            "affected_methods": 0,
            "found_methods": {}
        }
        self.result.issue_type = IssueType.NO_CANDIDATE
        for check in self.checks:
            if check.result.issue_type == IssueType.CANDIDATE:
                self.result.value["affected_methods"] += 1
                path = check.result.value["path"]
                method = check.result.value["http_method"]
                status_code = check.result.value["status_code"]

                if path not in self.result.value["found_methods"]:
                    self.result.value["affected_paths"] += 1
                    self.result.value["found_methods"][path] = {
                        "undocumented_methods": []
                    }

                self.result.value["found_methods"][path]["undocumented_methods"].append(
                    {
                        "method": method,
                        "status_code": status_code
                    }
                )
                self.result.issue_type = IssueType.CANDIDATE

        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start):
        return []

    @ classmethod
    def generate(cls, config, check_id_start=0):
        subchecks = TestAllowedHTTPMethod.generate(config, check_id_start)

        test_cases = []
        test_cases.extend(subchecks)
        check_id_start += len(subchecks)

        test_cases.append(MetaTestAllowedHTTPMethod(check_id_start, subchecks))

        check_id_start += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "check_ids": [check.check_id for check in self.checks],
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        # TODO: Reference checks from deserialized config

        # return MetaTestAllowedHTTPMethod(check_id, **serialized)
        return None


HTTP_REQUEST_METHODS = [
    # CRUD methods
    "get",
    "post",
    "put",
    "delete",
    "patch",


    # Other HTTP methods; ignored for now
    # "head",     # should be same result as get
    # "connect",  # not relevant (?)
    # "options",  # tested in extra test case
    # "trace",    # not relevant (?)
]

# Methods that hint at WebDAV usage
COMMON_WEBDAV_REQUEST_METHODS = [
    "copy",
    "lock",
    "mkcol",
    "move",
    "propfind",
    "proppatch",
    "unlock",
]
