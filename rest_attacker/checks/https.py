# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Test cases for analyzing HTTPS support.
"""

import logging

from urllib.parse import urlparse, urlunparse

from rest_attacker.checks.generic import TestCase
from rest_attacker.util.auth.token_generator import AccessLevelPolicy
from rest_attacker.util.openapi.wrapper import OpenAPI
from rest_attacker.util.request.request_info import AuthRequestInfo, RequestInfo
from rest_attacker.util.test_result import CheckStatus, IssueType
from rest_attacker.checks.types import AuthType, LiveType, TestCaseType
from rest_attacker.report.report import Report


class TestHTTPSAvailable(TestCase):
    """
    Checks whether an endpoint can be accessed via HTTPS.
    """
    test_type = TestCaseType.SECURITY
    auth_type = AuthType.OPTIONAL
    live_type = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        request_info: RequestInfo,
        auth_info: AuthRequestInfo = None
    ) -> None:
        """
        Creates a new check for TestHTTPSAvailable.

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

        if urlparse(self.request_info.url)[0] != "https":
            logging.info(
                f"Scheme of provided URL {self.request_info.url} is not HTTPS.")

            # Construct HTTPS URL if none was given
            self.request_info.url = ("https", *self.request_info._url[1:])
            logging.info(
                f"Using constructed URL {self.request_info.url} with HTTPS scheme.")

        auth_data = None
        if self.auth_info:
            auth_data = self.auth_info.auth_gen.get_auth(
                scheme_ids=self.auth_info.scheme_ids,
                scopes=self.auth_info.scopes,
                policy=self.auth_info.policy
            )

        response = self.request_info.send(auth_data)
        self.result.last_response = response

        if 200 <= response.status_code < 300:
            self.result.issue_type = IssueType.OKAY

        else:
            self.result.issue_type = IssueType.PROBLEM

            if 300 <= response.status_code < 400:
                # Check if the redirect URL is HTTPS
                redirect_url = urlparse(response.headers["location"])
                if redirect_url.scheme == 'https':
                    self.result.issue_type = IssueType.OKAY

        self.result.value = {
            "status_code": response.status_code,
            "redirect": 300 <= response.status_code < 400,
        }

        if 300 <= response.status_code < 400:
            self.result.value.update({
                "redirect_url": response.headers["location"]
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
        super().propose(config, check_id_start)

        new_checks = []
        if self.result.value["redirect"]:
            # Check if the redirect works
            new_request = RequestInfo(
                self.result.value["redirect_url"],
                "",  # path should be part of redirect URL
                self.request_info.operation,
                allow_redirects=False
            )
            new_checks.append(TestHTTPSAvailable(check_id_start, new_request))

        logging.debug(f"Proposed {len(new_checks)} new checks from check {self}")

        return new_checks

    @classmethod
    def generate(cls, config, check_id_start=0):
        if not config.descriptions:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for descr in config.descriptions.values():
            for server in descr["servers"]:
                for path_id, path in descr.endpoints.items():
                    for op_id, op in path.items():
                        nonauth_request = RequestInfo(
                            server["url"],
                            path_id,
                            op_id,
                            allow_redirects=False
                        )
                        test_cases.append(TestHTTPSAvailable(cur_check_id, nonauth_request))
                        cur_check_id += 1

                        if config.auth:
                            auth_request = RequestInfo(
                                server["url"],
                                path_id,
                                op_id,
                                allow_redirects=False
                            )
                            auth_info = AuthRequestInfo(
                                config.auth,
                                policy=AccessLevelPolicy.MAX
                            )
                            test_cases.append(
                                TestHTTPSAvailable(cur_check_id, auth_request, auth_info)
                            )
                            cur_check_id += 1

        logging.debug(
            f"Generated {len(test_cases)} checks from test case {cls}")

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

        return TestHTTPSAvailable(check_id, request_info, auth_info, **serialized)


class TestHTTPAvailable(TestCase):
    """
    Checks whether an endpoint can be accessed via plain HTTP (without TLS).
    """
    test_type = TestCaseType.SECURITY
    auth_type = AuthType.OPTIONAL
    live_type = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        request_info: RequestInfo,
        auth_info: AuthRequestInfo = None
    ) -> None:
        """
        Creates a new check for TestHTTPAvailable.

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

        if urlparse(self.request_info.url)[0] != "http":
            logging.info(
                f"Scheme of provided URL {self.request_info.url} is not HTTP.")

            # Construct HTTPS URL if none was given
            self.request_info.url = ("http", *self.request_info._url[1:])
            logging.info(
                f"Using constructed URL {self.request_info.url} with HTTP scheme.")

        auth_data = None
        if self.auth_info:
            auth_data = self.auth_info.auth_gen.get_auth(
                scheme_ids=self.auth_info.scheme_ids,
                scopes=self.auth_info.scopes,
                policy=self.auth_info.policy
            )

        response = self.request_info.send(auth_data)
        self.result.last_response = response

        if 200 <= response.status_code < 300:
            self.result.issue_type = IssueType.FLAW

        else:
            self.result.issue_type = IssueType.OKAY

            if 300 <= response.status_code < 400:
                # Check if the redirect URL is HTTPS
                redirect_url = urlparse(response.headers["location"])
                if redirect_url.scheme != 'https':
                    self.result.issue_type = IssueType.PROBLEM

        self.result.status = CheckStatus.FINISHED

        self.result.value = {
            "status_code": response.status_code,
            "redirect": 300 <= response.status_code < 400,
        }

        if 300 <= response.status_code < 400:
            self.result.value.update({
                "redirect_url": response.headers["location"]
            })

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
        super().propose(config, check_id_start)

        new_checks = []
        if self.result.value["redirect"]:
            # Check if the redirect is HTTPS
            new_request = RequestInfo(
                self.result.value["redirect_url"],
                "",  # path should be part of redirect URL
                self.request_info.operation,
                allow_redirects=False
            )
            new_checks.append(TestHTTPSAvailable(check_id_start, new_request))

        logging.debug(f"Proposed {len(new_checks)} new checks from check {self}")

        return new_checks

    @classmethod
    def generate(cls, config, check_id_start=0):
        if not config.descriptions:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for descr in config.descriptions.values():
            for server in descr["servers"]:
                for path_id, path in descr.endpoints.items():
                    for op_id, op in path.items():
                        nonauth_request = RequestInfo(
                            server["url"],
                            path_id,
                            op_id,
                            allow_redirects=False
                        )
                        test_cases.append(TestHTTPAvailable(cur_check_id, nonauth_request))
                        cur_check_id += 1

                        if config.auth:
                            auth_request = RequestInfo(
                                server["url"],
                                path_id,
                                op_id,
                                allow_redirects=False
                            )
                            auth_info = AuthRequestInfo(config.auth)
                            test_cases.append(
                                TestHTTPAvailable(cur_check_id, auth_request, auth_info)
                            )
                            cur_check_id += 1

        logging.debug(
            f"Generated {len(test_cases)} checks from test case {cls}")

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

        return TestHTTPAvailable(check_id, request_info, auth_info, **serialized)


class TestDescriptionURLs(TestCase):
    """
    Checks which protocol schemes are defined for servers in the API description.
    """
    test_type = TestCaseType.SECURITY
    auth_type = AuthType.NOPE
    live_type = LiveType.OFFLINE

    def __init__(self, check_id: int, description: OpenAPI) -> None:
        """
        Creates a new check for TestDescriptionURLs.

        :param description: API description.
        :type description: OpenAPI
        """
        super().__init__(check_id)

        self.description = description

    def run(self):
        self.result.status = CheckStatus.RUNNING

        try:
            global_server_urls = self.description["servers"]

        except KeyError as error:
            logging.warning("Could not find 'servers' entry in API description.")
            self.result.error = error
            self.result.finished = False
            return

        self.result.value = {
            "http_urls": [],
            "https_urls": [],
            "unknown_scheme_urls": [],
            "paths_with_servers": []
        }

        paths_with_servers = set()

        # Global server URLs
        for server_url in global_server_urls:
            url = urlparse(server_url["url"])
            if url.scheme == "http":
                self.result.value["http_urls"].append(server_url)

            elif url.scheme == "https":
                self.result.value["https_urls"].append(server_url)

            else:
                self.result.value["unknown_scheme_urls"].append(server_url)

        # Endpoint server URLs
        for path_id, path in self.description.endpoints.items():
            if not "servers" in path.keys():
                continue

            for server_url in path["servers"]:
                url = urlparse(server_url["url"])
                if url.scheme == "http":
                    self.result.value["http_urls"].append(server_url)
                    paths_with_servers.update(path_id)

                elif url.scheme == "https":
                    self.result.value["https_urls"].append(server_url)
                    paths_with_servers.update(path_id)

                else:
                    self.result.value["unknown_scheme_urls"].append(server_url)
                    paths_with_servers.update(path_id)

        self.result.value["paths_with_servers"] = sorted(list(paths_with_servers))

        if len(self.result.value["http_urls"]) > 0:
            self.result.issue_type = IssueType.FLAW

        if len(self.result.value["unknown_scheme_urls"]) > 0:
            self.result.issue_type = IssueType.PROBLEM

        else:
            self.result.issue_type = IssueType.OKAY

        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start):
        super().propose(config, check_id_start)

        new_checks = []
        # Check the found URls and see if they work
        for http_url in self.result.value["http_urls"]:
            new_request = RequestInfo(
                http_url['url'],
                "/",
                "get"
            )
            if config.auth:
                auth_info = AuthRequestInfo(
                    config.auth,
                    policy=AccessLevelPolicy.MAX
                )

            else:
                auth_info = None

            new_checks.append(TestHTTPAvailable(
                check_id_start,
                new_request,
                auth_info
            ))

            check_id_start += 1

        for https_url in self.result.value["https_urls"]:
            new_request = RequestInfo(
                https_url['url'],
                "/",
                "get"
            )
            if config.auth:
                auth_info = AuthRequestInfo(
                    config.auth,
                    policy=AccessLevelPolicy.MAX
                )

            else:
                auth_info = None

            new_checks.append(TestHTTPAvailable(
                check_id_start,
                new_request,
                auth_info
            ))

            check_id_start += 1

        logging.debug(f"Proposed {len(new_checks)} new checks from check {self}")

        return new_checks

    @classmethod
    def generate(cls, config, check_id_start=0):
        if not config.descriptions:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for descr in config.descriptions.values():
            test_cases.append(TestDescriptionURLs(cur_check_id, descr))

            cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "description": self.description.description_id,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        description = config.descriptions[serialized["description"]]

        return TestDescriptionURLs(check_id, description)
