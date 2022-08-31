# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Test cases for analyzing scope handling.
"""
import typing

import logging

from oauthlib.oauth2.rfc6749.tokens import OAuth2Token

from rest_attacker.checks.generic import TestCase
from rest_attacker.checks.types import AuthType, LiveType, TestCaseType
from rest_attacker.report.report import Report
from rest_attacker.util.auth.token_generator import AccessLevelPolicy, ClientInfo, OAuth2TokenGenerator
from rest_attacker.util.openapi.wrapper import OpenAPI
from rest_attacker.util.request.request_info import AuthRequestInfo, RequestInfo
from rest_attacker.util.test_result import CheckStatus, IssueType


class CheckScopesEndpoint(TestCase):
    """
    Check if an endpoint can be accessed with a specified authorization level (using OAuth2 scopes).
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.REQUIRED
    live_type = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        request_info: RequestInfo,
        auth_info: AuthRequestInfo
    ) -> None:
        """
        Creates a new check for CheckScopesEndpoint.

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

        if 200 < response.status_code < 300:
            self.result.issue_type = IssueType.CANDIDATE
            self.result.value = {
                "accepted": True
            }

        else:
            self.result.issue_type = IssueType.NO_CANDIDATE
            self.result.value = {
                "accepted": False
            }

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

        if not config.auth:
            return []

        cur_check_id = check_id_start
        test_cases = []

        # TODO: Reactivate for services with no rate limits or
        # services that actually define their security requirements
        # Currently this test case drains the rate/access limit significantly :(
        return test_cases

        for descr in config.descriptions.values():
            # Check for security schemes that support scoped security, e.g. OAuth
            if "components" not in descr:
                continue

            if "security_schemes" not in descr["components"]:
                continue

            scoped_schemes = set()
            for scheme_id, scheme in descr["components"]["security_schemes"].items():
                if scheme["type"] != "oauth2":
                    # TODO: Other scoped schemes?
                    continue

                scoped_schemes.add(scheme_id)

            if len(scoped_schemes) == 0:
                continue

            for path_id, path_item in descr["paths"]:
                if "parameters" in path_item.keys():
                    # TODO: Analyze paths with parameters
                    continue

                for op_id, op in path_item.items():
                    if "parameters" in op.keys():
                        # TODO: Analyze operations with parameters
                        continue

                    for server in descr["servers"]:
                        nonauth_request = RequestInfo(
                            server["url"],
                            path_id,
                            op_id
                        )
                        test_cases.append(CheckScopesEndpoint(cur_check_id, nonauth_request))
                        cur_check_id += 1

                        auth_request = RequestInfo(
                            server["url"],
                            path_id,
                            op_id
                        )
                        auth_info = AuthRequestInfo(
                            config.auth
                        )
                        test_cases.append(CheckScopesEndpoint(
                            cur_check_id, auth_request, auth_info))
                        cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "request_info": self.request_info.serialize(),
            "auth_info": self.auth_info.serialize(),
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        request_info = RequestInfo.deserialize(serialized.pop("request_info"))
        auth_info = AuthRequestInfo.deserialize(serialized.pop("auth_info"), config.auth)

        return CheckScopesEndpoint(check_id, request_info, auth_info, **serialized)


class ScopeMappingDescription(TestCase):
    """
    Creates a mapping of OAuth2 scopes to the endpoints they can access based on the information
    in an OpenAPI description.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.NOPE
    live_type = LiveType.OFFLINE

    def __init__(self, check_id: int, description: OpenAPI) -> None:
        """
        Creates a new check for ScopeMappingDescription.

        :param description: API description.
        :type description: OpenAPI
        """
        super().__init__(check_id)

        self.description = description

    def run(self):
        self.result.status = CheckStatus.RUNNING

        # Check for security schemes that support scoped security, e.g. OAuth
        if "components" not in self.description:
            logging.debug("API description has no components defined.")
            self.result.status = CheckStatus.SKIPPED
            return

        if "securitySchemes" not in self.description["components"]:
            logging.debug("API description has no security schemes defined.")
            self.result.status = CheckStatus.SKIPPED
            return

        scoped_schemes = set()
        scopemap = {}
        for scheme_id, scheme in self.description["components"]["securitySchemes"].items():
            if scheme["type"] != "oauth2":
                # TODO: Other scoped schemes?
                continue

            scoped_schemes.add(scheme_id)
            # Create scopemap from available scopes
            for flow in scheme["flows"].values():
                for scope_id in flow["scopes"]:
                    scopemap[scope_id] = []

        if len(scoped_schemes) == 0:
            logging.debug("API description has defined no scoped schemes (e.g. OAuth2).")
            self.result.status = CheckStatus.SKIPPED
            return

        # Top-level security requirements
        top_level_requirements = []
        if "security" in self.description:
            top_level_requirements = self.description["security"]
            if len(top_level_requirements) == 0:
                # This is non-standard because there should always be at least one object
                # No security --> Empty security requirement object
                logging.debug("API description has empty security requirements.")

        # Operation-level security requirements
        for path_id, path in self.description.endpoints.items():
            for op_id, op in path.items():
                if "security" not in op.keys():
                    # Use top-level requirements
                    requirements = top_level_requirements

                else:
                    requirements = op["security"]

                    if len(op["security"]) == 0:
                        # This is non-standard because there should always be at least one object
                        # No security --> Empty security requirement object
                        logging.debug(f"{op_id} / {path_id} has empty security requirements.")

                for requirement in requirements:
                    requirement_name = list(requirement.keys())[0]
                    if requirement_name not in scoped_schemes:
                        continue

                    for scopename in requirement[requirement_name]:
                        if scopename not in scopemap.keys():
                            # Shouldn't happen, but maybe interesting for analysis?
                            logging.debug(
                                f"Scope {scopename} required for {op_id} / {path_id} "
                                "not declared in security schemes.")
                            scopemap[scopename] = []

                        scopemap[scopename].append((path_id, op_id))

        self.result.issue_type = IssueType.CANDIDATE
        self.result.value = scopemap

        self.result.status = CheckStatus.FINISHED

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
        for descr in config.descriptions.values():
            test_cases.append(ScopeMappingDescription(cur_check_id, descr))

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

        return ScopeMappingDescription(check_id, description)


class CompareTokenScopesToClientScopes(TestCase):
    """
    Check if scopes assigned to an OAuth2 token are available to the client that requests
    the token.
    """
    test_type: TestCaseType = TestCaseType.SECURITY
    auth_type: AuthType = AuthType.NOPE
    live_type: LiveType = LiveType.OFFLINE

    def __init__(
        self,
        check_id: int,
        token: OAuth2Token,
        client_info: ClientInfo
    ) -> None:
        """
        Create a new check for TestTokenRequestScopeOmit.

        :param token: OAuth2 token with assigned scopes.
        :type token: OAuth2Token
        :param client_info: Information about the client for which the token was issued.
        :type client_info: ClientInfo
        """
        super().__init__(check_id)

        self.token = token
        self.client_info = client_info

    def run(self) -> None:
        self.result.status = CheckStatus.RUNNING

        # Check if we received any scopes that the client does not support
        received_scopes = set(self.token.scopes)
        extra_scopes = received_scopes.difference(set(self.client_info.supported_scopes))
        self.result.value = {}
        if len(extra_scopes) > 0:
            # Privilege escalation?
            self.result.issue_type = IssueType.FLAW

        else:
            self.result.issue_type = IssueType.OKAY

        self.result.value["supported_by_client"] = self.client_info.supported_scopes
        self.result.value["unsupported_by_client"] = sorted(list(extra_scopes))

        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start) -> list:
        return []

    @classmethod
    def generate(cls, config, check_id_start=0) -> list:
        if not config.auth:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for cred in config.credentials.values():
            if isinstance(cred, OAuth2TokenGenerator):
                token = cred.get_token()
                test_cases.append(CompareTokenScopesToClientScopes(
                    cur_check_id, token, cred.client_info))
                cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "token": self.token,
            "client_id": self.client_info.client_id,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        token = serialized["token"]

        client_info = None
        for cred in config.credentials.values():
            if isinstance(cred, OAuth2TokenGenerator):
                if cred.client_info.client_id == serialized["client_id"]:
                    client_info = cred.client_info
                    break

        if not client_info:
            raise Exception(f"Client with ID {serialized['client_id']} not found.")

        serialized.pop("client_id")

        return CompareTokenScopesToClientScopes(check_id, token, client_info)


class TestTokenRequestScopeOmit(TestCase):
    """
    Check which scopes are assigned to an OAuth2 token if the scope parameter is omitted.
    This means the OAuth2 authorization request is sent without a scope parameter.
    """
    test_type: TestCaseType = TestCaseType.ANALYTICAL
    auth_type: AuthType = AuthType.REQUIRED
    live_type: LiveType = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        token_gen: OAuth2TokenGenerator,
        grant_type: str,
        claims: list[str] = None
    ) -> None:
        """
        Create a new check for TestTokenRequestScopeOmit.

        :param token_gen: Token Generator for OAuth2 tokens.
        :type token_gen: OAuth2TokenGenerator
        :param grant_type: Grant used to request the token (code or token).
        :type grant_type: str
        :param claims: Optional list of scopes that are expected to be returned.
        :type claims: list[str]
        """
        super().__init__(check_id)

        self.token_gen = token_gen
        self.grant_type = grant_type
        self.claims = claims
        self.token: OAuth2Token = None

    def run(self) -> None:
        self.result.status = CheckStatus.RUNNING

        try:
            # Force omission of scope parameter
            self.token = self.token_gen.request_new_token(
                scopes=None,
                grant_type=self.grant_type,
                policy=AccessLevelPolicy.NOPE
            )

        except Exception as err:
            self.result.error = err
            self.token = None

        self.result.value = {}

        if not self.token:
            # Exit if no token could be created
            logging.warning(f"No token received for checking {repr(self)}.")
            self.result.issue_type = IssueType.NO_CANDIDATE
            self.result.status = CheckStatus.ERROR
            return

        if not self.token.scopes:
            # Auth server should indicate scope according to
            # https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
            logging.info(f"No scope information received in token.")
            self.result.issue_type = IssueType.CANDIDATE
            self.result.value["received_scopes"] = None
            self.result.status = CheckStatus.FINISHED
            return

        self.result.issue_type = IssueType.CANDIDATE
        self.result.value["received_scopes"] = self.token.scopes
        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start) -> list:
        cur_check_id = check_id_start
        test_cases = []
        if self.result.value["received_scopes"] is not None:
            test_cases.append(CompareTokenScopesToClientScopes(
                cur_check_id, self.token, self.token_gen.client_info))
            cur_check_id += 1

        return []

    @classmethod
    def generate(cls, config, check_id_start=0) -> list:
        if not config.credentials:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for cred in config.credentials.values():
            if not isinstance(cred, OAuth2TokenGenerator):
                continue

            if "scope_reqired" in cred.client_info.flags:
                continue

            if 'code' in cred.client_info.supported_grants:
                test_cases.append(TestTokenRequestScopeOmit(cur_check_id, cred, 'code'))
                cur_check_id += 1

            if 'token' in cred.client_info.supported_grants:
                test_cases.append(TestTokenRequestScopeOmit(cur_check_id, cred, 'token'))
                cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "client_id": self.token_gen.client_info.client_id,
            "grant_type": self.grant_type,
            "claims": self.claims,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        token_gen = None
        for cred in config.credentials.values():
            if isinstance(cred, OAuth2TokenGenerator):
                if cred.client_info.client_id == serialized["client_id"]:
                    token_gen = cred
                    break

        if not token_gen:
            raise Exception(f"Client with ID {serialized['client_id']} not found.")

        serialized.pop("client_id")

        return TestTokenRequestScopeOmit(check_id, token_gen, **serialized)


class TestTokenRequestScopeEmpty(TestCase):
    """
    Check which scopes are assigned to an OAuth2 token if the scope parameter is empty.
    This means the scope query parameter looks like this: scope=
    """
    test_type: TestCaseType = TestCaseType.ANALYTICAL
    auth_type: AuthType = AuthType.REQUIRED
    live_type: LiveType = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        token_gen: OAuth2TokenGenerator,
        grant_type: str,
        claims: list[str] = None
    ) -> None:
        """
        Create a new check for TestTokenRequestScopeEmpty.

        :param token_gen: Token Generator for OAuth2 tokens.
        :type token_gen: OAuth2TokenGenerator
        :param grant_type: Grant used to request the token (code or token).
        :type grant_type: str
        :param claims: Optional list of scopes that are expected to be returned.
        :type claims: Optional[List]
        """
        super().__init__(check_id)

        self.token_gen = token_gen
        self.grant_type = grant_type
        self.claims = claims
        self.token: OAuth2Token = None

    def run(self) -> None:
        self.result.status = CheckStatus.RUNNING

        try:
            self.token = self.token_gen.request_new_token(
                scopes=[],
                grant_type=self.grant_type,
                policy=AccessLevelPolicy.NOPE
            )

        except Exception as err:
            self.result.error = err
            self.token = None

        self.result.value = {}

        if not self.token:
            # Exit if no token could be created
            logging.warning(f"No token received for checking {repr(self)}.")
            self.result.issue_type = IssueType.NO_CANDIDATE
            self.result.status = CheckStatus.ERROR
            return

        if not self.token.scopes:
            # Auth server should indicate scope according to
            # https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
            logging.info(f"No scope information received in token.")
            self.result.issue_type = IssueType.CANDIDATE
            self.result.value["received_scopes"] = None

            self.result.status = CheckStatus.FINISHED
            return

        self.result.issue_type = IssueType.CANDIDATE
        self.result.value["received_scopes"] = self.token.scopes
        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start) -> list:
        cur_check_id = check_id_start
        test_cases = []
        if self.result.value["received_scopes"] is not None:
            test_cases.append(CompareTokenScopesToClientScopes(
                cur_check_id, self.token, self.token_gen.client_info))
            cur_check_id += 1

        return []

    @ classmethod
    def generate(cls, config, check_id_start=0) -> list:
        if not config.credentials:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for cred in config.credentials.values():
            if not isinstance(cred, OAuth2TokenGenerator):
                continue

            if 'code' in cred.client_info.supported_grants:
                test_cases.append(TestTokenRequestScopeEmpty(cur_check_id, cred, 'code'))
                cur_check_id += 1

            if 'token' in cred.client_info.supported_grants:
                test_cases.append(TestTokenRequestScopeEmpty(cur_check_id, cred, 'token'))
                cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "client_id": self.token_gen.client_info.client_id,
            "grant_type": self.grant_type,
            "claims": self.claims,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        token_gen = None
        for cred in config.credentials.values():
            if isinstance(cred, OAuth2TokenGenerator):
                if cred.client_info.client_id == serialized["client_id"]:
                    token_gen = cred
                    break

        if not token_gen:
            raise Exception(f"Client with ID {serialized['client_id']} not found.")

        serialized.pop("client_id")

        return TestTokenRequestScopeOmit(check_id, token_gen, **serialized)


class TestTokenRequestScopeInvalid(TestCase):
    """
    Check which scopes are assigned to an OAuth2 token if the scope parameter is invalid.
    Invalid means the scope is not supported by the service.
    """
    test_type: TestCaseType = TestCaseType.ANALYTICAL
    auth_type: AuthType = AuthType.REQUIRED
    live_type: LiveType = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        token_gen: OAuth2TokenGenerator,
        grant_type: str,
        claims: list[str] = None
    ) -> None:
        """
        Create a new check for TestTokenRequestScopeInvalid.

        :param token_gen: Token Generator for OAuth2 tokens.
        :type token_gen: OAuth2TokenGenerator
        :param grant_type: Grant used to request the token (code or token).
        :type grant_type: str
        :param claims: Optional list of scopes that are expected to be returned.
        :type claims: Optional[List]
        """
        super().__init__(check_id)

        self.token_gen = token_gen
        self.grant_type = grant_type
        self.claims = claims
        self.token: OAuth2Token = None

    def run(self) -> None:
        self.result.status = CheckStatus.RUNNING

        # Use an invalid scope value:

        # MD5(REST-Attacker)
        # scope = "8516bfad8d65603b872d2c4a688135d7"

        # Use a pseudo-random 16 Bit number and hash it
        # then use hex value as scope
        from random import randint
        from hashlib import sha256
        rand_val = randint(0, 2 ** 16 - 1)
        rand_bytes = rand_val.to_bytes(length=2, byteorder='little')
        scope = sha256(rand_bytes).hexdigest()

        self.result.value = {}
        self.result.value["random_number"] = rand_val
        self.result.value["scope"] = scope

        try:
            self.token = self.token_gen.request_new_token(
                scopes=[scope],
                grant_type=self.grant_type
            )

        except Exception as err:
            self.result.error = err
            self.token = None

        if not self.token:
            # Exit if no token could be created
            logging.warning(f"No token received for checking {repr(self)}.")
            self.result.issue_type = IssueType.NO_CANDIDATE
            self.result.status = CheckStatus.ERROR
            return

        if not self.token.scopes:
            # Auth server should indicate scope according to
            # https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
            logging.info(f"No scope information received in token.")
            self.result.issue_type = IssueType.CANDIDATE
            self.result.value["received_scopes"] = None

            self.result.status = CheckStatus.FINISHED
            return

        self.result.issue_type = IssueType.CANDIDATE
        self.result.value["received_scopes"] = self.token.scopes
        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start) -> list:
        cur_check_id = check_id_start
        test_cases = []
        if self.result.value["received_scopes"] is not None:
            test_cases.append(CompareTokenScopesToClientScopes(
                cur_check_id, self.token, self.token_gen.client_info))
            cur_check_id += 1

        return []

    @ classmethod
    def generate(cls, config, check_id_start=0) -> list:
        if not config.credentials:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for cred in config.credentials.values():
            if not isinstance(cred, OAuth2TokenGenerator):
                continue

            if 'code' in cred.client_info.supported_grants:
                test_cases.append(TestTokenRequestScopeInvalid(cur_check_id, cred, 'code'))
                cur_check_id += 1

            if 'token' in cred.client_info.supported_grants:
                test_cases.append(TestTokenRequestScopeInvalid(cur_check_id, cred, 'token'))
                cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "client_id": self.token_gen.client_info.client_id,
            "grant_type": self.grant_type,
            "claims": self.claims,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        token_gen = None
        for cred in config.credentials.values():
            if isinstance(cred, OAuth2TokenGenerator):
                if cred.client_info.client_id == serialized["client_id"]:
                    token_gen = cred
                    break

        if not token_gen:
            raise Exception(f"Client with ID {serialized['client_id']} not found.")

        serialized.pop("client_id")

        return TestTokenRequestScopeOmit(check_id, token_gen, **serialized)


class TestRefreshTokenRequestScopeOmit(TestCase):
    """
    Check which scopes are assigned to a refreshed OAuth2 token
    if the scope parameter is omitted. This means the OAuth2 refresh request is sent
    without a scope parameter.
    """
    test_type: TestCaseType = TestCaseType.ANALYTICAL
    auth_type: AuthType = AuthType.REQUIRED
    live_type: LiveType = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        token_gen: OAuth2TokenGenerator,
        first_token: OAuth2Token = None,
        claims: list[str] = None
    ) -> None:
        """
        Create a new check for TestRefreshTokenRequestScopeOmit.

        :param token_gen: Token Generator for OAuth2 tokens.
        :type token_gen: OAuth2TokenGenerator
        :param token: Token that is refreshed. A new token is requested if no token was specified.
        :type token_gen: OAuth2Token
        :param claims: Optional list of scopes that are expected to be returned.
        :type claims: Optional[List]
        """
        super().__init__(check_id)

        self.token_gen = token_gen
        self.claims = claims
        self.first_token = first_token
        self.refreshed_token: OAuth2Token = None

    def run(self) -> None:
        self.result.status = CheckStatus.RUNNING

        if not self.first_token:
            self.first_token = self.token_gen.request_new_token(
                scopes=None,
                grant_type='code',
                policy=AccessLevelPolicy.NOPE
            )

        try:
            self.refreshed_token = self.token_gen.refresh_token(self.first_token, scopes=None)

        except Exception as err:
            self.result.error = err
            self.refreshed_token = None

        self.result.value = {}

        if not self.refreshed_token:
            # Exit if no token could be created
            logging.warning(f"No token received for checking {repr(self)}.")
            self.result.issue_type = IssueType.NO_CANDIDATE
            self.result.status = CheckStatus.ERROR
            return

        if not self.refreshed_token.scopes:
            # Auth server should indicate scope according to
            # https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
            logging.info(f"No scope information received in token.")
            self.result.issue_type = IssueType.CANDIDATE
            self.result.value["received_scopes"] = None

            self.result.status = CheckStatus.FINISHED
            return

        self.result.issue_type = IssueType.CANDIDATE
        self.result.value["received_scopes"] = self.refreshed_token.scopes
        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start) -> list:
        cur_check_id = check_id_start
        test_cases = []
        if self.result.value["received_scopes"] is not None:
            test_cases.append(CompareTokenScopesToClientScopes(
                cur_check_id, self.first_token, self.token_gen.client_info))
            cur_check_id += 1

        return []

    @classmethod
    def generate(cls, config, check_id_start=0) -> list:
        if not config.credentials:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for cred in config.credentials.values():
            if not isinstance(cred, OAuth2TokenGenerator):
                continue

            if "scope_reqired" in cred.client_info.flags:
                continue

            if not 'refresh_token' in cred.client_info.supported_grants:
                # Generator must support refreshing tokens
                continue

            if 'code' in cred.client_info.supported_grants:
                test_cases.append(TestRefreshTokenRequestScopeOmit(cur_check_id, cred))
                cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "client_id": self.token_gen.client_info.client_id,
            "first_token": self.first_token,
            "claims": self.claims,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        token_gen = None
        for cred in config.credentials.values():
            if isinstance(cred, OAuth2TokenGenerator):
                if cred.client_info.client_id == serialized["client_id"]:
                    token_gen = cred
                    break

        if not token_gen:
            raise Exception(f"Client with ID {serialized['client_id']} not found.")

        serialized.pop("client_id")

        return TestRefreshTokenRequestScopeOmit(check_id, token_gen, **serialized)


class TestRefreshTokenRequestScopeEmpty(TestCase):
    """
    Check which scopes are assigned to a refreshed OAuth2 token if the scope parameter is empty.
    This means the scope query parameter looks like this: scope=
    """
    test_type: TestCaseType = TestCaseType.ANALYTICAL
    auth_type: AuthType = AuthType.REQUIRED
    live_type: LiveType = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        token_gen: OAuth2TokenGenerator,
        first_token: OAuth2Token = None,
        claims: list[str] = None
    ) -> None:
        """
        Create a new check for TestRefreshTokenRequestScopeEmpty.

        :param token_gen: Token Generator for OAuth2 tokens.
        :type token_gen: OAuth2TokenGenerator
        :param token: Token that is refreshed. A new token is requested if no token was specified.
        :type token_gen: OAuth2Token
        :param claims: Optional list of scopes that are expected to be returned.
        :type claims: Optional[List]
        """
        super().__init__(check_id)

        self.token_gen = token_gen
        self.claims = claims
        self.first_token = first_token
        self.refreshed_token: OAuth2Token = None

    def run(self) -> None:
        self.result.status = CheckStatus.RUNNING

        if not self.first_token:
            self.first_token = self.token_gen.request_new_token(
                scopes=None,
                grant_type='code',
                policy=AccessLevelPolicy.NOPE
            )

        try:
            self.refreshed_token = self.token_gen.refresh_token(self.first_token, scopes=[])

        except Exception as err:
            self.result.error = err
            self.refreshed_token = None

        self.result.value = {}

        if not self.refreshed_token:
            # Exit if no token could be created
            logging.warning(f"No token received for checking {repr(self)}.")
            self.result.issue_type = IssueType.NO_CANDIDATE
            self.result.status = CheckStatus.ERROR
            return

        if not self.refreshed_token.scopes:
            # Auth server should indicate scope according to
            # https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
            logging.info(f"No scope information received in token.")
            self.result.issue_type = IssueType.CANDIDATE
            self.result.value["received_scopes"] = None
            self.result.status = CheckStatus.FINISHED
            return

        self.result.issue_type = IssueType.CANDIDATE
        self.result.value["received_scopes"] = self.refreshed_token.scopes
        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start) -> list:
        cur_check_id = check_id_start
        test_cases = []
        if self.result.value["received_scopes"] is not None:
            test_cases.append(CompareTokenScopesToClientScopes(
                cur_check_id, self.first_token, self.token_gen.client_info))
            cur_check_id += 1

        return []

    @ classmethod
    def generate(cls, config, check_id_start=0) -> list:
        if not config.credentials:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for cred in config.credentials.values():
            if not isinstance(cred, OAuth2TokenGenerator):
                continue

            if not 'refresh_token' in cred.client_info.supported_grants:
                # Generator must support refreshing tokens
                continue

            if 'code' in cred.client_info.supported_grants:
                test_cases.append(TestRefreshTokenRequestScopeEmpty(cur_check_id, cred))
                cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "client_id": self.token_gen.client_info.client_id,
            "first_token": self.first_token,
            "claims": self.claims,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        token_gen = None
        for cred in config.credentials.values():
            if isinstance(cred, OAuth2TokenGenerator):
                if cred.client_info.client_id == serialized["client_id"]:
                    token_gen = cred
                    break

        if not token_gen:
            raise Exception(f"Client with ID {serialized['client_id']} not found.")

        serialized.pop("client_id")

        return TestRefreshTokenRequestScopeEmpty(check_id, token_gen, **serialized)


class TestRefreshTokenRequestScopeInvalid(TestCase):
    """
    Check which scopes are assigned to a refreshed OAuth2 token if the scope parameter is invalid.
    Invalid means the scope is not supported by the service.
    """
    test_type: TestCaseType = TestCaseType.ANALYTICAL
    auth_type: AuthType = AuthType.REQUIRED
    live_type: LiveType = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        token_gen: OAuth2TokenGenerator,
        first_token: OAuth2Token = None,
        claims: list[str] = None
    ) -> None:
        """
        Create a new check for TestRefreshTokenRequestScopeInvalid.

        :param token_gen: Token Generator for OAuth2 tokens.
        :type token_gen: OAuth2TokenGenerator
        :param token: Token that is refreshed. A new token is requested if no token was specified.
        :type token_gen: OAuth2Token
        :param claims: Optional list of scopes that are expected to be returned.
        :type claims: Optional[List]
        """
        super().__init__(check_id)

        self.token_gen = token_gen
        self.claims = claims
        self.first_token = first_token
        self.refreshed_token = None

    def run(self) -> None:
        self.result.status = CheckStatus.RUNNING

        if not self.first_token:
            self.first_token = self.token_gen.request_new_token(scopes=None, grant_type='code')

        # MD5(REST-Attacker)
        # scope = "8516bfad8d65603b872d2c4a688135d7"

        # Use a pseudo-random 16 Bit number and hash it
        # then use hex value as scope
        from random import randint
        from hashlib import sha256
        rand_val = randint(0, 2 ** 16 - 1)
        rand_bytes = rand_val.to_bytes(length=2, byteorder='little')
        scope = sha256(rand_bytes).hexdigest()

        self.result.value = {}

        self.result.value["random_number"] = rand_val
        self.result.value["scope"] = scope

        try:
            self.refreshed_token = self.token_gen.refresh_token(self.first_token, scopes=[scope])

        except Exception as err:
            self.result.error = err
            self.refreshed_token = None

        if not self.refreshed_token:
            # Exit if no token could be created
            logging.warning(f"No token received for checking {repr(self)}.")
            self.result.issue_type = IssueType.NO_CANDIDATE
            self.result.status = CheckStatus.ERROR
            return

        if not self.refreshed_token.scopes:
            # Auth server should indicate scope according to
            # https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
            logging.info(f"No scope information received in token.")
            self.result.issue_type = IssueType.CANDIDATE
            self.result.value["received_scopes"] = None
            self.result.status = CheckStatus.FINISHED
            return

        self.result.issue_type = IssueType.CANDIDATE
        self.result.value["received_scopes"] = self.refreshed_token.scopes
        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start) -> list:
        cur_check_id = check_id_start
        test_cases = []
        if self.result.value["received_scopes"] is not None:
            test_cases.append(CompareTokenScopesToClientScopes(
                cur_check_id, self.first_token, self.token_gen.client_info))
            cur_check_id += 1

        return []

    @ classmethod
    def generate(cls, config, check_id_start=0) -> list:
        if not config.credentials:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for cred in config.credentials.values():
            if not isinstance(cred, OAuth2TokenGenerator):
                continue

            if not 'refresh_token' in cred.client_info.supported_grants:
                # Generator must support refreshing tokens
                continue

            if 'code' in cred.client_info.supported_grants:
                test_cases.append(TestRefreshTokenRequestScopeEmpty(cur_check_id, cred))
                cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "client_id": self.token_gen.client_info.client_id,
            "first_token": self.first_token,
            "claims": self.claims,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        token_gen = None
        for cred in config.credentials.values():
            if isinstance(cred, OAuth2TokenGenerator):
                if cred.client_info.client_id == serialized["client_id"]:
                    token_gen = cred
                    break

        if not token_gen:
            raise Exception(f"Client with ID {serialized['client_id']} not found.")

        return TestRefreshTokenRequestScopeOmit(check_id, token_gen, **serialized)
