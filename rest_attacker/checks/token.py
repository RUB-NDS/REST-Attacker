# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Test cases for analyzing tokens provided by the service.
"""

import logging
import base64
import time

from oauthlib.oauth2.rfc6749.tokens import OAuth2Token

from rest_attacker.checks.generic import TestCase
from rest_attacker.checks.types import AuthType, LiveType, TestCaseType
from rest_attacker.report.report import Report
from rest_attacker.util.auth.token_generator import AccessLevelPolicy, OAuth2TokenGenerator
from rest_attacker.util.test_result import CheckStatus, IssueType
from rest_attacker.util.request.request_info import AuthRequestInfo, RequestInfo


class TestReadOAuth2Expiration(TestCase):
    """
    Check the expiration time of the provided token.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.NOPE
    live_type = LiveType.OFFLINE

    def __init__(self, check_id: int, token: OAuth2Token) -> None:
        """
        Creates a new check for TestExpiration.

        :param token: OAuth2 token from token request.
        :type token: OAuth2Token
        """
        super().__init__(check_id)

        self.token = token

    def run(self):
        self.result.status = CheckStatus.RUNNING

        if "expires_in" in self.token:
            self.result.issue_type = IssueType.CANDIDATE
            self.result.value = {
                "vailidity_length": self.token["expires_in"]
            }

        if "expires_at" in self.token:
            self.result.issue_type = IssueType.CANDIDATE
            self.result.value = {
                "expires_at": self.token["expires_at"]
            }

        if not self.result.value:
            logging.info("Token has no expiration time information.")
            self.result.issue_type = IssueType.NO_CANDIDATE

        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start):
        # TODO: Refresh/Expiration checks
        return []

    @classmethod
    def generate(cls, config, check_id_start=0):
        if not config.auth:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for cred in config.credentials.values():
            if isinstance(cred, OAuth2TokenGenerator):
                token = cred.get_token()
                test_cases.append(TestReadOAuth2Expiration(cur_check_id, token))
                cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "token": self.token,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        token = serialized["token"]

        return TestReadOAuth2Expiration(check_id, token)


class TestOAuth2Expiration(TestCase):
    """
    Check if the provided token expires after the specified time.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.REQUIRED
    live_type = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        token: OAuth2Token,
        request_info: RequestInfo,
        auth_info: AuthRequestInfo
    ) -> None:
        """
        Creates a new check for TestExpiration.

        :param token: OAuth2 token from a token request.
        :type token: OAuth2Token
        :param request_info: RequestInfo object that stores data to make the request.
        :type request_info: RequestInfo
        :param auth_info: AuthRequestInfo object that contains the specified token.
        :type auth_info: AuthRequestInfo
        """
        super().__init__(check_id)

        self.request_info = request_info
        self.auth_info = auth_info

        self.token = token

    def run(self):
        self.result.status = CheckStatus.RUNNING

        if "expires_at" in self.token:
            sleep_time = self.token["expires_at"] - time.time() - 30

        else:
            logging.warning("Token has no expiration time information.")
            self.result.status = CheckStatus.ERROR
            return

        if sleep_time < 0:
            logging.info("Token is already expired. Skipping check.")
            self.result.status = CheckStatus.SKIPPED
            return

        # Sleep until expiration time reached
        time.sleep(sleep_time)

        auth_data = None
        if self.auth_info:
            auth_data = self.auth_info.auth_gen.get_auth(
                scheme_ids=self.auth_info.scheme_ids,
                scopes=self.auth_info.scopes,
                policy=self.auth_info.policy
            )

        # Test various times to determine expiration allowance
        # 30 seconds before expiration
        logging.debug("Testing token expiration validation: -30 seconds after expiration time.")
        response = self.request_info.send(auth_data)
        self.result.last_response = response

        response = self.request_info.send()

        if not 200 <= response.status_code < 300:
            logging.warning("Token could not be used before expiration time was reached.")
            self.result.status = CheckStatus.ERROR
            return

        validity_time = 0
        # Test various times to determine expiration allowance
        # 1 seconds after expiration
        logging.debug("Testing token expiration validation: 1 seconds after expiration time.")
        time.sleep(31)
        response = self.request_info.send(auth_data)
        self.result.last_response = response

        if 200 <= response.status_code < 300:
            logging.debug("Token accepted: 1 second after expiration time.")
            # Set to PROBLEM bcause there might be some allowance
            self.result.issue_type = IssueType.PROBLEM
            validity_time = 1

        # 60 seconds after expiration
        logging.debug("Testing token expiration validation: 60 seconds after expiration time.")
        time.sleep(60)
        response = self.request_info.send(auth_data)
        self.result.last_response = response

        if 200 <= response.status_code < 300:
            logging.debug("Token accepted: 60 seconds after expiration time.")
            self.result.issue_type = IssueType.FLAW
            validity_time = 60

        # 300 seconds (= 5 mins) after expiration
        logging.debug("Testing token expiration validation: 300 seconds after expiration time.")
        time.sleep(240)
        response = self.request_info.send(auth_data)
        self.result.last_response = response

        if 200 <= response.status_code < 300:
            logging.debug("Token accepted: 300 seconds after expiration time.")
            self.result.issue_type = IssueType.FLAW
            validity_time = 300

        self.result.value = {
            "min_validity_time": validity_time
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
        if not config.auth:
            return []

        cur_check_id = check_id_start
        test_cases = []
        return test_cases

        # TODO: Reactivate
        # Currently these tests take ages to complete

        for cred in config.credentials.values():
            if isinstance(cred, OAuth2TokenGenerator):
                token = cred.get_token()
                test_cases.append(TestOAuth2Expiration(cur_check_id, token))
                cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "request_info": self.request_info.serialize(),
            "auth_info": self.auth_info.serialize(),
            "token": self.token,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        token = serialized["token"]
        request_info = RequestInfo.deserialize(serialized.pop("request_info"))
        auth_info = AuthRequestInfo.deserialize(serialized.pop("auth_info"), config.auth)

        return TestOAuth2Expiration(check_id, token, request_info, auth_info)


class TestDecodeOAuth2JWT(TestCase):
    """
    Check if the OAuth2 Token is a JWT.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.NOPE
    live_type = LiveType.OFFLINE

    def __init__(self, check_id, token: OAuth2Token) -> None:
        """
        Creates a new check for TestExpiration.

        :param token: OAuth2 token from token request.
        :type token: OAuth2Token
        """
        super().__init__(check_id)

        self.token = token

    def run(self):
        self.result.status = CheckStatus.RUNNING

        self.result.value = {}
        if not "access_token" in self.token:
            logging.info("Token has no access token defined.")
            self.result.issue_type = IssueType.NO_CANDIDATE

        else:
            access_token = self.token["access_token"]
            jwt_candidate = access_token.split('.')

            if len(jwt_candidate) == 3:
                # Test if header and payload can be decoded
                try:
                    header_candidate = base64.urlsafe_b64decode(
                        jwt_candidate[0] + '=' * (4 - len(jwt_candidate[0]) % 4)
                    )
                    self.result.issue_type = IssueType.CANDIDATE
                    self.result.value["header"] = header_candidate
                    logging.info("Token header could be decoded with Base64Url.")

                    payload_candidate = base64.urlsafe_b64decode(
                        jwt_candidate[1] + '=' * (4 - len(jwt_candidate[1]) % 4)
                    )
                    self.result.value["header"] = header_candidate.decode('utf-8')
                    self.result.value["payload"] = payload_candidate.decode('utf-8')
                    logging.info("Token payload could be decoded with Base64Url.")

                except ValueError as err:
                    logging.info("Token could not be decoded.")
                    self.result.issue_type = IssueType.NO_CANDIDATE

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

    @classmethod
    def generate(cls, config, check_id_start=0):
        if not config.auth:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for cred in config.credentials.values():
            if isinstance(cred, OAuth2TokenGenerator):
                token = cred.get_token()
                test_cases.append(TestDecodeOAuth2JWT(cur_check_id, token))
                cur_check_id += 1

                # Refresh token
                if 'refresh_token' in token:
                    refresh_token = token
                    test_cases.append(TestDecodeOAuth2JWT(cur_check_id, refresh_token))
                    cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "token": self.token,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        token = serialized["token"]

        return TestDecodeOAuth2JWT(check_id, token)


class TestRefreshTokenRevocation(TestCase):
    """
    Check if refresh tokens are single-use, i.e. they are invalidated after redeeming them once.
    """
    test_type: TestCaseType = TestCaseType.SECURITY
    auth_type: AuthType = AuthType.REQUIRED
    live_type: LiveType = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        token_gen: OAuth2TokenGenerator,
        token: OAuth2Token = None,
    ) -> None:
        """
        Create a new check for TestRefreshTokenRequestScopeInvalid.

        :param token_gen: Token Generator for OAuth2 tokens.
        :type token_gen: OAuth2TokenGenerator
        :param token: Token with a refresh token.
        :type token: OAuth2Token
        """
        super().__init__(check_id)

        self.token = token
        self.token_gen = token_gen

    def run(self) -> None:
        self.result.status = CheckStatus.RUNNING

        if not self.token:
            self.token = self.token_gen.request_new_token(
                grant_type='code',
                policy=AccessLevelPolicy.MAX
            )

        if not 'refresh_token' in self.token:
            # Token is not refreshable
            logging.warning(f"No refresh token available received for checking {repr(self)}.")
            self.result.status = CheckStatus.ERROR
            return

        self.result.value = {}

        # First redemption; this should be fine
        new_token = self.token_gen.refresh_token(self.token)

        # Second redemption; this may be rejected according to
        # https://datatracker.ietf.org/doc/html/rfc6749#section-6
        try:
            new_token2 = self.token_gen.refresh_token(self.token)
            self.result.issue_type = IssueType.PROBLEM
            self.result.value["refresh_token"] = self.token["refresh_token"]
            self.result.value["single_use"] = False

        except:
            self.result.issue_type = IssueType.OKAY
            self.result.value["refresh_token"] = self.token["refresh_token"]
            self.result.value["single_use"] = True

        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start) -> list:
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
                test_cases.append(TestRefreshTokenRevocation(cur_check_id, cred))
                cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "token": self.token,
            "client_id": self.token_gen.client_info.client_id,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        token = serialized["token"]

        token_gen = None
        for cred in config.credentials.values():
            if isinstance(cred, OAuth2TokenGenerator):
                if cred.client_info.client_id == serialized["client_id"]:
                    token_gen = cred
                    break

        if not token_gen:
            raise Exception(f"Client with ID {serialized['client_id']} not found.")

        return TestRefreshTokenRevocation(check_id, token_gen, token)


class TestRefreshTokenClientBinding(TestCase):
    """
    Check if refresh tokens are bound to the client that requests the corresponding access tokens.
    """
    test_type: TestCaseType = TestCaseType.SECURITY
    auth_type: AuthType = AuthType.REQUIRED
    live_type: LiveType = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        client0_token_gen: OAuth2TokenGenerator,
        client1_token_gen: OAuth2TokenGenerator,
        token: OAuth2Token = None,
    ) -> None:
        """
        Create a new check for TestRefreshTokenRequestScopeInvalid.

        :param client0_token_gen: Token Generator that genereted the token.
        :type client0_token_gen: OAuth2TokenGenerator
        :param client1_token_gen: Token Generator with different client information.
        :type client1_token_gen: OAuth2TokenGenerator
        :param token: Token with a refresh token.
        :type token: OAuth2Token
        """
        super().__init__(check_id)

        self.token = token
        self.token_gen0 = client0_token_gen
        self.token_gen1 = client1_token_gen

    def run(self) -> None:
        self.result.status = CheckStatus.RUNNING

        if self.token_gen0.client_info.client_id == self.token_gen1.client_info.client_id:
            # Clients are identical
            logging.info(f"Skipping check {repr(self)}: Clients are identical.")
            self.result.status = CheckStatus.SKIPPED
            return

        if not self.token:
            self.token = self.token_gen0.request_new_token(
                grant_type='code',
                policy=AccessLevelPolicy.MAX
            )

        if not 'refresh_token' in self.token:
            # Token is not refreshable
            logging.warning(f"No refresh token available received for checking {repr(self)}.")
            self.result.status = CheckStatus.ERROR
            return

        self.result.value = {}
        self.result.value["initial_client"] = self.token_gen0.client_info.client_id

        try:
            # Try refreshing with different client than the one who
            # received the token
            new_token = self.token_gen1.refresh_token(self.token)
            self.result.issue_type = IssueType.FLAW
            self.result.value["bound"] = False
            self.result.value["refresh_token"] = self.token["refresh_token"]
            self.result.value["refresher_client"] = self.token_gen1.client_info.client_id

        except:
            self.result.issue_type = IssueType.OKAY
            self.result.value["bound"] = True
            self.result.value["refresh_token"] = self.token["refresh_token"]

        self.result.status = CheckStatus.FINISHED

    def report(self, verbosity: int = 2):
        report = {}
        report.update(self.result.dump(verbosity=verbosity))

        # Check params
        report["config"] = self.serialize()

        return Report(self.check_id, content=report)

    def propose(self, config, check_id_start) -> list:
        return []

    @ classmethod
    def generate(cls, config, check_id_start=0) -> list:
        if not config.credentials:
            return []

        cur_check_id = check_id_start
        test_cases = []

        # Needs 2 or more clients for testing
        # and at least 1 refreshable client
        oauth2_clients = []
        refreshable_clients = []
        for cred in config.credentials.values():
            if not isinstance(cred, OAuth2TokenGenerator):
                continue

            oauth2_clients.append(cred)

            if not 'refresh_token' in cred.client_info.supported_grants:
                # Generator must support refreshing tokens
                continue

            if 'code' in cred.client_info.supported_grants:
                refreshable_clients.append(cred)

        if len(oauth2_clients) > 1 and len(refreshable_clients) > 0:
            for refr_client in refreshable_clients:
                for other_client in oauth2_clients:
                    if refr_client is other_client:
                        continue

                    test_cases.append(TestRefreshTokenClientBinding(
                        cur_check_id, refr_client, other_client))
                    cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "token": self.token,
            "client_id0": self.token_gen0.client_info.client_id,
            "client_id1": self.token_gen1.client_info.client_id,
        }

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        token = serialized["token"]
        token_gen0 = None
        token_gen1 = None
        for cred in config.credentials.values():
            if isinstance(cred, OAuth2TokenGenerator):
                if cred.client_info.client_id == serialized["client_id0"]:
                    token_gen0 = cred

                elif cred.client_info.client_id == serialized["client_id1"]:
                    token_gen1 = cred

                if token_gen0 and token_gen1:
                    break

        if not token_gen0:
            raise Exception(f"Client with ID {serialized['client_id0']} not found.")

        if not token_gen1:
            raise Exception(f"Client with ID {serialized['client_id1']} not found.")

        return TestRefreshTokenClientBinding(check_id, token_gen0, token_gen1, token)
