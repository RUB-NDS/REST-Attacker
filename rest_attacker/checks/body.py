# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Test cases for analyzing response body parameters.
"""

from email import header
import json
import logging
from os import stat
import jsonschema

from rest_attacker.checks.generic import TestCase
from rest_attacker.checks.types import AuthType, LiveType, TestCaseType
from rest_attacker.report.report import Report
from rest_attacker.util.input_gen import replace_params
from rest_attacker.util.request.request_info import AuthRequestInfo, RequestInfo
from rest_attacker.util.test_result import CheckStatus, IssueType


class CompareHTTPBodyToSchema(TestCase):
    """
    Compare the JSON body of a check to a JSON schema definitions from an API description.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.OPTIONAL
    live_type = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        request_info: RequestInfo,
        schema: dict,
        auth_info: AuthRequestInfo = None,
    ) -> None:
        """
        Creates a new check for CompareHTTPBodyToSchema.

        :param request_info: RequestInfo object that stores data to make the request.
        :type request_info: RequestInfo
        :param auth_info: AuthRequestInfo object that is used for authentication if specified.
        :type auth_info: AuthRequestInfo
        :param schema: JSON schema definition.
        :type schema: dict
        """
        super().__init__(check_id)

        self.request_info = request_info
        self.auth_info = auth_info

        self.schema = schema

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

        try:
            json_body = response.json()

        except ValueError as err:
            logging.warning("Response contained no valid JSON payload.")
            self.result.status = CheckStatus.ERROR
            self.result.error = err
            return

        try:
            jsonschema.validate(json_body, self.schema)

            # Payload matches schema
            self.result.issue_type = IssueType.MATCH
            self.result.value = {
                "valid": True,
            }

        except jsonschema.ValidationError as err:
            # Payload does not match to schema
            self.result.issue_type = IssueType.DIFFERENT
            self.result.value = {
                "valid": False,
                "invalid_subschema": err.schema     # Stores the faulty parts of schema
            }

        except jsonschema.SchemaError as err:
            logging.warning("JSON schema is invalid.")
            self.result.status = CheckStatus.ERROR
            self.result.error = err
            return

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
        if not config.descriptions:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for descr in config.descriptions.values():
            for server in descr.servers:
                for path_id, path in descr.endpoints.items():
                    for op_id, op in path.items():
                        replacments = None
                        if descr.requires_parameters(path_id, op_id):
                            if not config.users or not config.current_user_id:
                                # No replacement parameters defined
                                continue

                            default_user = config.users[config.current_user_id]
                            req_parameters = descr.get_required_param_defs(path_id, op_id)

                            replacments = replace_params(path, default_user, req_parameters)
                            if not replacments:
                                # No replacements found
                                continue

                        for status_code, response in op["responses"].items():
                            if not "content" in response.keys():
                                continue

                            if not "application/json" in response["content"].keys():
                                continue

                            if not "schema" in response["content"]["application/json"].keys():
                                continue

                            schema_def = response["content"]["application/json"]["schema"]
                            schemas = [schema_def]
                            if "allOf" in schema_def.keys():
                                schemas = schema_def["allOf"]

                            elif "oneOf" in schema_def.keys():
                                schemas = schema_def["oneOf"]

                            for schema in schemas:
                                if replacments:
                                    request_info = RequestInfo(
                                        server["url"],
                                        replacments[0],
                                        op_id,
                                        headers=replacments[1],
                                        params=replacments[2],
                                        cookies=replacments[3]
                                    )

                                else:
                                    request_info = RequestInfo(
                                        server["url"],
                                        path_id,
                                        op_id
                                    )

                                auth_info = None
                                if config.auth and 200 <= int(status_code) < 400:
                                    auth_info = AuthRequestInfo(
                                        config.auth
                                    )

                                test_cases.append(CompareHTTPBodyToSchema(
                                    cur_check_id, request_info, schema, auth_info))
                                cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "request_info": self.request_info.serialize(),
            "schema": self.schema,
        }

        if self.auth_info:
            serialized.update({
                "auth_info": self.auth_info.serialize(),
            })

        return serialized

    @classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        request_info = RequestInfo.deserialize(serialized.pop("request_info"))
        schema = serialized.pop("schema")
        auth_info = None
        if "auth_info" in serialized:
            auth_info = AuthRequestInfo.deserialize(serialized.pop("auth_info"), config.auth)

        return CompareHTTPBodyToSchema(check_id, request_info, schema, auth_info)


class CompareHTTPBodyAuthNonauth(TestCase):
    """
    Compare the response bodies of a non-auth request and an auth request for the same endpoint.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.REQUIRED
    live_type = LiveType.ONLINE

    def __init__(
        self,
        check_id: int,
        request_info: RequestInfo,
        auth_info: AuthRequestInfo,
    ) -> None:
        """
        Creates a new check for CompareHTTPBodyAuthNonauth.

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

        # 1st request: No authorization
        auth_data = self.auth_info.auth_gen.get_min_auth()
        response1 = self.request_info.send(auth_data)

        # 2nd request: Authorized
        auth_data = self.auth_info.auth_gen.get_auth(
            scheme_ids=self.auth_info.scheme_ids,
            scopes=self.auth_info.scopes,
            policy=self.auth_info.policy
        )
        response2 = self.request_info.send(auth_data)
        self.result.last_response = response2

        try:
            response1_json = response1.json()
            response2_json = response2.json()

        except json.JSONDecodeError as err:
            logging.warning("JSON payload could not be decoded.")
            self.result.status = CheckStatus.ERROR
            self.result.error = err
            return

        common_values, unique_values_left, unique_values_right = \
            _recursive_diff(
                response1_json,
                response2_json
            )

        if len(unique_values_left) == len(unique_values_right) == 0:
            self.result.issue_type = IssueType.MATCH

        else:
            self.result.issue_type = IssueType.DIFFERENT

        self.result.value = {
            "common_values": common_values,
            "unique_values_left": unique_values_left,
            "unique_values_right": unique_values_right,
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

    @ classmethod
    def generate(cls, config, check_id_start=0):
        if not config.descriptions:
            return []

        if not config.auth:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for descr in config.descriptions.values():
            for server in descr.servers:
                for path_id, path in descr.endpoints.items():
                    for op_id, op in path.items():
                        replacments = None
                        if descr.requires_parameters(path_id, op_id):
                            if not config.users or not config.current_user_id:
                                # No replacement parameters defined
                                continue

                            default_user = config.users[config.current_user_id]
                            req_parameters = descr.get_required_param_defs(path_id, op_id)

                            replacments = replace_params(path, default_user, req_parameters)
                            if not replacments:
                                # No replacements found
                                continue

                        if replacments:
                            request_info = RequestInfo(
                                server["url"],
                                replacments[0],
                                op_id,
                                headers=replacments[1],
                                params=replacments[2],
                                cookies=replacments[3]
                            )

                        else:
                            request_info = RequestInfo(
                                server["url"],
                                path_id,
                                op_id
                            )

                        auth_info = AuthRequestInfo(
                            config.auth
                        )

                        test_cases.append(
                            CompareHTTPBodyAuthNonauth(cur_check_id, request_info, auth_info)
                        )
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

        return CompareHTTPBodyAuthNonauth(check_id, request_info, auth_info, **serialized)


def _recursive_diff(left, right):
    """
    Compares two JSON payloads recursively and returns a comparison containing the common values
    and the unique values of 'left' and 'right'.

    :param left: First payload.
    :param right: Second payload.
    :type left: dict|list
    :type right: dict|list
    :return: Common values, unique values of left, unique values of right (in that order).
    :rtype: tuple
    """
    if type(left) is not type(right):
        # Different types cannot be compared
        return {}, [left], [right]

    if isinstance(left, dict):
        # Dict comparison recurse
        return _recursive_diff_dict(left, right)

    if isinstance(left, list):
        # List comparison recurse
        return _recursive_diff_list(left, right)

    # Primitive values
    if left != right:
        return {}, [left], [right]

    return [left], [], []


def _recursive_diff_dict(left, right):
    """
    Compares two dicts recursively and returns a comparison containing the common values
    and the unique values of 'left' and 'right'.

    :param left: First dict.
    :param right: Second dict.
    :type left: dict
    :type right: dict
    :return: Common values, unique values of left, unique values of right (in that order).
    :rtype: tuple[dict]
    """
    unique_values_left = {}
    unique_values_right = {}
    common_values = {}

    if left == right:
        common_values.update(left)

    else:
        for key_left, value_left in left.items():
            if key_left in right.keys():
                value_right = right[key_left]
                if value_left == value_right:
                    common_values.update({key_left: value_left})

                else:
                    if type(value_left) is not type(value_right):
                        # Different types cannot be compared
                        unique_values_left.update({key_left: value_left})
                        unique_values_right.update({key_left: value_right})

                    if isinstance(value_left, dict):
                        # Dict comparison recurse
                        common, un_left, un_right = _recursive_diff_dict(
                            value_left, value_right)
                        common_values.update({key_left: common})
                        unique_values_left.update({key_left: un_left})
                        unique_values_right.update({key_left: un_right})

                    elif isinstance(value_left, list):
                        # List comparison recurse
                        common, un_left, un_right = _recursive_diff_list(
                            value_left, value_right)
                        common_values.update({key_left: common})
                        unique_values_left.update({key_left: un_left})
                        unique_values_right.update({key_left: un_right})

                    else:
                        unique_values_left.update({key_left: value_left})
                        unique_values_right.update({key_left: value_right})

            else:
                unique_values_left.update({key_left: value_left})

        for key_right, value_right in right.items():
            if key_right in left.keys():
                # Should already be in dict because of 'left' for-loop
                pass

            else:
                unique_values_right.update({key_right: value_right})

    return common_values, unique_values_left, unique_values_right


def _recursive_diff_list(left, right):
    """
    Compares two lists recursively and returns a comparison containing the common values
    and the unique values of 'left' and 'right'.

    :param left: First list.
    :param right: Second list.
    :type left: list
    :type right: list
    :return: Common values, unique values of left, unique values of right (in that order).
    :rtype: tuple[list]
    """
    unique_values_left = []
    unique_values_right = []
    common_values = []

    if left == right:
        common_values.extend(left)

    else:
        min_length = 0
        if len(left) < len(right):
            min_length = len(left)

        else:
            min_length = len(right)

        for array_idx in range(min_length):
            value_left = left[array_idx]
            value_right = right[array_idx]
            if value_left != value_right:
                if type(value_left) is not type(value_right):
                    # Different types cannot be compared
                    unique_values_left.append(value_left)
                    unique_values_right.append(value_right)

                elif isinstance(value_left, dict):
                    # Dict comparison recurse
                    common, un_left, un_right = _recursive_diff_dict(
                        value_left, value_right)
                    common_values.append(common)
                    unique_values_left.append(un_left)
                    unique_values_right.append(un_right)

                elif isinstance(value_left, list):
                    # List comparison recurse
                    common, un_left, un_right = _recursive_diff_list(
                        value_left, value_right)
                    common_values.append(common)
                    unique_values_left.append(un_left)
                    unique_values_right.append(un_right)

                else:
                    unique_values_left.append(value_left)
                    unique_values_right.append(value_right)

            else:
                common_values.append(value_left)

        if len(left) < len(right):
            unique_values_right.extend(right[min_length:])

        else:
            unique_values_left.extend(left[min_length:])

    return common_values, unique_values_left, unique_values_right
