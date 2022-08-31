# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Test cases for analyzing resources and input parameters.
"""

import logging
from pydoc import describe
from rest_attacker.util.input_gen import replace_params
from rest_attacker.util.openapi.wrapper import OpenAPI
from rest_attacker.checks.misc import GetParameters
from rest_attacker.util.test_result import CheckStatus, IssueType

from rest_attacker.checks.generic import TestCase
from rest_attacker.checks.types import AuthType, LiveType, TestCaseType
from rest_attacker.util.request.request_info import AuthRequestInfo, RequestInfo
from rest_attacker.report.report import Report


class TestObjectIDInvalidUserAccess(TestCase):
    """
    Check if an object (resource with ID) is accessible without providing a
    sufficient access level (= unauthorized access).
    """
    test_type = TestCaseType.SECURITY
    auth_type = AuthType.OPTIONAL
    live_type = LiveType.OFFLINE

    def __init__(
        self,
        check_id: int,
        request_info: RequestInfo,
        auth_info: AuthRequestInfo = None,
        object_id: str = None,
        object_name: str = None
    ) -> None:
        """
        Creates a new check for TestObjectIDInvalidUserAccess.

        :param request_info: RequestInfo object that stores data to make the request.
        :type request_info: RequestInfo
        :param auth_info: AuthRequestInfo object that is used for authentication if specified.
        :type auth_info: AuthRequestInfo
        :param object_id: ID of the object that is requested.
        :type object_id: str
        :param object_name: Resource name of the object that is requested.
        :type object_name: str
        """
        super().__init__(check_id)

        self.request_info = request_info
        self.auth_info = auth_info

        self.object_id = object_id
        self.object_name = object_name

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
        self.result.issue_type = IssueType.OKAY

        if response.status_code not in (401, 403, 404):
            # Not Unauthorized/Forbidden/Not Found
            self.result.issue_type = IssueType.PROBLEM

        if 200 <= response.status_code < 300:
            # Direct access possible
            self.result.issue_type = IssueType.FLAW

        self.result.value["status_code"] = response.status_code

        if self.object_id:
            self.result.value["object_id"] = self.object_id

        if self.object_name:
            self.result.value["object_name"] = self.object_name

        if self.result.issue_type in (IssueType.PROBLEM, IssueType.FLAW):
            try:
                # Try to export received data
                self.result.value["response_body"] = response.json()

            except ValueError:
                self.result.value["response_body"] = None

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

                        else:
                            # Nothing is referenced
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

                        test_cases.append(
                            TestObjectIDInvalidUserAccess(cur_check_id, request_info)
                        )
                        cur_check_id += 1

                        if config.auth:
                            auth_info = AuthRequestInfo(config.auth)
                            test_cases.append(
                                TestObjectIDInvalidUserAccess(cur_check_id, request_info, auth_info)
                            )
                            cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "request_info": self.request_info.serialize(),
            "object_id": self.object_id,
            "object_name": self.object_name,
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

        return TestObjectIDInvalidUserAccess(check_id, request_info, auth_info, **serialized)


class CountParameterRequiredRefs(TestCase):
    """
    Determine frequency of required request parameters in an OpenAPI description. This is a
    naive search that counts each occurence of the names of required parameters.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.NOPE
    live_type = LiveType.OFFLINE

    def __init__(self, check_id: int, description: OpenAPI) -> None:
        """
        Creates a new check for FindIDParameters.

        :param description: API description.
        :type description: dict
        """
        super().__init__(check_id)

        self.description = description

    def run(self):
        self.result.status = CheckStatus.RUNNING

        try:
            paths = self.description.endpoints

        except KeyError as error:
            logging.warning("Could not find 'paths' entry in API description.")
            self.result.error = error
            self.result.status = CheckStatus.ERROR
            return

        unique_parameter_count = dict()
        self.result.issue_type = IssueType.NO_CANDIDATE
        for path_id, path in paths.items():
            for op_id, op in path.items():
                for param_id in self.description.get_required_param_ids(path_id, op_id):
                    if param_id not in unique_parameter_count.keys():
                        unique_parameter_count.update({
                            param_id: 0
                        })

                    unique_parameter_count[param_id] += 1

                    self.result.issue_type = IssueType.CANDIDATE

        self.result.value = dict(reversed(sorted(
            unique_parameter_count.items(),
            key=lambda dic: dic[1]  # Sort params by count
        )))

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

        new_checks.append(FindParameterReturns(
            check_id_start,
            self.description,
            list(self.result.value.keys())
        ))

        logging.debug(f"Proposed {len(new_checks)} new checks from check {self}")

        return new_checks

    @classmethod
    def generate(cls, config, check_id_start=0):
        if not config.descriptions:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for descr in config.descriptions.values():
            test_cases.append(CountParameterRequiredRefs(cur_check_id, descr))
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

        return FindIDParameters(check_id, description)


class FindIDParameters(TestCase):
    """
    Find parameters that could be resource IDs or other object references.
    This test case may be used to find candidates for testing object level authorization.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.NOPE
    live_type = LiveType.OFFLINE

    def __init__(self, check_id: int, description: OpenAPI) -> None:
        """
        Creates a new check for FindIDParameters.

        :param description: API description.
        :type description: dict
        """
        super().__init__(check_id)

        self.description = description

    def run(self):
        self.result.status = CheckStatus.RUNNING

        try:
            paths = self.description.endpoints

        except KeyError as error:
            logging.warning("Could not find 'paths' entry in API description.")
            self.result.error = error
            self.result.status = CheckStatus.ERROR
            return

        candidate_strings = {'id', 'name', 'obj'}

        unique_parameters = set()
        unique_parameter_count = dict()
        endpoints = dict()
        self.result.issue_type = IssueType.NO_CANDIDATE
        for path_id, path in paths.items():
            for op_id, op in path.items():
                parameters = self.description.get_required_param_defs(path_id, op_id).values()

                for param in parameters:
                    if "$ref" in param.keys():
                        param = self.description.resolve_ref(param["$ref"])

                    param_name = param["name"]
                    param_loc = param["in"]

                    if not isinstance(param_name, str):
                        # parameter name can be malformed
                        continue

                    for candidate in candidate_strings:
                        if candidate in param_name.lower():
                            if param_name not in unique_parameters:
                                unique_parameter_count.update({
                                    param_name: 0
                                })
                                unique_parameters.add(param_name)

                            unique_parameter_count[param_name] += 1

                            endpoints.update(
                                {path_id: (op_id, param_loc, param_name)}
                            )

                            self.result.issue_type = IssueType.CANDIDATE

        self.result.value = {
            "unique_parameters": sorted(list(unique_parameters)),
            "unique_parameter_count": dict(reversed(sorted(
                unique_parameter_count.items(),
                key=lambda dic: dic[1]  # Sort params by count
            ))),
            "endpoints": endpoints
        }

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

        new_checks.append(FindParameterReturns(
            check_id_start,
            self.description,
            list(self.result.value["unique_parameters"])
        ))

        logging.debug(f"Proposed {len(new_checks)} new checks from check {self}")

        return new_checks

    @classmethod
    def generate(cls, config, check_id_start=0):
        if not config.descriptions:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for descr in config.descriptions.values():
            test_cases.append(FindIDParameters(cur_check_id, descr))
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

        return FindIDParameters(check_id, description)


class FindParameterReturns(TestCase):
    """
    Find endpoints which return specified parameters in their response.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.NOPE
    live_type = LiveType.OFFLINE

    def __init__(self, check_id: int, description: OpenAPI, parameters: list[str]) -> None:
        """
        Creates a new check for FindParameterReturns.

        :param description: API description.
        :type description: OpenAPI
        :param parameters: Names of the parameters.
        :type parameters: list[str]
        """
        super().__init__(check_id)

        self.description = description

        self.search_parameters = parameters

    def run(self):
        self.result.status = CheckStatus.RUNNING

        try:
            paths = self.description.endpoints

        except KeyError as error:
            logging.warning("Could not find 'paths' entry in API description.")
            self.result.error = error
            self.result.status = CheckStatus.ERROR
            return

        param_locations = dict()
        self.result.issue_type = IssueType.NO_CANDIDATE
        for path_id, path in paths.items():
            for op_id, op in path.items():
                responses = op["responses"]
                for status_code, response in responses.items():
                    if not "content" in response.keys():
                        continue

                    response_content = response["content"]
                    for cty in response_content.values():
                        if not "schema" in cty.keys():
                            continue

                        schema_defs = []
                        schema_def = cty["schema"]

                        if "$ref" in schema_def.keys():
                            schema_def = self.description.resolve_ref(schema_def["$ref"])

                        # Skip choices in
                        if "allOf" in schema_def.keys():
                            schema_defs.extend(schema_def["allOf"])

                        elif "oneOf" in schema_def.keys():
                            schema_defs.extend(schema_def["oneOf"])

                        else:
                            schema_defs.append(schema_def)

                        for schema in schema_defs:
                            if not "properties" in schema.keys():
                                continue

                            schema_object = schema["properties"]

                            found_params = self._recursive_search(schema_object)
                            if len(found_params) == 0:
                                continue

                            self.result.issue_type = IssueType.CANDIDATE

                            for param_id in found_params:
                                param_name = param_id.split("/")[-1]
                                if param_name not in param_locations.keys():
                                    param_locations[param_name] = {
                                        "endpoints": []
                                    }

                                param_locations[param_name]["endpoints"].append({
                                    "path": path_id,
                                    "op": op_id,
                                    "status_code": status_code,
                                    "location": param_id,
                                    # Number of required parameters to access the endpoint
                                    # useful if we want to get the search parameters
                                    "required_param_count": len(
                                        self.description.get_required_param_ids(path_id, op_id)
                                    )
                                })

        for param_loc in param_locations.values():
            param_loc["endpoints"].sort(
                # Sort endpoints by required parameter count
                key=lambda item: item.get("required_param_count")
            )

        # Sort result by param name
        param_locations = dict(sorted(param_locations.items(), key=lambda dic: dic[0]))

        self.result.value = param_locations

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

        # TODO: Fetch parameter values?
        logging.debug(f"Proposed {len(new_checks)} new checks from check {self}")

        return new_checks

    @ classmethod
    def generate(cls, config, check_id_start=0):
        # Proposed by FindIDParameters
        return []

    def _recursive_search(self, schema_object: dict) -> list[str]:
        """
        Recursively search parameter definitions in a JSON schema object.

        :param schema_object: JSON schema definition.
        :type schema_object: dict
        """
        found_params = []
        for param_name, param in schema_object.items():
            param_descr = ""

            if "description" in param.keys():
                param_descr = param["description"]

            for candidate in self.search_parameters:
                if candidate in param_name.lower() or \
                        candidate in param_descr.lower():
                    found_params.append(param_name)

            if isinstance(param, dict):
                if not "properties" in param.keys():
                    continue

                subschema_object = param["properties"]
                subparams = self._recursive_search(subschema_object)
                for subparam_name in subparams:
                    subparam_id = "/".join((param_name, subparam_name))
                    found_params.append(subparam_id)

        return found_params

    def serialize(self) -> dict:
        serialized = {
            "description": self.description.description_id,
            "parameters": self.search_parameters,
        }

        return serialized

    @ classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        description = config.descriptions[serialized["description"]]
        parameters = serialized["parameters"]

        return FindParameterReturns(check_id, description, parameters)


class FindSecurityParameters(TestCase):
    """
    Find parameters that could be security-related, i.e. they contain access control
    data or other information for authentication/authorization.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.NOPE
    live_type = LiveType.OFFLINE

    def __init__(self, check_id: int, description: OpenAPI) -> None:
        """
        Creates a new check for FindSecurityParameters.

        :param description: API description.
        :type description: OpenAPI
        """
        super().__init__(check_id)

        self.description = description

        self._candidate_strings = {'token', 'key', 'auth', 'pass', 'pw', 'session'}

    def run(self):
        self.result.status = CheckStatus.RUNNING

        try:
            paths = self.description.endpoints

        except KeyError as error:
            logging.warning("Could not find 'paths' entry in API description.")
            self.result.error = error
            self.result.status = CheckStatus.ERROR
            return

        security_descr_set = set()
        security_params = set()
        endpoints = dict()
        self.result.issue_type = IssueType.NO_CANDIDATE
        for path_id, path in paths.items():
            for op_id, op in path.items():
                responses = op["responses"]
                for status_code, response in responses.items():
                    if "description" not in response.keys():
                        logging.info("Response has no description")
                        continue

                    description = response["description"]

                    for candidate in self._candidate_strings:
                        if candidate in description.lower():
                            security_descr_set.add(description)
                            endpoints.update(
                                {
                                    path_id: {
                                        "method": op_id,
                                        "status_code": status_code,
                                        "descr": description,
                                        "params": [],
                                    }
                                }
                            )

                            self.result.issue_type = IssueType.CANDIDATE

                    if not "content" in response.keys():
                        continue

                    response_content = response["content"]
                    for cty in response_content.values():
                        if not "schema" in cty.keys():
                            continue

                        schema_defs = []
                        schema_def = cty["schema"]

                        if "$ref" in schema_def.keys():
                            schema_def = self.description.resolve_ref(schema_def["$ref"])

                        # Skip choices in
                        if "allOf" in schema_def.keys():
                            schema_defs.extend(schema_def["allOf"])

                        elif "oneOf" in schema_def.keys():
                            schema_defs.extend(schema_def["oneOf"])

                        else:
                            schema_defs.append(schema_def)

                        for schema in schema_defs:
                            if not "properties" in schema.keys():
                                continue

                            schema_object = schema["properties"]

                            found_params = self._recursive_search(schema_object)
                            if len(found_params) == 0:
                                self.result.issue_type = IssueType.NO_CANDIDATE
                                continue

                            self.result.issue_type = IssueType.CANDIDATE
                            security_params.update(found_params)

                            if path_id not in endpoints.keys():
                                endpoints.update({
                                    path_id: {
                                        "method": op_id,
                                        "status_code": status_code,
                                        "descr": description,
                                        "params": [],
                                    }
                                })

                            endpoints[path_id]["params"].extend(found_params)

        self.result.value = {
            "security_descriptions": sorted(list(security_descr_set)),
            "security_params": sorted(list(security_params)),
            "endpoints": endpoints
        }

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

        # Fetch parameter values
        for path_name, path_item in self.result.value["endpoints"].items():
            new_request = RequestInfo(
                self.description["servers"][0]["url"],  # TODO: What if there are multiple servers?
                path_name,
                path_item["method"]
            )

            if config.auth:
                new_auth_info = AuthRequestInfo(config.auth)

            else:
                new_auth_info = None

            # Split parameter subpaths
            params = []
            for param in path_item["params"]:
                param_parts = param.split("/")
                params.append(param_parts)

            new_checks.append(GetParameters(
                check_id_start,
                new_request,
                new_auth_info,
                parameters=params
            ))

            check_id_start += 1

        logging.debug(f"Proposed {len(new_checks)} new checks from check {self}")

        return new_checks

    @ classmethod
    def generate(cls, config, check_id_start=0):
        if not config.descriptions:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for descr in config.descriptions.values():
            test_cases.append(FindSecurityParameters(cur_check_id, descr))
            cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def _recursive_search(self, schema_object: dict) -> list[str]:
        """
        Recursively search parameter definitions in a JSON schema object.

        :param schema_object: JSON schema definition.
        :type schema_object: dict
        """
        found_params = []
        for param_name, param in schema_object.items():
            param_descr = ""

            if "description" in param.keys():
                param_descr = param["description"]

            for candidate in self._candidate_strings:
                if candidate in param_name.lower() or \
                        candidate in param_descr.lower():
                    found_params.append(param_name)

            if isinstance(param, dict):
                if not "properties" in param.keys():
                    continue

                subschema_object = param["properties"]
                subparams = self._recursive_search(subschema_object)
                for subparam_name in subparams:
                    subparam_id = "/".join((param_name, subparam_name))
                    found_params.append(subparam_id)

        return found_params

    def serialize(self) -> dict:
        serialized = {
            "description": self.description.description_id,
        }

        return serialized

    @ classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        description = config.descriptions[serialized["description"]]

        return FindSecurityParameters(check_id, description)


class FindDuplicateParameters(TestCase):
    """
    Find parameters that are returned at multiple endpoints. This can be used to find
    alternative ways to access a specific parameter.
    """
    test_type = TestCaseType.ANALYTICAL
    auth_type = AuthType.NOPE
    live_type = LiveType.OFFLINE

    def __init__(self, check_id: int, description: OpenAPI) -> None:
        """
        Creates a new check for FindDuplicateParameters.

        :param description: API description.
        :type description: OpenAPI
        """
        super().__init__(check_id)

        self.description = description

    def run(self):
        self.result.status = CheckStatus.RUNNING

        try:
            paths = self.description.endpoints

        except KeyError as error:
            logging.warning("Could not find 'paths' entry in API description.")
            self.result.error = error
            self.result.status = CheckStatus.ERROR
            return

        # Parameters by name
        params = {}

        # Components by reference
        components = {}

        # Search for parameters and components
        for path_id, path in paths.items():
            for op_id, op in path.items():
                responses = op["responses"]
                for status_code, response in responses.items():
                    if not "content" in response.keys():
                        logging.info("Response has no content.")
                        continue

                    response_content = response["content"]
                    for cty in response_content.values():
                        if not "schema" in cty.keys():
                            logging.info("Response content has no schema.")
                            continue

                        schema_defs = []
                        schema_def = cty["schema"]

                        if "$ref" in schema_def.keys():
                            component_ref = schema_def["$ref"]
                            if component_ref not in components.keys():
                                components.update({
                                    component_ref: {
                                        "endpoints": [{
                                            "op": op_id,
                                            "path": path_id,
                                            "response_code": status_code
                                        }],
                                        "count": 1,
                                    }
                                })

                            else:
                                components[component_ref]["endpoints"].append({
                                    "op": op_id,
                                    "path": path_id,
                                    "response_code": status_code
                                })
                                components[component_ref]["count"] += 1

                            schema_def = self.description.resolve_ref(schema_def["$ref"])

                        # Handle choices
                        if "allOf" in schema_def.keys():
                            schema_defs.extend(schema_def["allOf"])

                        elif "oneOf" in schema_def.keys():
                            schema_defs.extend(schema_def["oneOf"])

                        else:
                            schema_defs.append(schema_def)

                        for schema in schema_defs:
                            if not "properties" in schema.keys():
                                continue

                            schema_object = schema["properties"]

                            found_params = self._recursive_search(schema_object)
                            if len(found_params) == 0:
                                continue

                            for param_id, param_meta in found_params.items():
                                param_meta.update({
                                    "endpoints": [{
                                        "op": op_id,
                                        "path": path_id,
                                        "response_code": status_code
                                    }],
                                })

                                if param_id not in params.keys():
                                    params.update({
                                        param_id: param_meta
                                    })

                                else:
                                    params[param_id]["endpoints"].append(param_meta["endpoints"])
                                    params[param_id]["count"] += param_meta["count"]

        # Look for duplicate parameters (i.e. count > 1)
        candidate_params = {}
        for param_name, param_data in params.items():
            if param_data["count"] > 1:
                candidate_params.update({
                    param_name: param_data
                })

        # Look for duplicate components (i.e. count > 1)
        candidate_components = {}
        for component_ref, component_data in components.items():
            if component_data["count"] > 1:
                candidate_components.update({
                    component_ref: component_data
                })

        if len(candidate_params) > 0 or len(candidate_components) > 0:
            self.result.issue_type = IssueType.CANDIDATE

        else:
            self.result.issue_type = IssueType.NO_CANDIDATE

        self.result.value = {
            "params_count": len(candidate_params),
            "params": dict(sorted(candidate_params.items(), key=lambda dic: dic[0])),
            "components_count": len(candidate_params),
            "components": dict(sorted(candidate_components.items(), key=lambda dic: dic[0])),
        }

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
        if not config.descriptions:
            return []

        cur_check_id = check_id_start
        test_cases = []
        for descr in config.descriptions.values():
            test_cases.append(FindDuplicateParameters(cur_check_id, descr))
            cur_check_id += 1

        logging.debug(f"Generated {len(test_cases)} checks from test case {cls}")

        return test_cases

    def serialize(self) -> dict:
        serialized = {
            "description": self.description.description_id,
        }

        return serialized

    @ classmethod
    def deserialize(cls, serialized, config, check_id: int = 0):
        description = config.descriptions[serialized["description"]]

        return FindDuplicateParameters(check_id, description)

    def _recursive_search(self, schema_object: dict) -> dict[str, dict]:
        """
        Recursively search parameter definitions in a JSON schema object.

        :param schema_object: JSON schema definition.
        :type schema_object: dict
        """
        found_params: dict[str, dict] = {}
        for param_name, param in schema_object.items():
            if param_name not in found_params.keys():
                found_params.update({
                    param_name: {
                        "count": 1
                    }
                })

            else:
                found_params[param_name]["count"] += 1

            if "properties" in param.keys():
                subschema_object = param["properties"]
                subparams = self._recursive_search(subschema_object)
                for subparam_name in subparams.keys():
                    if subparam_name not in found_params.keys():
                        found_params.update({
                            param_name: {
                                "count": 1
                            }
                        })

                    else:
                        found_params[param_name]["count"] += 1

        return found_params
