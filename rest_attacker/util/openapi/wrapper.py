# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Wrapper for Swagger 2.0 and OpenAPI 3.0 formats
"""

from collections import defaultdict
from urllib.parse import unquote


class OpenAPI:
    """
    Wrapper for an OpenAPI definition.
    """

    def __init__(self, description_id: str, content: dict) -> None:
        """
        Create a new OpenAPI description.

        :param description_id: Identifier for the description.
        :type description_id: str
        :param content: Content of the description file.
        :type content: dict
        """
        self.description_id = description_id
        self.definition = content

        self.version = None
        if "swagger" in self.definition.keys():
            if self.definition["swagger"] == "2.0":
                self.version = self.definition["swagger"]
                self.transform()

        elif "openapi" in self.definition.keys():
            self.version = self.definition["openapi"]

        else:
            raise Exception("Could not find version in OpenAPI description.")

    def transform(self) -> None:
        """
        Transform the format from swagger 2.0 to OpenAPI 3.0.
        """
        # Multiple hosts are supported
        host = self.definition.pop("host")
        base_path = self.definition.pop("basePath")
        schemes = self.definition.pop("schemes")

        servers = []
        for scheme in schemes:
            server_url = f"{scheme}://{host}{base_path}"
            servers.append({"url": server_url})

        self.definition["servers"] = servers

        global_consumes = self.definition.pop("consumes", [])
        global_produces = self.definition.pop("produces", [])
        for path in self.definition["paths"].values():
            for method in path.values():
                local_consumes = method.pop("consumes", [])
                if len(local_consumes) == 0:
                    if len(global_consumes) == 0:
                        local_consumes = []

                    else:
                        local_consumes = global_consumes[0]

                input_parameters = method.pop("parameters", [])
                if len(input_parameters) > 0:
                    response_body = None
                    response_form = None
                    for param in input_parameters:
                        if param["in"] == "body":
                            response_body = {
                                "description": param["description"],
                                "content": {
                                    local_consumes: param["schema"]
                                }
                            }

                        elif param["in"] == "form":
                            response_form = {
                                "description": param["description"],
                                "content": {
                                    local_consumes: param["schema"]
                                }
                            }

                    if response_body:
                        method["responseBody"] = response_body

                    if response_form:
                        method["responseForm"] = response_form

                for response in method["responses"].values():
                    response_schema = response.pop("schema", [])
                    if response_schema:
                        response.update({
                            "content": {
                                global_produces[0]: response_schema
                            }
                        })

    def resolve_ref(self, ref: str) -> None | dict:
        """
        Get the referenced object to a relative reference. The reference can be an
        URI or a JSON pointer (RFC 6901).

        :param ref: Reference URI.
        :type ref: str
        """
        if ref[0] == "#":
            # JSON pointer
            # Remove URI encoding
            new_ref = unquote(ref)

            # Split into parts
            parts = new_ref[2:].split('/')

            # Start at root
            current_item = self.definition
            for part in parts:
                # Replace escaped symbols_ '~', '/'
                part_ref = part.replace('~0', '~')
                part_ref = part_ref.replace("~1", "/")

                if isinstance(current_item, dict):
                    # JSON object
                    current_item = current_item[part_ref]

                elif isinstance(current_item, list):
                    # JSON array
                    current_item = current_item[int(part_ref)]

                else:
                    return Exception(f"Item at {part} in {new_ref} must be a JSON object or array.")

            return current_item

        # TODO: External references
        return None

    def get_security_requirements(self, path: str, operation: str) -> list[dict]:
        """
        Get the security requirements of an endpoint.
        """
        endpoint_def = self.paths[path][operation]
        if "security" in endpoint_def.keys():
            return endpoint_def["security"]

        # Fall back to default security requirements if they exist
        elif "security" in self.definition.keys():
            return self.definition["security"]

        return []

    def requires_auth(self, path: str, operation: str) -> bool:
        """
        Check whether an endpoint requires authentication or authorization for access.
        """
        endpoint_reqs = self.get_security_requirements(path, operation)

        return len(endpoint_reqs) > 0

    def get_required_param_defs(self, path: str, operation: str) -> dict[str, dict]:
        """
        Get the parameter requirement definitions for an endpoint.
        """
        path_def = self.paths[path]
        endpoint_def = path_def[operation]
        params = {}

        # Path parameters
        if "parameters" in path_def.keys():
            for param in path_def["parameters"]:
                if "$ref" in param.keys():
                    param = self.resolve_ref(param["$ref"])

                if "required" in param.keys() and param["required"] == True:
                    params.update({
                        param["name"]: param
                    })

        # Endpoint parameters (overwrite path parameter definitions)
        if "parameters" in endpoint_def.keys():
            for param in endpoint_def["parameters"]:
                if "$ref" in param.keys():
                    param = self.resolve_ref(param["$ref"])

                if "required" in param.keys() and param["required"] == True:
                    params.update({
                        param["name"]: param
                    })

                elif "required" in param.keys() and param["required"] == False:
                    params.pop(param["name"], None)

        return params

    def get_required_param_ids(self, path: str, operation: str) -> list[str]:
        """
        Get the IDs of the required parameter of an endpoint.
        """
        return list(self.get_required_param_defs(path, operation).keys())

    def requires_parameters(self, path: str, operation: str) -> bool:
        """
        Check whether an endpoint requires one or more input parameters.
        """
        endpoint_reqs = self.get_required_param_ids(path, operation)

        return len(endpoint_reqs) > 0

    def get_nosec_endpoints(self) -> dict[str, list[str]]:
        """
        Get all endpoint IDs that require no security.
        """
        endpoints = defaultdict(list)

        search_endpoints = self.endpoints
        for path_id, path in search_endpoints.items():
            for op_id, _ in path.items():
                if not self.requires_auth(path_id, op_id):
                    endpoints[path_id].append(op_id)

        return dict(endpoints)

    def get_sec_endpoints(self) -> dict[str, list[str]]:
        """
        Get all endpoint IDs that have at least one security requirement.
        """
        endpoints = defaultdict(list)

        search_endpoints = self.endpoints
        for path_id, path in search_endpoints.items():
            for op_id, _ in path.items():
                if self.requires_auth(path_id, op_id):
                    endpoints[path_id].append(op_id)

        return dict(endpoints)

    def get_param_endpoints(self) -> dict[str, list[str]]:
        """
        Get all endpoint IDs that have at least one parameter requirement.
        """
        endpoints = defaultdict(list)

        search_endpoints = self.endpoints
        for path_id, path in search_endpoints.items():
            for op_id, _ in path.items():
                if self.requires_parameters(path_id, op_id):
                    endpoints[path_id].append(op_id)

        return dict(endpoints)

    def get_noparam_endpoints(self) -> dict[str, list[str]]:
        """
        Get all endpoint IDs that require no parameter.
        """
        endpoints = defaultdict(list)

        search_endpoints = self.endpoints
        for path_id, path in search_endpoints.items():
            for op_id, _ in path.items():
                if not self.requires_parameters(path_id, op_id):
                    endpoints[path_id].append(op_id)

        return dict(endpoints)

    @property
    def components(self) -> dict:
        """
        Get the component definitions of the description.
        """
        return self.definition["components"]

    @property
    def endpoints(self) -> dict[str, dict]:
        """
        Get only the path + operation definitions of the description. Other
        fields from the PathItem object (summary, description, servers, parameters)
        are excluded.
        """
        endpoints = defaultdict(dict)

        for path_id, path in self.paths.items():
            if "$ref" in path.keys():
                # Follow reference
                path = self.resolve_ref(path["$ref"])

            for op_id, operation in path.items():
                if op_id in ("summary", "description", "servers", "parameters"):
                    continue

                endpoints[path_id].update({
                    op_id: operation
                })

        return dict(endpoints)

    @ property
    def paths(self) -> dict[str, dict]:
        """
        Get the path definitions of the description.
        """
        return self.definition["paths"]

    @ property
    def servers(self) -> list[dict]:
        """
        Get the server definitions of the description.
        """
        return self.definition["servers"]

    def __getitem__(self, key):
        return self.definition[key]

    def __contains__(self, key):
        return key in self.definition.keys()
