# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Generate inputs for parameters in a request.
"""

from __future__ import annotations
import typing

import jsonschema
import re
import logging

from jsf import JSF

if typing.TYPE_CHECKING:
    from rest_attacker.util.auth.userinfo import UserInfo


def fake_param(param_schema: dict):
    """
    Create a fake parameter value for a parameter from a JSON schema definition.

    :param param_schema: JSON schema definition for the parameter.
    :type param_schema: dict
    """
    faker = JSF(param_schema)

    return faker.generate()


def fake_path_params(path: str, param_schemas: dict[str, dict]) -> str:
    """
    Create fake parameter values for parameters in a given path. Returns the
    parametrized path.

    :param path: The path string. Parameters in the path are enclosed by curly brackets.
    :type path: str
    :param param_schemas: JSON schema definition for each parameter.
    :type param_schemas: dict
    """
    new_path = path
    params = re.findall(r"\{[a-zA-Z0-9]+\}", path)

    # REplace all placeholders with fake values
    for p_param in params:
        param_schema = param_schemas[p_param[1:-1]]
        fake_value = fake_param(param_schema)

        search_param = re.escape(p_param)
        new_path = re.sub(search_param, fake_value, new_path)

    return new_path


def replace_params(
    path: str,
    user_info: UserInfo,
    param_defs: dict[str, dict]
) -> tuple[str, dict, dict, dict] | None:
    """
    Replace parameter definitions by user defined values.

    :param defined_params: Replacement values.
    :type defined_params: dict
    :param param_defs: OpenAPI parameter definitions.
    :type param_defs: dict
    """
    if user_info.owned_resources:
        defined_params = user_info.owned_resources

    elif user_info.allowed_resources:
        defined_params = user_info.allowed_resources

    else:
        # No replacement parameters defined
        return None

    new_path = replace_uri_params(path, defined_params)
    header_params, query_params, cookie_params = replace_http_params(defined_params, param_defs)

    return new_path, header_params, query_params, cookie_params


def replace_uri_params(
    path: str,
    defined_params: dict[str, list[str]],
    required_schemas: dict[str, dict] = None
) -> str:
    """
    Replace parameters value for a parameter from a JSON schema definition.

    :param path: The path string. Parameters in the path are enclosed by curly brackets.
    :type path: str
    :param defined_params: Parameter values.
    :type defined_params: dict
    :param required_schemas: JSON schema definitions for the parameters.
    :type required_schemas: dict
    """
    new_path = path
    params = re.findall(r"\{[a-zA-Z0-9]+\}", path)

    # Replace all placeholders
    for param_def in params:
        param_id = param_def[1:-1]
        if not param_id in defined_params.keys():
            # Exit if a required parameter cannot be found
            logging.warning(f"Could not find paramater '{param_id}' in lookup dict.")
            return ""

        param_value = defined_params[param_id][0]
        if required_schemas and param_id in required_schemas.keys():
            # Optional schema validation
            try:
                jsonschema.validate(param_value, required_schemas[param_id])

            except jsonschema.ValidationError:
                # Continue if schema is not correct but log error
                logging.info(
                    f"Parameter '{param_id}' does not conform to requested schema.")

            except jsonschema.SchemaError:
                # Continue if schema is not correct but log error
                logging.info(
                    f"Requested schema for parameter '{param_id}' is invalid.")

        search_param = re.escape(param_def)
        new_path = re.sub(search_param, param_value, new_path)

    return new_path


def replace_http_params(
    defined_params: dict[str, list[str]],
    param_defs: dict[str, dict]
) -> tuple[dict, dict, dict]:
    """
    Replace parameter values for an endpoint from OpenAPI parameter definitions.

    :param defined_params: Replacement values.
    :type defined_params: dict
    :param param_defs: OpenAPI parameter definitions.
    :type param_defs: dict
    """
    header_params = {}
    query_params = {}
    cookie_params = {}

    # Replace all placeholders
    for param_id, param_def in param_defs.items():
        if not param_id in defined_params.keys():
            # Exit if a required parameter cannot be found
            logging.warning(f"Could not find paramater '{param_id}' in lookup dict.")
            return {}, {}, {}

        # TODO: Schema validations?

        if param_def["in"] == "header":
            header_params[param_id] = defined_params[param_id][0]

        elif param_def["in"] == "query":
            query_params[param_id] = defined_params[param_id][0]

        elif param_def["in"] == "cookie":
            cookie_params[param_id] = defined_params[param_id][0]

    return header_params, query_params, cookie_params
