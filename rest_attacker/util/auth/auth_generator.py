# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Generates authentication information from authentication schemes.
"""

import logging

from rest_attacker.util.auth.auth_scheme import AuthScheme, AuthType
from rest_attacker.util.auth.token_generator import AccessLevelPolicy


class AuthGenerator:
    """
    Generates authentication/authorization information for a request.
    """

    def __init__(
        self,
        schemes: dict[str, AuthScheme] = {},
        required_min: dict[str, list[str]] = {},
        required_auth: dict[str, list[str]] = {}
    ) -> None:
        """
        Create a new AuthGenerator.

        :param schemes: Dict of schemes that can be used by the auth generator.
        :type schemes: dict[AuthScheme]
        :param required_min: Dict of scheme lists that are required for non-authenticated
                                 requests.
                                 The first ID in each list is used as the default.
        :type required_min: dict
        :param required_auth: Dict of scheme lists that are required for authenticated requests.
                              The first ID in each list is used as the default.
        :type required_auth: dict
        """
        self.supported_schemes = schemes
        self.required_min = required_min
        self.required_auth = required_auth

    def get_auth(
        self,
        scheme_ids: list[str] = None,
        scopes: list[str] = None,
        policy: AccessLevelPolicy = AccessLevelPolicy.DEFAULT,
    ) -> list[tuple[AuthType, dict]]:
        """
        Get an authentication infos that can be inserted into a request. The location
        of each info in the request is returned as the first parameter of each tuple.

        :param scheme_ids: Optional list of IDs of the authentication schemes that should be used.
        :type scheme_ids: list[str]
        :param scopes: Authorization scopes that should be requested.
        :type scopes: list[str]
        """
        auth_infos = []
        if scheme_ids:
            logging.debug(f"Generating auth infos for schemes {scheme_ids}")
            for scheme_id in scheme_ids:
                auth_infos.append(
                    self.get_auth_scheme(scheme_id=scheme_id, scopes=scopes, policy=policy)
                )

            return auth_infos

        logging.debug(f"Generating auth infos from required schemes {self.required_auth}")
        for scheme_list in self.required_auth.values():
            scheme_id = scheme_list[0]
            auth_infos.append(
                self.get_auth_scheme(scheme_id=scheme_id, scopes=scopes, policy=policy)
            )

        return auth_infos

    def get_min_auth(self) -> list[tuple[AuthType, dict]]:
        """
        Get authentication infos that are required for every request. The location
        of each info in the request is returned as the first parameter of each tuple.
        """
        auth_infos = []
        logging.debug(f"Generating auth infos from required schemes {self.required_min}")
        for scheme_list in self.required_min.values():
            scheme_id = scheme_list[0]
            auth_infos.append(self.get_auth_scheme(scheme_id=scheme_id))

        return auth_infos

    def get_auth_scheme(
        self,
        scheme_id: str = None,
        auth_type: AuthType = None,
        credentials_map: dict[str, str] = None,
        scopes: list[str] = None,
        policy: AccessLevelPolicy = AccessLevelPolicy.DEFAULT,
    ) -> tuple[AuthType, dict]:
        """
        Get an authentication info for a scheme. The location of the info in the request is
        returned as the first parameter. Scheme ID, authentication type and credentials
        can be specified independently. The auth generator will try to find the best match.

        :param scheme_id: ID of the preferred authentication scheme.
        :type scheme_id: str
        :param auth_type: Preferred location of authentication.
        :type scheme_id: AuthType
        :param default_creds: Map of parameter ID to credential ID. Overrides the preference in the
                              parameter config.
        :type default_creds: dict[str,str]
        :param scopes: Authorization scopes that should be requested.
        :type scopes: list[str]
        """
        if scheme_id:
            # Get the specific scheme
            scheme = self.supported_schemes[scheme_id]

            if auth_type and not scheme.auth_type is auth_type:
                # Check if the scheme has the correct auth type
                raise Exception(
                    f"scheme '{scheme.scheme_id}' does not match auth type '{auth_type}'")

            if credentials_map and not scheme.supports_credentials(credentials_map.keys()):
                # Check if the scheme supports the credentials
                raise Exception(
                    f"scheme '{scheme.scheme_id}' does not support "
                    f"credentials '{credentials_map.keys()}'")

        elif auth_type:
            # Use the first matching scheme that can be found
            for sch in self.supported_schemes.values():
                if sch.auth_type is auth_type:
                    scheme = sch
                    break

            else:
                raise Exception(
                    f"Could not find scheme with auth type '{auth_type}'")

        elif credentials_map:
            # Use the first matching scheme that can be found
            for sch in self.supported_schemes.values():
                if sch.supports_credentials(credentials_map.keys()):
                    scheme = sch
                    break

            else:
                raise Exception(
                    f"Could not find scheme that uses credentials '{credentials_map.keys()}'")

        else:
            raise Exception(
                "Generator cannot select scheme. Specify at least one of: "
                "scheme ID, auth type or credentials ID.")

        logging.debug(f"Generating auth info for scheme '{scheme.scheme_id}'")
        auth_type, auth_info = scheme.get_auth(credentials_map=credentials_map,
                                               scopes=scopes,
                                               access_policy=policy)

        return auth_type, auth_info
