# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Manages authentication schemes.
"""

from abc import ABC, abstractmethod
import base64
import enum
import re
from typing import Collection, Mapping


from rest_attacker.util.auth.token_generator import AccessLevelPolicy, OAuth2TokenGenerator


class AuthType(enum.Enum):
    """
    Authentication Types.
    """
    QUERY = "query"
    HEADER = "header"
    BASIC = "basic"
    COOKIE = "cookie"


class AuthScheme(ABC):
    """
    Stores patterns to generate authentication/authorization information.
    """

    def __init__(
        self,
        scheme_id: str,
        auth_type: AuthType,
        credentials: dict = {},
        default_creds: Mapping[str, str] = None
    ) -> None:
        """
        Create a new AuthScheme.

        :param scheme_id: ID of the scheme.
        :type scheme_id: str
        :param auth_type: Location of the scheme in the request.
        :type auth_type: AuthType
        :param credentials: Credentials used by the scheme.
        :type credentials: dict[str,dict]
        :param default_creds: Map of parameter ID to credential ID. Overrides the preference in the
                              parameter config.
        :type default_creds: dict[str,str]
        """
        self.scheme_id = scheme_id
        self.auth_type = auth_type
        self.credentials = credentials
        self.default_creds = None

        if default_creds:
            self.default_creds = {}
            for param_id, cred_id in default_creds.items():
                self.default_creds[param_id] = self.credentials[cred_id]

    def supports_credential_id(self, credentials_id: str) -> bool:
        """
        Checks if the auth scheme supports the credentials with the specified ID.

        :param credentials_id: ID of credentials.
        :type credentials_id: str
        """
        return credentials_id in self.credentials.keys()

    def supports_credentials(self, credentials: Collection) -> bool:
        """
        Checks if the auth scheme supports all credentials with the IDs in the collection.

        :param credentials: Collection of credential IDs.
        :type credentials: Collection
        """
        return all(self.supports_credential_id(cred_id) for cred_id in credentials)

    @abstractmethod
    def get_auth(
        self,
        credentials_map: Mapping[str, str] = None,
        scopes: list[str] = None,
        access_policy: AccessLevelPolicy = AccessLevelPolicy.DEFAULT
    ) -> tuple[AuthType, dict]:
        """
        Create the authentication info for the scheme.

        :param credentials_map: Map of parameter ID to preferred credentials ID.
        :type credentials_map: dict[str,str]
        :param scopes: Authorization scopes that should be requested. These are ignored
                       for credentials that do not support scoped access control.
        :type scopes: list[str]
        """


class KeyValueAuthScheme(AuthScheme):
    """
    Stores patterns to generate key-value based authentication info.
    """

    def __init__(
        self,
        scheme_id: str,
        auth_type: AuthType,
        key_id: str,
        payload_pattern: str,
        params_cfg: dict,
        credentials: dict = {},
        default_creds: Mapping[str, str] = None
    ) -> None:
        """
        Create a new ValueAuthScheme.

        :param key_id: ID of the key of the key-value pair.
        :type key_id: str
        :param payload_pattern: Regex pattern for building the payload.
        :type payload_pattern: str
        :param params_cfg: Config for the parameters used in the payload.
        :type params_cfg: dict
        """
        super().__init__(scheme_id, auth_type, credentials=credentials, default_creds=default_creds)

        self.key_id = key_id
        self.payload_pattern = payload_pattern
        self.params_cfg = params_cfg

    def get_auth(
        self,
        credentials_map=None,
        scopes: list[str] = None,
        access_policy: AccessLevelPolicy = AccessLevelPolicy.DEFAULT
    ) -> tuple[AuthType, dict]:
        params = re.findall(r"\{[0-9]+\}", self.payload_pattern)

        creds = None
        if credentials_map:
            creds = {}
            for param_id, cred_src_id in credentials_map.items():
                creds[param_id] = self.credentials[cred_src_id]

        elif self.default_creds:
            creds = self.default_creds

        payload_str = self.payload_pattern
        for p_param in params:
            param_cfg = self.params_cfg[p_param[1:-1]]
            cred_value_id = param_cfg["id"]

            if not creds:
                # Use the first entry in the list as default
                cred_src_id = param_cfg["from"][0]

            else:
                # Use the preconfigured default for the scheme
                cred_src_id = creds[cred_value_id]

            try:
                cred = self.credentials[cred_src_id]

            except KeyError as err:
                raise Exception(f"Could not generate auth info for scheme '{self.scheme_id}': "
                                f"Could not find credentials '{cred_src_id}' in dict "
                                f"of credentials for the scheme") from err

            try:
                if isinstance(cred, OAuth2TokenGenerator):
                    param_val = cred.get_token(scopes, policy=access_policy)[cred_value_id]

                elif isinstance(cred, dict):
                    param_val = cred[cred_value_id]

                else:
                    raise Exception(
                        f"Unknown credentials format '{type(cred)}'. "
                        "Expected dict or OAuth2TokenGenerator")

            except KeyError as err:
                raise Exception(f"Could not generate auth info for scheme '{self.scheme_id}': "
                                f"Could not find parameter '{cred_value_id}' in credentials "
                                f"{cred_src_id}") from err

            search_param = re.escape(p_param)
            payload_str = re.sub(search_param, param_val, payload_str)

        value = {
            self.key_id: payload_str
        }

        return self.auth_type, value


class BasicAuthScheme(AuthScheme):
    """
    Stores patterns to generate a HTTP Basic Authentication header.
    """

    def __init__(
        self,
        scheme_id: str,
        payload_pattern: str,
        params_cfg: dict,
        credentials: dict = {},
        default_creds: Mapping[str, str] = None
    ) -> None:
        """
        Create a new BasicAuthScheme.

        :param payload_pattern: Regex pattern for building the payload after the 'Basic' keyword.
        :type payload_pattern: str
        :param params_cfg: Config for the parameters used in the paload.
        :type params_cfg: dict
        """
        super().__init__(scheme_id,
                         AuthType.BASIC,
                         credentials=credentials,
                         default_creds=default_creds)

        self.key_id = 'authorization'
        self.payload_pattern = payload_pattern
        self.params_cfg = params_cfg

    def get_auth(
        self,
        credentials_map=None,
        scopes: list[str] = None,
        access_policy: AccessLevelPolicy = AccessLevelPolicy.DEFAULT
    ) -> tuple[AuthType, dict]:
        params = re.findall(r"\{[0-9]+\}", self.payload_pattern)

        creds = None
        if credentials_map:
            creds = {}
            for param_id, cred_src_id in credentials_map.items():
                creds[param_id] = self.credentials[cred_src_id]

        elif self.default_creds:
            creds = self.default_creds

        payload_str = self.payload_pattern
        for p_param in params:
            param_cfg = self.params_cfg[p_param[1:-1]]
            cred_value_id = param_cfg["id"]

            if not creds:
                # Use the first entry in the list as default
                cred_src_id = param_cfg["from"][0]

            else:
                # Use the preconfigured default for the scheme
                cred_src_id = creds[cred_value_id]

            try:
                cred = self.credentials[cred_src_id]

            except KeyError as err:
                raise Exception(f"Could not generate auth info for scheme '{self.scheme_id}': "
                                f"Could not find credentials '{cred_src_id}' in dict "
                                f"of credentials for the scheme") from err

            try:
                if isinstance(cred, OAuth2TokenGenerator):
                    param_val = cred.get_token(scopes, policy=access_policy)[cred_value_id]

                else:
                    param_val = cred[cred_value_id]

            except KeyError as err:
                raise Exception(f"Could not generate auth info for scheme '{self.scheme_id}': "
                                f"Could not find parameter '{cred_value_id}' in credentials "
                                f"{cred_src_id}") from err

            search_param = re.escape(p_param)
            payload_str = re.sub(search_param, param_val, payload_str)

        # Convert to bytes for Base64 encoding
        payload_bytes = payload_str.encode('ascii')
        payload_str = f"Basic {base64.b64encode(payload_bytes).decode('ascii')}"

        header = {
            self.key_id: payload_str
        }

        return AuthType.HEADER, header
