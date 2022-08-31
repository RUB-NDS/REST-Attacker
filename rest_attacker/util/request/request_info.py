# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Store request info for checks.
"""

import logging
from urllib.parse import urlparse, urlunparse
import requests

from requests.models import Response

from rest_attacker.util.auth.auth_scheme import AuthType
from rest_attacker.util.auth.auth_generator import AuthGenerator
from rest_attacker.util.auth.token_generator import AccessLevelPolicy
from rest_attacker.util.errors import RestrictedOperationError
from rest_attacker.util.request.http_methods import METHODS as HTTP_METHODS


class RequestInfo:
    """
    Request for a check. Wraps around the requests interface to allow
    separate specification of endpoint info, i.e. server URL, endpoint
    path and endpoint operation.
    """
    # Settings that are used for every request. Overwritten by self.kwargs.
    global_kwargs: dict = {}
    allowed_ops = HTTP_METHODS

    def __init__(self, url: str, path: str, operation: str, **kwargs) -> None:
        """
        Creates a new Request object.

        :param url: URL string containing the base path to the REST API.
                    You can also pass a tuple returned from urllib.parse
        :type url: str | tuple
        :param path: Endpoint path.
        :type path: str
        :param operation: Endpoint operation.
        :type operation: str
        :param kwargs: Additional parameters that will be passed to requests.request() method.
        :type kwargs: dict
        """
        if isinstance(url, str):
            self._url = urlparse(url)

        elif isinstance(url, tuple):
            self._url = url

        for idx in range(3, 6):
            # Confirm that the URL contains no query/fragment information
            if len(self._url[idx]) > 0:
                logging.warning("URL for request contains more than scheme, netloc, path.")

        self.path = path
        self.operation = operation

        self.kwargs = kwargs

    def send(self, auth_data: list[tuple[AuthType, dict]] = None) -> Response:
        """
        Send the request and return the response.

        :return: Response to the request.
        :rtype: requests.models.Response
        """
        if self.operation.lower() not in self.allowed_ops:
            raise RestrictedOperationError(f"HTTP Method {self.operation} is not allowed.")

        kwargs = {}
        kwargs.update(self.global_kwargs)

        if auth_data:
            kwargs = self._prepare_auth_args(auth_data)

        else:
            kwargs.update(self.kwargs)

        return requests.request(self.operation, self.endpoint_url, **kwargs)

    def _prepare_auth_args(self, auth_data: list[tuple[AuthType, dict]]) -> dict:
        """
        Prepare request arguments and include auth data.

        :param auth_data: List of auth payloads specialized by auth type.
        :type auth_data: list[tuple[AuthType, dict]]
        """
        # Make a copy to not pollute normal request info
        tmp_kwargs = self.kwargs.copy()

        for auth_type, auth_payload in auth_data:
            if auth_type in (AuthType.HEADER, AuthType.BASIC):
                if not "headers" in tmp_kwargs.keys():
                    tmp_kwargs["headers"] = {}

                tmp_kwargs["headers"].update(auth_payload)

            elif auth_type is AuthType.QUERY:
                if not "params" in tmp_kwargs.keys():
                    tmp_kwargs["params"] = {}

                tmp_kwargs["params"].update(auth_payload)

            elif auth_type is AuthType.COOKIE:
                if not "cookies" in tmp_kwargs.keys():
                    tmp_kwargs["cookies"] = {}

                tmp_kwargs["cookies"].update(auth_payload)

        return tmp_kwargs

    def get_curl_command(self, auth_data: list[tuple[AuthType, dict]] = None) -> str:
        """
        Build a curl CLI command from the request info.
        """
        kwargs = {}
        kwargs.update(self.global_kwargs)

        if auth_data:
            kwargs = self._prepare_auth_args(auth_data)

        else:
            kwargs.update(self.kwargs)

        output = "curl "

        # TODO: Proxies, verify, cert

        # Headers
        if len(self.headers) > 0:
            output += " ".join(
                f"-H \"{header_id}: {header_payload}\""
                for header_id, header_payload in self.headers.items()
            )
            output += " "

        # Cookies
        if len(self.cookies) > 0:
            output += " ".join(
                f"-b \"{cookie_id}={cookie_payload}\""
                for cookie_id, cookie_payload in self.cookies.items()
            )
            output += " "

        # Body Data
        if self.data:
            output += f"-d {self.data} "

        # Follow redirects (by default curl does not follow them)
        if self.allow_redirects:
            output += "-L "

        # Timeout
        if self.timeout:
            output += f"-m {self.timeout} "

        # HTTP method
        output += f"-X {self.operation.upper()} "

        # scheme + host + path
        output += self.endpoint_url

        # Query params
        if self.params:
            output += "?" + "&".join(
                f"{param_id}={param_payload}"
                for param_id, param_payload in self.params.items()
            )

        return output

    @property
    def endpoint_url(self) -> str:
        """
        Get the endpoint URL as a string.
        """
        return f"{urlunparse(self._url)}{self.path}"

    @property
    def url(self) -> str:
        """
        Get the server URL as a string.
        """
        return urlunparse(self._url)

    @url.setter
    def url(self, value) -> None:
        """
        Set the server URL. Can use either a tuple or a str.
        """
        if isinstance(value, str):
            self._url = urlparse(value)

        elif isinstance(value, tuple):
            self._url = value

    # Set optional parameters of requests library
    # TODO: There must be a better way to do this. Subclass Request maybe?
    @property
    def params(self):
        """
        Get the query parameters of the request.
        """
        if "params" in self.kwargs:
            return self.kwargs["params"]

        if "params" in self.global_kwargs:
            return self.global_kwargs["params"]

        return {}

    @params.setter
    def params(self, value):
        """
        Set the query parameters of the request.
        """
        self.kwargs["params"] = value

    @property
    def data(self):
        """
        Get the body parameters or data of the request.
        """
        if "data" in self.kwargs:
            return self.kwargs["data"]

        if "data" in self.global_kwargs:
            return self.global_kwargs["data"]

        return {}

    @data.setter
    def data(self, value):
        """
        Set the body parameters or data of the request.
        """
        self.kwargs["data"] = value

    @property
    def json(self):
        """
        Get the JSON payload of the request.
        """
        if "json" in self.kwargs:
            return self.kwargs["json"]

        if "json" in self.global_kwargs:
            return self.global_kwargs["json"]

        return {}

    @json.setter
    def json(self, value):
        """
        Set the JSON payload of the request.
        """
        self.kwargs["json"] = value

    @property
    def headers(self):
        """
        Get the headers of the request.
        """
        if "headers" in self.kwargs:
            return self.kwargs["headers"]

        if "headers" in self.global_kwargs:
            return self.global_kwargs["headers"]

        return {}

    @headers.setter
    def headers(self, value):
        """
        Set the headers of the request.
        """
        self.kwargs["headers"] = value

    @property
    def cookies(self):
        """
        Get the cookies of the request.
        """
        if "cookies" in self.kwargs:
            return self.kwargs["cookies"]

        if "cookies" in self.global_kwargs:
            return self.global_kwargs["cookies"]

        return {}

    @cookies.setter
    def cookies(self, value):
        """
        Set the cookies of the request.
        """
        self.kwargs["cookies"] = value

    @property
    def timeout(self):
        """
        Get the timeout limit of the request.
        """
        if "timeout" in self.kwargs:
            return self.kwargs["timeout"]

        if "timeout" in self.global_kwargs:
            return self.global_kwargs["timeout"]

        return None

    @timeout.setter
    def timeout(self, value):
        """
        Set the timeout limit of the request.
        """
        self.kwargs["timeout"] = value

    @property
    def allow_redirects(self):
        """
        Get the redirect setting of the request.
        """
        if "allow_redirects" in self.kwargs:
            return self.kwargs["allow_redirects"]

        if "allow_redirects" in self.global_kwargs:
            return self.global_kwargs["allow_redirects"]

        return True

    @allow_redirects.setter
    def allow_redirects(self, value):
        """
        Set the redirect setting of the request.
        """
        self.kwargs["allow_redirects"] = value

    @property
    def proxies(self):
        """
        Get the proxy settings of the request.
        """
        if "proxies" in self.kwargs:
            return self.kwargs["proxies"]

        if "proxies" in self.global_kwargs:
            return self.global_kwargs["proxies"]

        return {}

    @proxies.setter
    def proxies(self, value):
        """
        Set the proxy settings of the request.
        """
        self.kwargs["proxies"] = value

    @property
    def verify(self):
        """
        Get the CA verification settings of the request.
        """
        if "verify" in self.kwargs:
            return self.kwargs["verify"]

        if "verify" in self.global_kwargs:
            return self.global_kwargs["verify"]

        return {}

    @verify.setter
    def verify(self, value):
        """
        Set the CA verification settings of the request.
        """
        self.kwargs["verify"] = value

    @property
    def cert(self):
        """
        Get the client-side cert settings of the request.
        """
        if "cert" in self.kwargs:
            return self.kwargs["cert"]

        if "cert" in self.global_kwargs:
            return self.global_kwargs["cert"]

        return {}

    @cert.setter
    def cert(self, value):
        """
        Set the client-side cert settings of the request.
        """
        self.kwargs["cert"] = value

    def serialize(self) -> dict:
        """
        Serialize a request to a JSON-compatible dict.
        """
        return {
            "url": self.url,
            "path": self.path,
            "operation": self.operation,
            "kwargs": self.kwargs,
            # Global kwargs should be reconfigurable?
            # either way they could be stored somewhere else
            # "global_args": self.global_kwargs
        }

    @classmethod
    def deserialize(cls, serialized: dict):
        """
        Deserialize a request from a JSON-compatible dict to a RequestInfo object.

        :param serialized: Serialized representation of the request.
        :type serialized: dict
        """
        url = serialized.pop("url")
        path = serialized.pop("path")
        operation = serialized.pop("operation")
        kwargs = serialized.pop("kwargs")
        return RequestInfo(url, path, operation, **kwargs)


class AuthRequestInfo:
    """
    Auth information for an online check. Contains a generator for dynamically
    creating authentication and authorization payloads for the request.
    """

    def __init__(
        self,
        auth_gen: AuthGenerator,
        scheme_ids: list[str] = None,
        scopes: list[str] = None,
        policy: AccessLevelPolicy = AccessLevelPolicy.DEFAULT
    ) -> None:
        """
        Creates a new AuthRequestInfo object.

        :param auth_gen: AuthGenerator for creation auth info.
        :type auth_gen: AuthGenerator
        :param scheme_ids: Optional list of scheme IDs that auth info should be generated for.
        :type scheme_ids: list[str]
        :param scopes: List of scopes that are requested if OAuth2 credentials are used.
        :type scopes: list[str]
        """
        self.auth_gen = auth_gen
        self.scheme_ids = scheme_ids
        self.scopes = scopes
        self.policy = policy

    def serialize(self) -> dict:
        """
        Serialize authorized request information to a JSON-compatible dict.
        """
        return {
            # auth_gen is recreated dynamically because its settings can change between runs
            "scheme_ids": self.scheme_ids,
            "scopes": self.scopes,
            "policy": self.policy.name
        }

    @classmethod
    def deserialize(cls, serialized: dict, auth_gen: AuthGenerator):
        """
        Deserialize authorized request information from a JSON-compatible dict to a AuthRequestInfo object.

        :param auth_gen: AuthGenerator for creation auth info.
        :type auth_gen: AuthGenerator
        :param serialized: Serialized representation of the authorized request information.
        :type serialized: dict
        """
        policy = AccessLevelPolicy[serialized.pop("policy")]
        return AuthRequestInfo(auth_gen, policy=policy, **serialized)
