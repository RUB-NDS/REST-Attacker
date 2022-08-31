# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Listen to OAuth2 redirects to localhost.
"""

from http.server import BaseHTTPRequestHandler
from os.path import dirname
from urllib.parse import unquote

# Content of the denug page shown in the browser
PAYLOAD = open(f"{dirname(__file__)}/server_payload.html", encoding='utf-8').read()


class RedirectHandler(BaseHTTPRequestHandler):
    """
    Listens to incoming HTTP requests.
    """
    called = False
    call_url = None

    def do_GET(self) -> None:
        query_params = self._get_query_params()
        if "fragment" in query_params:
            return self._implicit_handler()

        # Always return HTTPS URL because oauthlib does not like plain HTTP
        call_url = "https://"
        call_url += self.server.server_address[0]
        call_url += ":"
        call_url += str(self.server.server_address[1])
        call_url += self.path

        RedirectHandler.called = True
        RedirectHandler.call_url = call_url

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(PAYLOAD.encode('utf-8'))

    def _get_query_params(self) -> dict[str, str]:
        """
        Get the query parameters from the URL path-
        """
        query_string = self.path.split("?")
        if len(query_string) < 2:
            # No query string in path
            return {}

        query_string = query_string[1]
        query_param_strings = query_string.split("&")

        query_params = {}
        for query_param_string in query_param_strings:
            query_param = query_param_string.split("=")
            query_params[query_param[0]] = query_param[1]

        return query_params

    def _implicit_handler(self) -> None:
        """
        Handle a request that contains the fragment value of the implicit grant.
        """
        query_params = self._get_query_params()
        fragment = query_params.pop("fragment")

        call_url = "https://"
        call_url += self.server.server_address[0]
        call_url += ":"
        call_url += str(self.server.server_address[1])
        call_url += self.path.split("?")[0]
        call_url += unquote(fragment)

        RedirectHandler.called = True
        RedirectHandler.call_url = call_url

        self.send_response(200)
        self.end_headers()
