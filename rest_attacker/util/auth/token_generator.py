# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Generates and keeps track of tokens for an OAuth provider.
"""


from http.server import HTTPServer
import logging
import os
import time
import enum

from oauthlib.oauth2.rfc6749.clients.mobile_application import MobileApplicationClient
from oauthlib.oauth2.rfc6749.tokens import OAuth2Token
from requests_oauthlib.oauth2_session import OAuth2Session

from rest_attacker.util.auth.server import RedirectHandler
from rest_attacker.util.auth.session import ROBrowserSession, ROCookieSession, ROWebSession
from rest_attacker.util.auth.userinfo import UserInfo


@enum.unique
class AccessLevelPolicy(enum.Enum):
    """
    Policy for retrieving an access level if no access level is specified.
    """
    NOPE = "nope"      # Scope parameter is omitted (i.e. let authorization server decide)
    DEFAULT = "default"   # if service requires scope parameter: MAX; otherwise NOPE
    MAX = "max"       # get all available scopes (e.g. for guaranteed access)


@enum.unique
class ClientInfoFlag(enum.Enum):
    """
    Flags for client settings.
    """
    SCOPE_REQUIRED = "scope_required"   # Authorization requests must contain scope


class ClientInfo:
    """
    Stores OAuth2 client information.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_urls: list[str],
        auth_url: str,
        token_url: str,
        grants: list[str],
        revoke_url: str = None,
        scopes: list[str] = [],
        flags: list[ClientInfoFlag] = [],
        description: str = None
    ) -> None:
        """
        Creates a new ClientInfo object.

        :param client_id: Client ID.
        :param client_secret: Client secret.
        :param redirect_urls: Redirect URIs registered by the client at the service.
        :param auth_url: URL of the authorization endpoint.
        :param token_url: URL of the token endpoint.
        :param revoke_url: URL for manual revocation of tokens. Implementation is service-specific
                           and not standardized in OAuth2.
        :param grants: List of supported grants.
        :param scopes: List of supported scopes (optional).
        :param scopes: List of flags for token generator settings (optional).
        :param description: Description or name of the client (optional).
        :type client_id: str
        :type client_secret: str
        :type redirect_urls: list[str]
        :type auth_url: str
        :type token_url: str
        :type revoke_url: str
        :type grants: list[str]
        :type scopes: list[str]
        :type flags: list[ClientInfoFlag]
        :type description: str
        """
        self.description = description
        self.client_id = client_id
        self.client_secret = client_secret

        self.redirect_urls = redirect_urls
        self.auth_url = auth_url
        self.token_url = token_url
        self.revoke_url = revoke_url

        self.supported_grants = grants
        self.supported_scopes = scopes

        self.flags = flags


class OAuth2TokenGenerator:
    """
    Generates and keeps track of tokens.
    """

    def __init__(self, client_info: ClientInfo, user_agent: UserInfo = None) -> None:
        """
        Create a new OAuth2TokenGenerator.

        :param client_info: Object that contains information about the service
                            and authentication data for a client.
        :type client_info: ClientInfo
        :param user_agent: User info which can contain a resource owner session which
                           is used to authorize requrests.
        :type user_agent: UserInfo
        """

        self.client_info = client_info
        self.user_agent = user_agent

        self.active_token: OAuth2Token | None = None
        # Requested scopes of active token (not necessarily the scopes of the active token)
        self._req_scopes: list[str] | None = None

        # Log of all previously requested tokens
        # New tokens are appended to the front
        # The first item in the list is the currently active token
        self.token_history: list[OAuth2Token] = []

        self._setup_oauthlib()

    def get_token(
        self,
        scopes: list[str] = None,
        policy: AccessLevelPolicy = AccessLevelPolicy.DEFAULT
    ) -> OAuth2Token:
        """
        Get a valid token for authorization.

        By default, the last generated token is returned. If a token is expired, it will
        be refreshed for a new token if a refresh token is available. If scopes were
        requested and the scopes do not exactly match the scopes of the active token
        (i.e. scope value AND order of scopes), a new token is requested.

        :param scopes: Scopes that must be assigned to this token.
        :type scopes: list[str]
        """
        if not self.active_token:
            return self.request_new_token(scopes=scopes, policy=policy)

        if self._is_expired(self.active_token) and self._is_refreshable(self.active_token):
            # TODO: Use requests_oauthlib's token refresher for automatic updates
            return self.request_new_token(scopes=scopes, grant_type='refresh_token', policy=policy)

        if scopes and self._req_scopes != scopes:
            return self.request_new_token(scopes=scopes, policy=policy)

        return self.active_token

    def get_access_token(self, scopes: list[str] = None) -> str:
        """
        Gets only the access token part required for authentication from a valid token.

        :param scopes: Scopes that must be assigned to this token.
        :type scopes: list[str]
        """
        return self.get_token(scopes=scopes)['access_token']

    def request_new_token(
        self,
        scopes: list[str] = None,
        grant_type: str = 'code',
        policy: AccessLevelPolicy = AccessLevelPolicy.DEFAULT
    ) -> OAuth2Token:
        """
        Fetch a new token from the service.

        :param scopes: Scopes that must be assigned to this token.
        :type scopes: list[str]
        :param grant_type: Grant type used for the OAuth2 exchange.
        :type grant_type: str
        """
        if scopes is None:
            if policy is AccessLevelPolicy.MAX:
                scopes = self.client_info.supported_scopes

            elif "scope_required" in self.client_info.flags and policy is AccessLevelPolicy.DEFAULT:
                # If no scopes are requested, but the service requires the scope parameter
                # request all supported scopes from the authorization server
                scopes = self.client_info.supported_scopes

            elif policy is AccessLevelPolicy.NOPE:
                scopes = None

        logging.debug(f"Requesting new token from client '{self.client_info.client_id}'")
        if self.active_token:
            self.token_history.insert(0, self.active_token)

        if not grant_type in self.client_info.supported_grants:
            raise Exception(f"grant type '{grant_type}'' is not available for service")

        if grant_type == 'code':
            self.active_token = self._request_auth_grant(scopes=scopes)
            self._req_scopes = scopes

        elif grant_type == 'token':
            self.active_token = self._request_impl_grant(scopes=scopes)
            self._req_scopes = scopes

        elif grant_type == 'refresh_token':
            if not self.active_token:
                raise Exception(f"Action 'refresh_token' not available: No currently active token")

            self.active_token = self.refresh_token(token=self.active_token, scopes=scopes)
            self._req_scopes = scopes

        else:
            raise Exception(f"unrecognized grant type: {grant_type}")

        return self.active_token

    def _request_auth_grant(self, scopes: list[str] = None) -> OAuth2Token:
        """
        Fetch a new token from the service using the Authorization Code Grant.

        :param scopes: Scopes that must be assigned to this token.
        :type scopes: list[str]
        """
        logging.debug("Using Authorization Grant to request token")
        session = OAuth2Session(
            client_id=self.client_info.client_id,
            redirect_uri=self._get_redirect_url(),
            scope=scopes
        )
        authorization_url, state = session.authorization_url(self.client_info.auth_url)

        redirect_result = self._get_redirect_result(authorization_url)

        token = session.fetch_token(self.client_info.token_url,
                                    client_secret=self.client_info.client_secret,
                                    authorization_response=redirect_result)

        return token

    def _request_impl_grant(self, scopes: list[str] = None) -> OAuth2Token:
        """
        Fetch a new token from the service using the Implicit Grant.

        :param scopes: Scopes that must be assigned to this token.
        :type scopes: list[str]
        """
        logging.debug("Using Implicit Grant to request token")
        session = OAuth2Session(
            client=MobileApplicationClient(client_id=self.client_info.client_id),
            redirect_uri=self._get_redirect_url(),
            scope=scopes
        )
        authorization_url, state = session.authorization_url(
            self.client_info.auth_url)

        redirect_result = self._get_redirect_result(authorization_url, fragment_expected=True)

        token = session.token_from_fragment(redirect_result)

        return token

    def switch_user(self, user_agent: UserInfo) -> None:
        """
        Switch to a different user for authorizing requests. This will also clear
        the currently active token.

        :param user_agent: UserInfo object definition for the new user.
        :type user_agent: UserInfo
        """
        logging.debug(f"Switching to user '{user_agent.internal_id}'")
        if self.active_token:
            self.token_history.insert(0, self.active_token)
            self.active_token = None

        self.user_agent = user_agent

    def refresh_token(self, token: OAuth2Token, scopes: list[str] = None) -> OAuth2Token:
        """
        Refresh a given token.

        :param token: Token that should be refreshed.
        :type token: OAuth2Token
        :param scopes: Scopes that must be assigned to this token.
        :type scopes: list[str]
        """
        logging.debug("Using Refresh Token Grant to request token")
        session = OAuth2Session(
            client_id=self.client_info.client_id,
            scope=scopes,
            token=token
        )

        new_token = session.refresh_token(
            self.client_info.token_url,
            client_id=self.client_info.client_id,
            client_secret=self.client_info.client_secret
        )

        return new_token

    def _get_redirect_result(self, auth_url: str, fragment_expected: bool = False) -> str:
        """
        Authorize the resource owner by using the supplied user agent (if it exists) and
        return the resulting redirect URL.

        :param auth_url: Authorization URL for the authorization request.
        :type auth_url: str
        :param fragment_expected: True if the redirect URL should contain a fragment, else False.
        :type fragment_expected: bool
        """
        user_session = self._get_user_session()
        if user_session:
            logging.debug(f"Selected user agent via established session: {user_session}")
            if isinstance(user_session, ROBrowserSession):
                server = HTTPServer(
                    ('127.0.0.1', user_session.port),
                    RedirectHandler,
                    bind_and_activate=True
                )

                # Wait max 30 seconds for answer
                server.timeout = 30
                user_session.authorize(auth_url)
                server.handle_request()
                # time.sleep(5)       # Helps when too many auth requests are sent (?)
                if RedirectHandler.called and fragment_expected:
                    RedirectHandler.called = False
                    RedirectHandler.call_url = None

                    # Handle a second request that contains the fragment value
                    server.handle_request()

                if RedirectHandler.called:
                    redirect_result = RedirectHandler.call_url

                    # Reset handler class
                    RedirectHandler.called = False
                    RedirectHandler.call_url = None

                else:
                    logging.warning(f"No redirect received after {server.timeout} seconds. "
                                    "Token could not be generated")
                    return  # TODO: Custom error type

            else:
                redirect_response = user_session.session.get(auth_url, allow_redirects=False)
                redirect_result = redirect_response.headers["location"]

        else:
            logging.debug("No established session found. Creating manual request.")
            cli_manual_request = ("Authorization required for OAuth2 "
                                  f"Authorization Grant:\n{auth_url}")
            print(cli_manual_request)
            logging.debug(cli_manual_request)

            redirect_result = input('Enter the returned URI: ')

        logging.debug(f"Got Redirect URI: {redirect_result}")
        return redirect_result

    def _get_user_session(self):
        """
        Get the user session that is used for authorizing the request.
        """
        user_session = None
        if self.user_agent and self.user_agent.sessions:
            web_session = None
            # Select established session
            for _, session in self.user_agent.sessions.items():
                # Prefer the cookie session
                if isinstance(session, ROCookieSession):
                    user_session = session
                    break

                elif isinstance(session, ROBrowserSession):
                    user_session = session
                    break

                elif isinstance(session, ROWebSession):
                    web_session = session

            else:
                # Use the web session if no alternative is available
                user_session = web_session

        return user_session

    def _get_redirect_url(self) -> str:
        """
        Get the redirect URL that is used for redirecting the user agent.
        """
        if isinstance(self._get_user_session(), ROBrowserSession):
            # Browser sessions need a HTTP redirect URL to avoid TLS handshake
            # problem in HTTPServer
            for url in self.client_info.redirect_urls:
                if url.startswith("http:"):
                    return url

        else:
            # Use HTTPS redirect URL for everything else
            for url in self.client_info.redirect_urls:
                if url.startswith("https:"):
                    return url

        # Default URL (= first URL) as fallback
        return self.client_info.redirect_urls[0]

    def _is_expired(self, token: OAuth2Token) -> bool:
        """
        Check if a given token is expired.

        :param token: Token that is checked.
        :type token: OAuth2Token
        """
        if "expires_at" in token.keys():
            return time.time() - token["expires_at"] > 0

        return False

    def _is_refreshable(self, token: OAuth2Token) -> bool:
        """
        Check if a given token has a refresh token.

        :param token: Token that is checked.
        :type token: OAuth2Token
        """
        return "refresh_token" in token.keys()

    def __getitem__(self, key):
        """
        Access the active token's parameters like a dict.
        """
        return self.get_token()[key]

    @staticmethod
    def _setup_oauthlib() -> None:
        """
        Setup environment variables for oauthlib.
        """
        # Deactivate warning when using HTTP redirects
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

        # Deactivate warning when scopes change ion refresh
        os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
