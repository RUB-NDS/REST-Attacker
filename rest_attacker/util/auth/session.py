# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Creates and manages an OAuth Resource Owner session.
"""

import webbrowser
from abc import ABC, abstractmethod
import time
import requests


class ROSession(ABC):
    """
    A user session of a resource owner.
    """

    def __init__(self, session_id: str, test_url: str = None) -> None:
        """
        Create a new Resource Owner Session.

        :param session_id: Identifier of the session.
        :type session_id: str
        :param test_url: URL for testing if the session is valid.
        :type test_url: str
        """
        self.session_id = session_id

        self.test_url = test_url

    @abstractmethod
    def setup(self) -> None:
        """
        Create a new session.
        """


class ROCookieSession(ROSession):
    """
    User session using session cookies from an existing browser session.
    """

    def __init__(
        self,
        session_id: str,
        cookies: dict,
        test_url: str = None,
        expires: int = None
    ) -> None:
        """
        Create a new ROCookieSession.

        :param cookies: Cookies from a browser session.
        :type cookies: dict
        :param expires: Expiration time of the session in UNIX time.
        :type expires: int
        """
        super().__init__(session_id, test_url=test_url)

        self.cookies = cookies
        self.expires = expires

        self.setup()

    def setup(self) -> None:
        cookies = requests.cookies.cookiejar_from_dict(self.cookies)
        self.session = requests.Session()
        self.session.cookies = cookies

    def is_expired(self):
        """
        Checks if the current session is expired.
        """
        return self.expires - time.time() < 0

    def is_valid(self) -> bool:
        response = self.session.get(self.test_url)

        return 200 <= response.status_code < 300


class ROWebSession(ROSession):
    """
    User session using a web login.
    """

    def __init__(
        self,
        session_id: str,
        login_url: str,
        login_data: dict,
        test_url: str = None
    ) -> None:
        """
        Create a new ROWebSession. Note that this type of session likely does not work
        for services that use 2FA or CSFR tokens.

        :param login_url: Web login endpoint of the service. Must be accessible via POST method.
        :type login_url: str
        :param login_data: Body parameters with the login data.
        :type login_data: dict
        """
        super().__init__(session_id, test_url=test_url)

        self.login_url = login_url
        self.login_data = login_data

        self.setup()

    def setup(self) -> None:
        self.session = requests.Session()
        login_response = self.session.post(
            self.login_url, data=self.login_data)

        if 400 <= login_response.status_code < 500:
            raise Exception(f"Failed to create session '{self.session_id}'.")

    def is_valid(self) -> bool:
        response = self.session.get(self.test_url)

        return 200 <= response.status_code < 300


class ROBrowserSession(ROSession):
    """
    User session using a browser session.
    """

    def __init__(
        self,
        session_id: str,
        executable: str,
        port: int,
        test_url: str = None
    ) -> None:
        """
        Create a new ROBrowserSession.

        :param executable: Browser executable path.
        :type executable: str
        :param port: Port number used for the local server.
        :type port: int
        """
        super().__init__(session_id, test_url)

        self.executable = executable
        self.port = port

        self.setup()

    def setup(self):
        webbrowser.register(
            "ratt-browser",
            None,
            webbrowser.BackgroundBrowser(self.executable),
            preferred=True
        )

    def authorize(self, url: str) -> None:
        """
        Send the authorization request with a browser using the invocation.

        :param url: URL of the authorization request.
        :type url: str
        """
        browser = webbrowser.get()
        browser.open_new_tab(url)
