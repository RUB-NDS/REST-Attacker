# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Handles information about a user/resource owner.
"""

from __future__ import annotations
import typing


if typing.TYPE_CHECKING:
    from rest_attacker.util.auth.session import ROSession


class UserInfo:
    """
    Stores user information.
    """

    def __init__(
            self,
            internal_id: str,
            account_id: str,
            user_id: str,
            userinfo_endpoint: str = None,
            owned_resources: dict[str, list[str]] = {},
            allowed_resources: dict[str, list[str]] = {},
            sessions: dict[str, ROSession] = None,
            credentials: list[str] = [],
    ) -> None:
        """
        Creates a new UserInfo object.

        :param internal_id: Internal ID for the user in the tool.
        :param account_id: ID of the user account (i.e. login name).
        :param user_id: ID of the user in the service.
        :param userinfo_endpoint: API endpoint where user information can be fetched (optional).
        :param owned_resources: Dict of resource IDs mapped to usable object IDs that are owned by the user (optional).
        :param allowed_resources: Dict of resource IDs mapped to usable object IDs that the user has access to, but does not own (optional).
        :param sessions: Sessions that can be used as a user-agent to fetch authorization tokens (optional).
        :param credentials: Credentials that can be used for this user (optional).
        :type internal_id: str
        :type account_id: str
        :type user_id: str
        :type userinfo_endpoint: str
        :type owned_resources: dict[str, list[str]]
        :type allowed_resources: dict[str, list[str]]
        :type sessions: dict[str, ROSession]
        :type credentials: list[str]
        """
        self.internal_id = internal_id

        self.account_id = account_id
        self.user_id = user_id

        self.userinfo_endpoint = userinfo_endpoint

        self.owned_resources = owned_resources
        self.allowed_resources = allowed_resources

        self.sessions = sessions
        self.credentials = credentials
