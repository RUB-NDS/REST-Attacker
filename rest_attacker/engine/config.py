# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Stores the main service configuration for the engine.
"""
from __future__ import annotations
import typing

from argparse import Namespace

from rest_attacker.util.auth.auth_generator import AuthGenerator

if typing.TYPE_CHECKING:
    from rest_attacker.util.openapi.wrapper import OpenAPI


class EngineConfig:
    """
    Store configuration information for the test run.
    """

    def __init__(
        self,
        meta: dict,
        info: dict,
        credentials: dict,
        users: dict = None,
        current_user_id: str = None,
        auth_gen: AuthGenerator = None,
        descriptions: dict[str, OpenAPI] = None,
        cli_args: Namespace = None
    ) -> None:
        """
        Create a new configuration object for the engine.

        :param meta: Metadata (name, etc.) for the service.
        :type meta: dict
        :param info: Analysis information (scopes, etc.) for the service.
        :type info: dict
        :param credentials: Authentication information for the service.
        :type credentials: dict
        :param users: User definitions for the service.
        :type users: dict
        :param current_user_id: ID of the currently active user.
        :type current_user_id: str
        :param auth_gen: Authentication generator that handles creation of
        authentication data for checks.
        :type auth_gen: AuthGenerator
        :param descriptions: Available API descriptions.
        :type descriptions: dict
        :param cli_args: Arguments from the RATT CLI interface.
        :type cli_args: argparse.Namespace
        """
        # Metadata about the service
        self.meta = meta

        # Information for the analysis
        self.info = info

        # Credentials info
        self.credentials = credentials

        # User definitions
        self.users = users
        self.current_user_id = current_user_id

        # Auth Generator
        self.auth = auth_gen

        # API Descriptions
        self.descriptions = descriptions

        # CLI args
        self.cli_args = cli_args
