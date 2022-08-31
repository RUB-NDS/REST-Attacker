# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Loads the auth configuration format.
"""

from __future__ import annotations
import typing

import json
import logging

from rest_attacker.util.auth.auth_generator import AuthGenerator
from rest_attacker.util.auth.auth_scheme import AuthType, BasicAuthScheme, KeyValueAuthScheme
from rest_attacker.util.auth.session import ROBrowserSession, ROCookieSession, ROWebSession
from rest_attacker.util.auth.token_generator import ClientInfo, OAuth2TokenGenerator
from rest_attacker.util.auth.userinfo import UserInfo

if typing.TYPE_CHECKING:
    from pathlib import Path


def load_auth_file(path: Path) -> tuple[typing.Optional[dict[str, UserInfo]],
                                        dict,
                                        AuthGenerator]:
    """
    Load a credentials and authentication info from JSON.

    :param path: Path to the credentials file.
    :type path: pathlib.Path
    """
    logging.debug("Starting: Loading credentials configuration.")

    if not path.exists():
        raise Exception(f"Configuration in '{path}' does not exist.")

    if not path.is_file():
        raise Exception(f"{path} is not a file")

    with path.open() as credfile:
        auth_data = json.load(credfile)

    logging.debug(f"Using service credentials file at: {path}")

    # Users + sessions (optional)
    users = None
    if "users" in auth_data.keys():
        users = {}
        users_info = auth_data["users"]

        for user_internal_id, user_data in users_info.items():
            user_info_data = {
                "internal_id": user_internal_id,
                "account_id": user_data["account_id"],
                "user_id": user_data["user_id"]
            }

            if "userinfo_endpoint" in user_data.keys():
                user_info_data["userinfo_endpoint"] = user_data["userinfo_endpoint"]

            if "owned_resources" in user_data.keys():
                user_info_data["owned_resources"] = user_data["owned_resources"]

            if "allowed_resources" in user_data.keys():
                user_info_data["allowed_resources"] = user_data["allowed_resources"]

            if "credentials" in user_data.keys():
                user_info_data["credentials"] = user_data["credentials"]

            if "sessions" in user_data.keys():
                sessions = {}
                sessions_info = user_data["sessions"]

                for session_id, session_data in sessions_info.items():
                    test_url = None
                    if "test_url" in session_data.keys():
                        test_url = session_data["test_url"]

                    if session_data["type"] == "weblogin":
                        login_data = session_data["params"]
                        login_url = session_data["url"]
                        session = ROWebSession(session_id, login_url, login_data, test_url=test_url)

                        sessions.update({
                            session_id: session
                        })

                    elif session_data["type"] == "cookie":
                        cookies = session_data["params"]
                        session = ROCookieSession(session_id, cookies, test_url=test_url)

                        sessions.update({
                            session_id: session
                        })

                    elif session_data["type"] == "browser":
                        executable = session_data["exec_path"]
                        port = int(session_data["local_port"])
                        session = ROBrowserSession(session_id, executable, port, test_url=test_url)

                        sessions.update({
                            session_id: session
                        })

                    else:
                        raise ValueError(f"Unrecognized session type: '{session_data['type']}'")

                    logging.debug(f"Added session info: {session_id}")

                user_info_data["sessions"] = sessions

            users.update({
                user_internal_id: UserInfo(**user_info_data)
            })

            logging.debug(f"Added user info: {user_internal_id}")

    # Required auth infos (optional)
    required_min = {}
    if "required_always" in auth_data.keys():
        required_min = auth_data["required_always"]

        logging.debug("Added unauthorized scheme requirements")

    else:
        logging.debug("No unauthorized schemes specified.")

    required_auth = {}
    if "required_auth" in auth_data.keys():
        required_auth = auth_data["required_auth"]

        logging.debug("Added authenticated scheme requirements")

    else:
        logging.debug("No authenticated schemes specified.")

    # Credentials
    credentials = auth_data["creds"]

    # Create token generators for OAuth2
    for cred_id, cred in auth_data["creds"].items():
        if cred["type"] == "oauth2_client":
            client_info_data = {
                "client_id": cred["client_id"],
                "client_secret": cred["client_secret"],
                "redirect_urls": cred["redirect_uris"],
                "auth_url": cred["authorization_endpoint"],
                "token_url": cred["token_endpoint"],
            }

            if "revocation_endpoint" in cred.keys():
                client_info_data.update(
                    {"revoke_url": cred["revocation_endpoint"]}
                )

            if "scopes" in cred.keys():
                client_info_data.update(
                    {"scopes": cred["scopes"]}
                )

            if "grants" in cred.keys():
                client_info_data.update(
                    {"grants": cred["grants"]}
                )

            if "description" in cred.keys():
                client_info_data.update(
                    {"description": cred["description"]}
                )

            if "flags" in cred.keys():
                client_info_data.update(
                    {"flags": cred["flags"]}
                )

            client_info = ClientInfo(**client_info_data)

            # Initialize with a user-agent session to retrieve tokens
            default_user = None
            if users and len(users) > 0:
                default_user = list(users.values())[0]

            token_gen = OAuth2TokenGenerator(client_info, user_agent=default_user)

            # Replace data with reference to token generator
            credentials.update({
                cred_id: token_gen
            })

            logging.debug(f"Created token generator for credentials: {cred_id}")

        logging.debug(f"Added credentials: {cred_id}")

    # Schemes
    schemes = {}
    scheme_info = auth_data["schemes"]
    for scheme_id, scheme in scheme_info.items():
        auth_type = AuthType[scheme["type"].upper()]
        payload_pattern = scheme["payload"]
        params_cfg = scheme["params"]

        scheme_creds = {}
        for _, param in params_cfg.items():
            param_srcs = param["from"]
            for param_src in param_srcs:
                scheme_creds.update({
                    param_src: credentials[param_src]
                })

        if auth_type is AuthType.BASIC:
            schemes.update({
                scheme_id: BasicAuthScheme(
                    scheme_id, payload_pattern, params_cfg, credentials=scheme_creds)
            })

        else:
            key_id = scheme["key_id"]
            schemes.update({
                scheme_id: KeyValueAuthScheme(
                    scheme_id, auth_type, key_id, payload_pattern,
                    params_cfg, credentials=scheme_creds)
            })

        logging.debug(f"Added scheme: {scheme_id}")

    auth_gen = AuthGenerator(schemes, required_min, required_auth)

    logging.debug("Finished: Loading credentials configuration.")

    return users, credentials, auth_gen
