# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Loads the configuration formats.
"""

import json
import logging

from pathlib import Path

from rest_attacker.util.parsers.config_auth import load_auth_file
from rest_attacker.util.parsers.openapi import load_openapi
from rest_attacker.engine.config import EngineConfig


def load_config(path: Path) -> EngineConfig:
    """
    Load a service info and metadata files from JSON.

    :param path: Path to the service directory.
    :type path: pathlib.Path
    """
    logging.debug("Starting: Loading service configuration.")

    if not path.exists():
        raise Exception(f"Configuration in '{path}' does not exist.")

    if not path.is_dir():
        raise Exception(f"{path} is not a directory.")

    # Mandatory info file
    info_path = path / "info.json"
    with info_path.open() as infofile:
        info = json.load(infofile)

    logging.debug(f"Using service info file at: {info_path}")

    # Non-mandatory information files
    if "meta" in info.keys():
        meta_path = path / info["meta"]
        with meta_path.open() as metafile:
            meta = json.load(metafile)

        logging.debug(f"Using service meta file at: {meta_path}")

    else:
        logging.debug("No service meta file specified: Skipping meta info load.")
        meta = {}

    if "credentials" in info.keys():
        credentials_path = path / info["credentials"]
        users, credentials, auth_gen = load_auth_file(credentials_path)

    else:
        logging.debug("No service credentials file specified: Skipping credential info load.")
        users = None
        credentials = {}
        auth_gen = None

    current_user_id = None
    if users and len(users) > 0:
        current_user_id = list(users.keys())[0]

    if "descriptions" in info.keys():
        descriptions = {}
        for descr_key, descr in info["descriptions"].items():
            if not descr["available"]:
                logging.debug(f"Skipping API description '{descr_key}'")
                continue

            logging.debug(f"Using OpenAPI description '{descr_key}'")
            description_path = path / descr["path"]
            description = load_openapi(descr_key, description_path)
            descriptions[descr_key] = description

        logging.debug(f"{len(descriptions)} API descriptions available.")

    else:
        logging.debug("No API descriptions found.")

        descriptions = None

    logging.debug("Finished: Loading service configuration.")

    return EngineConfig(
        meta,
        info,
        credentials,
        users=users,
        current_user_id=current_user_id,
        auth_gen=auth_gen,
        descriptions=descriptions
    )


def create_config_from_openapi(path: Path) -> EngineConfig:
    """
    Create a temporary config from an OpenAPI description.

    :param path: Path to the OpenAPI file.
    :type path: pathlib.Path
    """
    logging.debug("Starting: Loading OpenAPI file.")

    if not path.exists():
        raise Exception(f"Configuration in '{path}' does not exist.")

    if not path.is_file():
        raise Exception(f"{path} is not a file.")

    # Use filename as key
    descr_key = path.name
    logging.debug(f"Using OpenAPI description '{descr_key}'")
    description = load_openapi(descr_key, path)
    descriptions = {descr_key: description}

    logging.debug("Finished: Loading service configuration.")

    return EngineConfig(
        {},
        {},
        {},
        descriptions=descriptions
    )
