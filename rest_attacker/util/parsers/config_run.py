# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Loads the configuration formats.
"""

from __future__ import annotations
import typing

import json
import logging
from pathlib import Path

if typing.TYPE_CHECKING:
    from rest_attacker.checks.generic import TestCase
    from rest_attacker.engine.config import EngineConfig


def load_config(
    test_cases: dict[str, TestCase],
    engine_cfg: EngineConfig,
    path: Path,
    continue_run: bool = False
) -> list[TestCase]:
    """
    Load check configurations.

    :param test_cases: Available test cases by test case ID.
    :type test_cases: dict
    :param engine_cfg: Configuration for the service
    :type engine_cfg: EngineConfig
    :param path: Path to the run configuration file.
    :type path: pathlib.Path
    """
    logging.debug("Starting: Loading run configuration.")

    if not path.exists():
        raise Exception(f"Configuration in '{path}'' does not exist.")

    if not path.is_file():
        raise Exception(f"{path} is not a file")

    with path.open() as checkfile:
        check_cfg = json.load(checkfile)

    logging.debug(f"Using checks file at: {path}")

    if check_cfg["type"] == "report":
        check_defs = check_cfg["reports"]

    elif check_cfg["type"] == "run":
        check_defs = check_cfg["checks"]

    elif check_cfg["type"] == "partial":
        part_check_defs = check_cfg["reports"]

        if continue_run:
            # Only run the aborted checks
            check_defs = []
            for check_def in part_check_defs:
                if check_def["status"] == "aborted":
                    check_defs.append(check_def)

        else:
            check_defs = part_check_defs

    checks = []
    for check_def in check_defs:
        if not "config" in check_def:
            # No serialization provided
            logging.warning(f"Skipping check {check_def['check_id']}: No serialization found.")
            continue

        check_id = check_def["check_id"]
        test_case_id = check_def["test_case"]
        test_case_cls = test_cases[test_case_id]

        check = test_case_cls.deserialize(check_def["config"], engine_cfg, check_id)
        if check:
            checks.append(check)
            logging.debug(
                f"Configured check for test case '{check_def['test_case']}' loaded.")

        else:
            logging.info(
                f"Check '{check_def['check_id']}' coild not be loaded. "
                "No deserialization avaliable")

    logging.debug(f"{len(checks)} checks loaded.")
    logging.debug("Finished: Loading run configuration.")

    return checks
