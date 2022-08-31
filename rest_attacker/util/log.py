# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Setup logging for the tool.
"""

import logging


def setup_logging(cli_loglevel=logging.WARNING, file_loglevel=logging.DEBUG, logpath=None):
    """
    Setup logging for the tool.

    :param cli_loglevel: Loglevel for logging to the CLI.
    :type cli_loglevel: int
    :param file_loglevel: Loglevel for logging to file.
    :type file_loglevel: EngineConfig
    :param logpath: Path to the log file. If 'None', no file handler is created.
    :type logpath: pathlib.Path
    """
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("[%(levelname)s] %(message)s")

    # CLI output
    handler = logging.StreamHandler()
    handler.setLevel(cli_loglevel)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # File output
    handler = logging.FileHandler(str(logpath.resolve()))
    handler.setLevel(file_loglevel)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    logging.info(f"Logfile created at: {logpath}")
