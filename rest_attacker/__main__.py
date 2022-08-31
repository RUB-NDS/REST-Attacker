#!/usr/bin/env python3
# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Main entrypoint for the tool. Handles argument parsing.
"""
from __future__ import annotations
import typing

import argparse
from datetime import datetime
import os
import pathlib
import sys
import time
import logging

from rest_attacker.checks.types import AuthType, LiveType, TestCaseType
from rest_attacker.engine.config import EngineConfig
from rest_attacker.engine.generate_checks import generate_checks
from rest_attacker.engine.internal_state import EngineStatus
from rest_attacker.util.auth.token_generator import OAuth2TokenGenerator
from rest_attacker.util.log import setup_logging
import rest_attacker.util.parsers.config_info as config_info
import rest_attacker.util.parsers.config_run as config_run
from rest_attacker.util.request.http_methods import SAFE_METHODS
from rest_attacker.util.request.request_info import AuthRequestInfo, RequestInfo
from rest_attacker.util.response_handler import AccessLimitHandler, RateLimitHandler
from rest_attacker.util.version import GetVersion
from rest_attacker.util.enum_test_cases import GetTestCases, get_test_cases
from rest_attacker.engine.engine import Engine

if typing.TYPE_CHECKING:
    from rest_attacker.checks.generic import TestCase


def parse_args() -> argparse.Namespace:
    """
    Parse CLI arguments to initialize the tool.
    """
    parser = argparse.ArgumentParser(
        "REST-Attacker",
        description=("Pentesting tool for analyzing REST APIs")
    )

    parser.add_argument("config", default=None,
                        help=("Path to the service configuration. "
                              "Can be a directory or OpenAPI file."))

    parser.add_argument("--version", nargs=0, action=GetVersion,
                        help="Print version number.")
    parser.add_argument("--list", "-l", nargs=0, action=GetTestCases,
                        help="List all available test cases.")
    parser.add_argument("--output-dir", default=None,
                        help="Export path for logs and reports.")

    parser.add_argument("--loglevel", type=int, default=3, choices={1, 2, 3, 4, 5},
                        help=("Set the loglevel for the CLI. "
                              "Choices map to Python loglevels. "
                              "Logging to file is always level 5."))

    # parser.add_argument("--demo", action="store_true",
    #                     help="Run the demo. Shortcut for --config-dir demo")

    parser.add_argument("--handle-limits", action="store_true",
                        help="Handle rate and access limits during the test run.")

    parser.add_argument("--safemode", action="store_true", default=False,
                        help=("Deactivate modifying/destructive API operations."))
    parser.add_argument("--fake-inputs", action="store_true",
                        help=("Generate fake input parameter values when generating checks. "
                              "WARNING: May result in destructive behavior."))

    run_cfg = parser.add_mutually_exclusive_group()
    run_cfg.add_argument("--run", default=None,
                         help="Start test run from a run configuration file.")
    run_cfg.add_argument("--continue", default=None, dest='cont',
                         help="Continue test run from a run configuration file.")

    parser.add_argument("--generate", action="store_true",
                        help="Automatically generate checks at load-time.")
    parser.add_argument("--propose", action="store_true",
                        help="Automatically generate checks at run-time.")

    filters = parser.add_argument_group()
    filters.add_argument("--test-cases", action="extend", nargs="+", type=str,
                         help="Only execute checks with the specified test case IDs.")
    filters.add_argument("--test-type", action="extend", nargs="+", type=str,
                         choices={"ANALYTICAL", "SECURITY", "COMPARISON"},
                         help="Only execute checks with the specified TestType.")
    filters.add_argument("--auth-type", action="extend", nargs="+", type=str,
                         choices={"NOPE", "OPTIONAL",
                                  "RECOMMENDED", "REQUIRED"},
                         help="Only execute checks with the specified AuthType.")
    filters.add_argument("--live-type", action="extend", nargs="+", type=str,
                         choices={"ONLINE", "OFFLINE"},
                         help="Only execute checks with the specified LiveType.")

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("--verbosity", '-v', action='count', default=1,
                           help="Set output verbosity level.")
    # verbosity.add_argument("--quiet", action="store_true",
    #                        help="Run without terminal output.")

    proxy = parser.add_argument_group()
    proxy.add_argument("--proxy", default=None, type=str,
                       help="Define a HTTP/HTTPS proxy server for requests.")
    proxy.add_argument("--cacert", default=None, type=str,
                       help="Path to a custom CA certificate.")

    return parser.parse_args()


def setup_outputs(args: argparse.Namespace) -> None:
    """
    Set the output directory for run reports and logging.

    :param args: CLI aguments from argparse.
    :type args: argparse.Namespace
    """
    if args.output_dir:
        args.output_path = pathlib.Path(args.output_dir)

    else:
        args.output_path = pathlib.Path().resolve() / "rest_attacker" / "out"
        out_folder = datetime.utcfromtimestamp(
            time.time()).strftime('%Y-%m-%dT%H-%M-%SZ')
        # Append service config name
        out_folder += f"-{pathlib.Path(args.config).name.split('.')[0]}"

        args.output_path = args.output_path / out_folder

        if not os.path.exists(args.output_path):
            os.makedirs(args.output_path)

    # Setup logging
    logpath = args.output_path / "run.log"
    # Multiply by 10 to match Python loglevels
    args.loglevel = args.loglevel * 10
    setup_logging(cli_loglevel=args.loglevel, logpath=logpath)


def setup_config(args: argparse.Namespace) -> EngineConfig:
    """
    Setup the service configuration for the engine.

    :param args: CLI aguments from argparse.
    :type args: argparse.Namespace
    """
    # if args.demo:
    #     args.config = "demo"
    #     logging.info("Starting demo.")
    #     args.run = pathlib.Path().resolve() / "rest_attacker" / \
    #         "cfg" / "demo" / "runs" / "sample.json"

    args.config_path = pathlib.Path(args.config)
    if not args.config_path.exists():
        # Assume it's a name of a folder in cfg and get the actual path
        args.config_path = pathlib.Path().resolve() / "rest_attacker" / \
            "cfg" / args.config

        if args.config_path.exists():
            cfg = config_info.load_config(args.config_path)

        else:
            raise Exception(f"No service configuration found at '{args.config}'.")

    elif args.config_path.is_dir():
        cfg = config_info.load_config(args.config_path)

    elif args.config_path.is_file():
        cfg = config_info.create_config_from_openapi(args.config_path)

    else:
        raise Exception(f"No service configuration found for '{args.config}'.")

    logging.info(f"Using service configuration at: {args.config_path}")

    cfg.cli_args = args

    return cfg


def setup_run(cfg: EngineConfig, args: argparse.Namespace) -> list[TestCase]:
    """
    Setup the run configuration for the engine.

    :param args: CLI aguments from argparse.
    :type args: argparse.Namespace
    """
    # Test case filters
    test_filters = {}
    if args.test_cases:
        test_filters.update({
            "test_cases": args.test_cases
        })

    if args.test_type:
        test_filters.update({
            "test_type": [TestCaseType[test_type] for test_type in args.test_type]
        })
    if args.auth_type:
        test_filters.update({
            "auth_type": [AuthType[auth_type] for auth_type in args.auth_type]
        })
    if args.live_type:
        test_filters.update({
            "live_type": [LiveType[live_type] for live_type in args.live_type]
        })

    checks = []
    if args.run:
        args.run_path = pathlib.Path(args.run)
        logging.info(f"Using run configuration at: {args.run_path}")
        checks = config_run.load_config(get_test_cases(), cfg, args.run_path)

    elif args.cont:
        args.run_path = pathlib.Path(args.cont)
        logging.info(f"Continuing run from configuration at: {args.run_path}")
        checks = config_run.load_config(get_test_cases(), cfg, args.run_path, continue_run=True)

    elif args.generate:
        logging.info("No run configuration found.")
        logging.info("Resuming with automatically generated checks.")
        checks = generate_checks(cfg, get_test_cases(), test_filters)

    else:
        logging.warning("No run configuration found.")
        logging.warning("Use --run to specify run configuration or "
                        "--generate to automatically generate checks.")

    return checks


def setup_request_backend(args: argparse.Namespace) -> None:
    """
    Configure the request backend.

    :param args: CLI aguments from argparse.
    :type args: argparse.Namespace
    """
    if args.safemode:
        RequestInfo.allowed_ops = SAFE_METHODS

    if args.proxy:
        RequestInfo.global_kwargs["proxies"] = {
            "http": args.proxy,
            "https": args.proxy
        }

    if args.cacert:
        RequestInfo.global_kwargs["verify"] = pathlib.Path(args.cacert)


def setup_limits(cfg: EngineConfig, args: argparse.Namespace) -> list:
    """
    Setup handling of rate and access limits.

    :param args: CLI aguments from argparse.
    :type args: argparse.Namespace
    """
    handlers = []
    if args.handle_limits:
        # Rate limit handler
        headers = {}
        if "custom_headers" in cfg.info.keys():
            headers.update(cfg.info["custom_headers"])

        # handlers.append(RateLimitHandler(headers=headers))

        # Access limit handler
        # User userinfo endpoint of (default) user
        if cfg.current_user_id:
            default_user = cfg.users[cfg.current_user_id]
            if default_user.userinfo_endpoint:
                request_info = RequestInfo(
                    default_user.userinfo_endpoint[0],
                    default_user.userinfo_endpoint[1],
                    default_user.userinfo_endpoint[2]
                )
                # Request required scopes
                # TODO: Look up endpoint and check security requirements (if defined)
                user_cred_ids = default_user.credentials
                scopes = None
                for cred_id in user_cred_ids:
                    # Find a suitable client and request all scopes
                    cred = cfg.credentials[cred_id]

                    if isinstance(cred, OAuth2TokenGenerator):
                        scopes = cred.client_info.supported_scopes
                        break

                auth_info = AuthRequestInfo(cfg.auth, scopes=scopes)

                # TODO: Make interval configurable
                handlers.append(AccessLimitHandler(
                    request_info, auth_info, interval=20))

    return handlers


def main():
    """
    CLI entrypoint of REST-Attacker.
    """
    args = parse_args()

    # Setup output files
    setup_outputs(args)

    # Setup service configuration
    cfg = setup_config(args)

    if args.fake_inputs:
        # Ask for confirmation before doing this.
        print("Do you really want to generate fake inputs?")
        print("This may retrieve, MODIFY or DELETE resources of other users.")
        confirm = input("To proceed anyway type 'Yes, I understand' here: ")

        if confirm != "Yes, I understand":
            return

    # Setup run configuration
    checks = setup_run(cfg, args)
    if len(checks) == 0:
        return

    # Setup Request Backend
    setup_request_backend(args)

    handlers = setup_limits(cfg, args)

    # Start run
    engine = Engine(cfg, checks, handlers=handlers)

    try:
        engine.run()

    except KeyboardInterrupt:
        logging.warning("Aborting run: KeyboardInterrupt")
        engine.abort()

    except Exception as e:
        engine.state.status = EngineStatus.ERROR
        logging.exception(
            "Execution failed with the following error:", exc_info=e)

    # Export results
    try:
        engine.export(args.output_path)

    except Exception as e:
        logging.exception(
            "Exporting results failed with the following error:", exc_info=e)


if __name__ == '__main__':
    sys.exit(main())
