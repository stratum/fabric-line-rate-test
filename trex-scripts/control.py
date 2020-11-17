#!/usr/bin/python3

# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import argparse
import importlib
import inspect
import logging
import os
import sys
import time
import typing
from os import name

from lib.base_test import BaseTest
from lib.utils import ParseExtendArgAction
from trex.astf.api import ASTFClient
from trex.stl.api import STLClient, STLError
from trex.utils.parsing_opts import match_multiplier_help
from trex_stf_lib.trex_client import (
    CTRexClient,
    ProtocolError,
    TRexError,
    TRexInUseError,
    TRexRequestDenied,
)

TREX_FILES_DIR = "/tmp/trex_files/"
LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
DEFAULT_KILL_TIMEOUT = 10
logging.basicConfig(format=LOG_FORMAT, level="INFO")


def get_test_class(test_name: str) -> typing.Type[BaseTest]:
    """
    Get test class from test module

    :parameters:
    test_name: str
        The test name, which is the python module name in the `tests` directory.

    :returns:
        The test class
    """
    try:
        m = importlib.import_module("tests.{}".format(test_name))
        test_classes = [
            mem[1]
            for mem in inspect.getmembers(m)
            if inspect.isclass(mem[1])
            and issubclass(mem[1], BaseTest)
            and not inspect.isabstract(mem[1])
        ]
        if not test_classes:
            logging.error("Unable to find any test classes from %s module", test_name)
            return None

        if len(test_classes) > 1:
            logging.warning(
                "Found more than one test class in %s module, will use %s",
                test_name,
                test_classes[0],
            )
        return test_classes[0]

    except ModuleNotFoundError as e:
        logging.error("Got error when loading the test %s: %s", test_name, e)
        return None


def run_test(
    server_addr: str,
    test_class: typing.Type[BaseTest],
    duration: int,
    mult: str,
    test_args: dict,
) -> int:
    test_type = test_class.test_type()
    if test_type == "stateless":
        client = STLClient(server=server_addr)
    elif test_type == "stateful":
        client = ASTFClient(server=server_addr)
    else:
        # Should noe happened since we already checked from the caller
        logging.error("Unknown test type %s", test_type)
        return 1

    test = test_class(client, duration, mult, test_args)
    try:
        logging.info("Connecting to Trex server...")
        client.connect()
        logging.info("Acquaring ports...")
        client.acquire()
        logging.info("Resetting and clearing port...")
        client.reset()  # Resets configs from all ports
        client.clear_stats()  # Clear status from all ports

        logging.info("Running the test: %s...", test)
        test.start()
    except STLError as e:
        logging.error("Got error from Trex server: %s", e)
        return 1
    finally:
        logging.info("Cleaning up Trex client")
        client.stop()
        client.release()
        client.disconnect()


def parse_command_args() -> None:

    parser = argparse.ArgumentParser(description="Linerate test control plane")
    parser.add_argument(
        "--server-addr",
        type=str,
        help="The server address",
        default="127.0.0.1",
        required=False,
    )
    parser.add_argument("--duration", type=int, help="Test duration", default=5)
    parser.add_argument(
        "--trex-config",
        type=str,
        help="The Trex config to be placed on the server.",
        required=True,
    )
    parser.add_argument(
        "--keep-running",
        action="store_true",
        default=False,
        help="Keep Trex running after the test.",
    )
    parser.add_argument(
        "--force-restart",
        action="store_true",
        default=False,
        help="Force restart the Trex process " + "if there is one running.",
    )
    parser.add_argument(
        "-m", "--mult", default="1pps", type=str, help=match_multiplier_help
    )
    parser.add_argument(
        "-t",
        "--test_args",
        action=ParseExtendArgAction,
        help="Pass additional arguments to the test "
        + "E.g., -a KEY1=VAL1 -a KEY2=VAL2",
        default={},
    )
    parser.add_argument(
        "test",
        type=str,
        help="The test profile, which is the "
        + "filename(without .py) in the test directory",
        default="simple_tcp",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_command_args()

    # Set up the Trex server
    if not os.path.exists(args.trex_config):
        logging.error("Can not find Trex config file: %s", args.trex_config)
        return

    if not os.path.isfile(args.trex_config):
        logging.error("%s is not a file", args.trex_config)
        return 1

    trex_config_file_on_server = TREX_FILES_DIR + os.path.basename(args.trex_config)

    trex_client = CTRexClient(args.server_addr)
    trex_started = False

    try:
        logging.info("Pushing Trex config %s to the server", args.trex_config)
        if not trex_client.push_files(args.trex_config):
            logging.error("Unable to push %s to Trex server", args.trex_config)
            return 1

        if args.force_restart:
            logging.info("Killing all Trexes... with meteorite... Boom!")
            trex_client.kill_all_trexes()

            # Wait until Trex enter the Idle state
            start_time = time.time()
            success = False
            while time.time() - start_time < DEFAULT_KILL_TIMEOUT:
                if trex_client.is_idle():
                    success = True
                    break
                time.sleep(1)

            if not success:
                logging.error(
                    "Unable to kill Trex process, please login "
                    + "to the server and kill it manually."
                )
                return 1

        if not trex_client.is_idle():
            logging.info("The Trex server process is running")
            logging.warning(
                "A Trex server process is still running, "
                + "use --force-restart to kill it if necessary."
            )
            return 1

        test_class = get_test_class(args.test)

        if not test_class:
            logging.error("Unable to get test class for test %s", args.test)
            return 1

        test_type = test_class.test_type()

        logging.info("Starting Trex with %s mode", test_class.test_type())
        if test_type == "stateless":
            # Not checking the return value from this
            # call since it always return True
            trex_client.start_stateless(cfg=trex_config_file_on_server)
            trex_started = True
        elif test_type == "stateful":
            trex_client.start_astf(cfg=trex_config_file_on_server)
            trex_started = True
        else:
            logging.error("Unkonwon test type %s", test_type)
            return 1

        # Start the stateless traffic
        run_test(args.server_addr, test_class, args.duration, args.mult, args.test_args)
    except ConnectionRefusedError:
        logging.error(
            "Unable to connect to server %s.\n" + "Did you start the Trex daemon?",
            args.server_addr,
        )
        return 1
    except ProtocolError as pe:
        logging.error("%s", pe)
        return 1
    except TRexError as te:
        logging.error("TRex error: %s", te.msg)
        return 1
    except TRexInUseError as tiue:
        logging.error("TRex is already taken: %s", tiue.msg)
        return 1
    except TRexRequestDenied as trd:
        logging.error("Request denied: %s", trd.msg)
        return 1
    finally:
        if trex_started and not args.keep_running:
            logging.info("Stopping Trex server")
            trex_client.stop_trex()


if __name__ == "__main__":
    sys.exit(main())
