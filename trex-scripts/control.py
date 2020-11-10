#!/usr/bin/python3

# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

from trex_stl_lib.api import *
import argparse
import importlib


def main():
    parser = argparse.ArgumentParser(description='Linerate test control plane')
    parser.add_argument('--server', type=str, help='The server address',
                        default='127.0.0.1', required=False)
    parser.add_argument('--duration', type=int,
                        help='Test duration', default=5)
    parser.add_argument(
        'test', type=str, help='The test profile, which is the ' +
        'filename(without .py) in the test directory',
        default='simple_tcp')

    args = parser.parse_args()

    try:
        test_module = importlib.import_module('tests.{}'.format(args.test))
    except ModuleNotFoundError as e:
        print('Cannot find {} in tests directory'.format(args.test))
        print(e)
        return

    client = STLClient(server=args.server)

    try:
        client.connect()
        client.acquire()
        client.reset()
        client.clear_stats()
        test = test_module.get_test(client, args.duration)
        test.start()
        stats = client.get_stats()
        import json
        print(json.dumps(stats))

    except STLError as e:
        print("Got error from Trex server: {}".format(e))
    finally:
        client.stop()
        client.release()
        client.disconnect()


if __name__ == '__main__':
    main()
