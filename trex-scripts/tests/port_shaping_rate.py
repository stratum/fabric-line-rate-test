# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import os
from argparse import ArgumentParser
from datetime import datetime

from lib.base_test import StatelessTest
from lib.utils import get_readable_port_stats, list_port_status
from lib.xnt import analysis_report_pcap
from scapy.layers.all import IP, TCP, UDP, Ether
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont, STLTXSingleBurst

SOURCE_MAC = "00:00:00:00:00:01"
DEST_MAC = "00:00:00:00:00:02"


SENDER_PORT = [0]
RECEIVER_PORT = [1]
SHAPING_RATE_MBPS = 1000  # in Mbps


class PortShapingSTL(StatelessTest):

    # setup_subparser is an optional class method
    # You can implement this method if you want to add additional command line
    # parameters for your test.
    # Those parameters will be parsed and be passed to the "start" method below as
    # "args" argument.
    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        parser.add_argument("--duration", type=float, help="Test duration", default=10)

    # The entrypoint of a test
    def start(self, args: dict) -> None:

        pkt = Ether(dst=DEST_MAC) / IP() / TCP() / ("*" * 1500)
        # Create a traffic stream
        stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=[]), mode=STLTXCont())
        self.client.add_streams(stream, ports=[0])

        logging.info(
            "Starting traffic, duration: %d sec", args.duration,
        )

        # Start sending traffic
        self.client.start(SENDER_PORT, mult="100%", duration=args.duration)

        logging.info("Waiting until all traffic stop")
        self.client.wait_on_traffic(ports=SENDER_PORT)

        # Get statistics for TX and RX ports
        stats = self.client.get_stats()
        rx_rate_mbps = stats[1]["rx_bps"] / (10 ** 6)
        assert (
            SHAPING_RATE_MBPS * 0.95 < rx_rate_mbps < SHAPING_RATE_MBPS
        ), "The measured RX rate is not close to the port shaping rate"

        readable_stats_0 = get_readable_port_stats(stats[0])
        readable_stats_1 = get_readable_port_stats(stats[1])

        print("\n Statistics for TX port: \n")
        print(readable_stats_0)

        print("\n Statistics for RX port: \n")
        print(readable_stats_1)
