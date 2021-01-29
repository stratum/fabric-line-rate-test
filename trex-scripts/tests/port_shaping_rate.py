# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import json
from argparse import ArgumentParser
from datetime import datetime
from scapy.layers.all import IP, TCP, UDP, Ether

from lib.base_test import StatelessTest
from lib.utils import list_port_status,get_readable_port_stats
from lib.xnt import analysis_report_pcap
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont, STLTXSingleBurst

SOURCE_MAC = "00:00:00:00:00:01"
DEST_MAC   = "00:00:00:00:00:02"


SENDER_PORT   = [0]
RECEIVER_PORT = [1]


class PortShapingSTL(StatelessTest):

    # setup_subparser is an optional class method
    # You can implement this method if you want to add additional command line
    # parameters for your test.
    # Those parameters will be parsed and be passed to the "start" method below as
    # "args" argument.
    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--mult", type=str, help="The speed multiplier", default="1pps"
        )
        parser.add_argument("--duration", type=float, help="Test duration", default=-1)


    # The entrypoint of a test
    def start(self, args: dict) -> None:

        pkt = Ether(dst=DEST_MAC) / IP() / TCP() / ("*" * 1500)
        # Create a traffic stream
        stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=[]), mode=STLTXCont())
        #stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=[]), mode=STLTXSingleBurst(total_pkts=5))
        self.client.add_streams(stream, ports=[0])


        logging.info(
                "Starting traffic, TX rate: %s, duration: %d sec", args.mult, args.duration,
        )

        # Start sending traffic
        self.client.start(SENDER_PORT, mult=args.mult, duration=args.duration)

        logging.info("Waiting until all traffic stop")
        self.client.wait_on_traffic(ports=SENDER_PORT)

        # Get statistics for TX and RX ports
        stats = self.client.get_stats()
        readable_stats_0 = get_readable_port_stats(stats[0])
        readable_stats_1 = get_readable_port_stats(stats[1])

        print ("\n Statistics for TX port: \n")
        print (readable_stats_0)

        print ("\n Statistics for RX port: \n")
        print (readable_stats_1)

        #print (json.dumps(stats[0], indent = 4, separators=(',', ': '), sort_keys = True))
        #print (json.dumps(stats[1], indent = 4, separators=(',', ': '), sort_keys = True))
