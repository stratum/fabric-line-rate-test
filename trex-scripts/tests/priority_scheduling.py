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
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont, STLTXSingleBurst, STLFlowLatencyStats


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
        parser.add_argument("--duration", type=float, help="Test duration", default=10)


    # The entrypoint of a test
    def start(self, args: dict) -> None:

        # create packets
        pkt1 = Ether(dst=DEST_MAC) / IP(src="16.0.0.1",dst="48.0.0.1") / UDP(dport=12,sport=1025) / ("*" * 1500)
        pkt2 = Ether(dst=DEST_MAC) / IP(src="16.0.0.2",dst="48.0.0.2") / UDP(dport=12,sport=1025) / ("*" * 1500)

        #stream list
        streams = []

        # Create a traffic stream
        # assume s1 is a delay critical stream
        s1 = STLStream( packet=STLPktBuilder(pkt=pkt1), mode=STLTXCont(bps_L2 = 200000), flow_stats = STLFlowLatencyStats(pg_id = 5))
        # assume s2 is a lower priority stream
        s2 = STLStream( packet=STLPktBuilder(pkt=pkt2), mode=STLTXCont(bps_L2 = 35000000000), flow_stats = STLFlowLatencyStats(pg_id = 10))


        # prepare ports
        self.client.reset(ports=[0,1])

        # add sterams
        streams.append(s1)
        streams.append(s2)
        self.client.add_streams(streams, ports=[0])


        logging.info(
                "Starting traffic, duration: %d sec", args.duration,
        )

        # Start sending traffic
        self.client.start(SENDER_PORT, mult="100%", duration=args.duration)
        pgids = self.client.get_active_pgids()


        logging.info("Waiting until all traffic stop")
        self.client.wait_on_traffic(ports=SENDER_PORT)

        # stats for pg_id 5
        stats            = self.client.get_pgid_stats(pgids['latency'])
        flow_stats       = stats['flow_stats'].get(5)
        global_lat_stats = stats['latency']
        lat_stats        = global_lat_stats.get(5)

        tx_pkts  = flow_stats['tx_pkts'].get(0, 0)
        tx_bytes = flow_stats['tx_bytes'].get(0, 0)
        tx_pps   = flow_stats['tx_pps'].get(0, 0)
        rx_pkts  = flow_stats['rx_pkts'].get(1, 0)
        drops    = lat_stats['err_cntrs']['dropped']

        print(" \n TX and RX flow stats and packet dopped for pg id 5 (i.e., delay critical): ")
        print("  tx packets: {0}".format(tx_pkts))
        print("  tx bytes : {0}".format(tx_pps))
        print("  rx packets : {0}".format(rx_pkts))
        print("  drops: {0}".format(drops))


        # latency info for pg_id 5
        lat = lat_stats['latency']
        jitter = lat['jitter']
        avg = lat['average']
        tot_max = lat['total_max']
        tot_min = lat['total_min']
        print('\n Latency info for pg id 5 (ie., delay critical):')
        print("  Maximum latency(usec): {0}".format(tot_max))
        print("  Minimum latency(usec): {0}".format(tot_min))
        print("  Average latency(usec): {0}".format(avg))


        # Get statistics for TX and RX ports
        stats = self.client.get_stats()
        readable_stats_0 = get_readable_port_stats(stats[0])
        readable_stats_1 = get_readable_port_stats(stats[1])

        print ("\n Overall Statistics for TX port: \n")
        print (readable_stats_0)
        print ("\n Overall Statistics for RX port: \n")
        print (readable_stats_1)
