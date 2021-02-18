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
from trex_stl_lib.api import (
    STLFlowLatencyStats,
    STLPktBuilder,
    STLStream,
    STLTXCont,
    STLTXSingleBurst,
)

SOURCE_MAC = "00:00:00:00:00:01"
DEST_MAC = "00:00:00:00:00:02"

SENDER_PORT = [0]
RECEIVER_PORT = [1]

# In this test case, we consider two types of flows: 1) delay critical, and 2) best effort
# assume max. latency for delay critical flows
LATENCY_DC_MAX_USEC = 1000  # in mircoseconds
# assume max. latency for best effort (i.e., low priority flows) traffic during congestion
# with the priortization of delay critical flows
LATENCY_LP_MAX_USEC = 24000  # in mircoseconds


class PriorityScheduling(StatelessTest):

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
        pkt1 = (
            Ether(dst=DEST_MAC)
            / IP(src="16.0.0.1", dst="48.0.0.1")
            / UDP(dport=12, sport=1025)
            / ("*" * 1500)
        )
        pkt2 = (
            Ether(dst=DEST_MAC)
            / IP(src="16.0.0.2", dst="48.0.0.2")
            / UDP(dport=12, sport=1025)
            / ("*" * 1500)
        )
        pkt3 = (
            Ether(dst=DEST_MAC)
            / IP(src="16.0.0.3", dst="48.0.0.3")
            / UDP(dport=12, sport=1025)
            / ("*" * 1500)
        )

        # stream list
        streams = []

        # Create a traffic stream
        # assume s1 is a delay critical stream with QoS
        s1 = STLStream(
            packet=STLPktBuilder(pkt=pkt1),
            mode=STLTXCont(percentage=1),
            flow_stats=STLFlowLatencyStats(pg_id=1),
        )
        # assume s2 is a delay critical stream without QoS
        s2 = STLStream(
            packet=STLPktBuilder(pkt=pkt2),
            mode=STLTXCont(percentage=1),
            flow_stats=STLFlowLatencyStats(pg_id=2),
        )
        # assume s3 is a lower priority stream
        s3 = STLStream(
            packet=STLPktBuilder(pkt=pkt3),
            mode=STLTXCont(percentage=98),
            flow_stats=STLFlowLatencyStats(pg_id=3),
        )

        # prepare ports
        self.client.reset(ports=[0, 1])

        # add sterams
        streams.append(s1)
        streams.append(s2)
        streams.append(s3)
        self.client.add_streams(streams, ports=[0])

        logging.info(
            "Starting traffic, duration: %d sec", args.duration,
        )

        # Start sending traffic
        self.client.start(SENDER_PORT, mult="100%", duration=args.duration)
        pgids = self.client.get_active_pgids()

        logging.info("Waiting until all traffic stop")
        self.client.wait_on_traffic(ports=SENDER_PORT)

        # stats for pg_id 1 and 2
        stats = self.client.get_pgid_stats(pgids["latency"])
        flow_stats_1 = stats["flow_stats"].get(1)
        flow_stats_2 = stats["flow_stats"].get(2)
        global_lat_stats = stats["latency"]
        lat_stats_1 = global_lat_stats.get(1)
        lat_stats_2 = global_lat_stats.get(2)

        tx_pkts_1 = flow_stats_1["tx_pkts"].get(0, 0)
        rx_pkts_1 = flow_stats_1["rx_pkts"].get(1, 0)
        drops_1 = lat_stats_1["err_cntrs"]["dropped"]

        tx_pkts_2 = flow_stats_2["tx_pkts"].get(0, 0)
        rx_pkts_2 = flow_stats_2["rx_pkts"].get(1, 0)
        drops_2 = lat_stats_2["err_cntrs"]["dropped"]

        print(
            " \n TX and RX flow stats and packets dropped for s1 (i.e., delay critical): "
        )
        print("  tx packets: {0}".format(tx_pkts_1))
        print("  tx bytes : {0}".format(tx_pps_1))
        print("  rx packets : {0}".format(rx_pkts_1))
        print("  drops: {0}".format(drops_1))

        print(
            " \n TX and RX flow stats and packets dropped for s2 (i.e., delay critical): "
        )
        print("  tx packets: {0}".format(tx_pkts_2))
        print("  tx bytes : {0}".format(tx_pps_2))
        print("  rx packets : {0}".format(rx_pkts_2))
        print("  drops: {0}".format(drops_2))

        # latency info for s1
        lat_1 = lat_stats_1["latency"]
        avg_1 = lat_1["average"]
        tot_max_1 = lat_1["total_max"]
        tot_min_1 = lat_1["total_min"]

        # latency info for s2
        lat_2 = lat_stats_2["latency"]
        avg_2 = lat_2["average"]
        tot_max_2 = lat_2["total_max"]
        tot_min_2 = lat_2["total_min"]

        print("\n Latency info for s1 (ie., delay critical with QoS):")
        print("  Maximum latency(usec): {0}".format(tot_max_1))
        print("  Minimum latency(usec): {0}".format(tot_min_1))
        print("  Average latency(usec): {0}".format(avg_1))

        print("\n Latency info for s2 (ie., delay critical without QoS):")
        print("  Maximum latency(usec): {0}".format(tot_max_2))
        print("  Minimum latency(usec): {0}".format(tot_min_2))
        print("  Average latency(usec): {0}".format(avg_2))

        # max latency difference between delay critcal streams s1 and s2
        dc_max_lat_diff = tot_max_2 - tot_max_1

        assert (
            LATENCY_LP_MAX_USEC - LATENCY_DC_MAX_USEC
        ) <= dc_max_lat_diff, "Priority scheduling test failed."

        # Get statistics for TX and RX ports
        stats = self.client.get_stats()
        readable_stats_0 = get_readable_port_stats(stats[0])
        readable_stats_1 = get_readable_port_stats(stats[1])

        logging.info("Priority scheduling test successfully executed.")
        print("\n Overall Statistics for TX port: \n")
        print(readable_stats_0)
        print("\n Overall Statistics for RX port: \n")
        print(readable_stats_1)
