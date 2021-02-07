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

# assume maximum latency for delay critical flows
LATENCY_DC_MAX_uSEC = 1000   # in mircoseconds
# assume maximum latency for low priority flows during congestion
LATENCY_LP_MAX_uSEC = 25500 # in mircoseconds
# assume average latency for low priority flows during congestion
LATENCY_LP_AVG_uSEC = 15000 # in mircoseconds


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
        pkt1 = Ether(dst=DEST_MAC) / IP(src="16.0.0.1",dst="48.0.0.1") / UDP(dport=12,sport=1025) / ("*" * 1500)
        pkt2 = Ether(dst=DEST_MAC) / IP(src="16.0.0.2",dst="48.0.0.2") / UDP(dport=12,sport=1025) / ("*" * 1500)
        pkt3 = Ether(dst=DEST_MAC) / IP(src="16.0.0.3",dst="48.0.0.3") / UDP(dport=12,sport=1025) / ("*" * 1500)

        #stream list
        streams = []

        # Create a traffic stream
        # assume s1 is a delay critical stream with QoS
        s1 = STLStream( packet=STLPktBuilder(pkt=pkt1), mode=STLTXCont(percentage = 1), flow_stats = STLFlowLatencyStats(pg_id = 5))
        # assume s2 is a delay critical stream without QoS
        s2 = STLStream( packet=STLPktBuilder(pkt=pkt2), mode=STLTXCont(percentage = 1), flow_stats = STLFlowLatencyStats(pg_id = 10))
        # assume s3 is a lower priority stream
        s3 = STLStream( packet=STLPktBuilder(pkt=pkt3), mode=STLTXCont(percentage = 98), flow_stats = STLFlowLatencyStats(pg_id = 15))


        # prepare ports
        self.client.reset(ports=[0,1])

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


        # stats for pg_id 5 and 15
        stats              = self.client.get_pgid_stats(pgids['latency'])
        flow_stats_5       = stats['flow_stats'].get(5)
        flow_stats_10      = stats['flow_stats'].get(10)
        global_lat_stats   = stats['latency']
        lat_stats_5        = global_lat_stats.get(5)
        lat_stats_10       = global_lat_stats.get(10)

        tx_pkts_5  = flow_stats_5['tx_pkts'].get(0, 0)
        rx_pkts_5  = flow_stats_5['rx_pkts'].get(1, 0)
        drops_5    = lat_stats_5['err_cntrs']['dropped']

        tx_pkts_10  = flow_stats_10['tx_pkts'].get(0, 0)
        rx_pkts_10  = flow_stats_10['rx_pkts'].get(1, 0)
        drops_10    = lat_stats_10['err_cntrs']['dropped']

        print(" \n TX and RX flow stats and packet dopped for pg id 5 (i.e., delay critical): ")
        print("  tx packets: {0}".format(tx_pkts_5))
        print("  tx bytes : {0}".format(tx_pps_5))
        print("  rx packets : {0}".format(rx_pkts_5))
        print("  drops: {0}".format(drops_5))

        print(" \n TX and RX flow stats and packet dopped for pg id 10 (i.e., delay critical): ")
        print("  tx packets: {0}".format(tx_pkts_10))
        print("  tx bytes : {0}".format(tx_pps_10))
        print("  rx packets : {0}".format(rx_pkts_10))
        print("  drops: {0}".format(drops_10))

        # latency info for pg_id 5
        lat_5     = lat_stats_5['latency']
        avg_5     = lat_5['average']
        tot_max_5 = lat_5['total_max']
        tot_min_5 = lat_5['total_min']

        # latency info for pg_id 10
        lat_10     = lat_stats_10['latency']
        avg_10     = lat_10['average']
        tot_max_10 = lat_10['total_max']
        tot_min_10 = lat_10['total_min']

        print('\n Latency info for pg id 5 (ie., delay critical with QoS):')
        print("  Maximum latency(usec): {0}".format(tot_max_5))
        print("  Minimum latency(usec): {0}".format(tot_min_5))
        print("  Average latency(usec): {0}".format(avg_5))

        print('\n Latency info for pg id 10 (ie., delay critical without QoS):')
        print("  Maximum latency(usec): {0}".format(tot_max_10))
        print("  Minimum latency(usec): {0}".format(tot_min_10))
        print("  Average latency(usec): {0}".format(avg_10))

        # max latency difference between delay critcal flows with gp id 5 and 15
        dc_max_lat_diff = tot_max_10 - tot_max_5

        assert ((LATENCY_LP_AVG_uSEC <= dc_max_lat_diff <= LATENCY_LP_MAX_uSEC) & (tot_max_5 <= LATENCY_DC_MAX_uSEC)), \
        "Priority scheduling test failed."


        # Get statistics for TX and RX ports
        stats = self.client.get_stats()
        readable_stats_0 = get_readable_port_stats(stats[0])
        readable_stats_1 = get_readable_port_stats(stats[1])

        logging.info("Priority scheduling test successfully executed.")
        print ("\n Overall Statistics for TX port: \n")
        print (readable_stats_0)
        print ("\n Overall Statistics for RX port: \n")
        print (readable_stats_1)
