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
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont, STLTXSingleBurst, STLFlowLatencyStats, STLFlowStats


SOURCE_MAC = "00:00:00:00:00:01"
DEST_MAC   = "00:00:00:00:00:02"

SENDER_PORT   = [0]
RECEIVER_PORT = [1]

class Metering(StatelessTest):

    # setup_subparser is an optional class method
    # You can implement this method if you want to add additional command line
    # parameters for your test.
    # Those parameters will be parsed and be passed to the "start" method below as
    # "args" argument.
    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        parser.add_argument("--duration", type=float, help="Test duration", default=2)


    # The entrypoint of a test
    def start(self, args: dict) -> None:

        # create packets
        pkt1 = Ether(dst=DEST_MAC) / IP(src="16.0.0.1",dst="48.0.0.1") / UDP(dport=12,sport=1025)
        pkt2 = Ether(dst=DEST_MAC) / IP(src="16.0.0.2",dst="48.0.0.2") / UDP(dport=12,sport=1025)

        pad1 = max(0, 1500 - len(pkt1)) * 'x'
        pad2 = max(0, 1500 - len(pkt2)) * 'x'

        # two different burst sizes
        burst_size_b1 = 83333  # 1 Gb
        burst_size_b2 = 416666 # 5 Gb


        # In this test case, we consider two delay critical streams: 1) s1 with metering, and 2) s2 without metering
        # This test verifies both peak information rate (pir) and peak burst size (pbs)
        # For this test case, meter parameters for stream s1 are set as follows:
        # pir (in kbps)  = 2000000  (i.e., 2Gbps)
        # pbs (in kbits) = 1000000  (i.e., 1Gb)
        # cir (in kbps)  = 100
        # cbs (in kbits) = 1000

        # stream s1 is a delay critical, contains two bursts s1_b1 and s1_b2 with burst size 'burst_size_b1' and 'burst_size_b2'
        # rate (in pps) for each burst is set as same as burst size
        s1_b1 = STLStream( name = 's1_b1', packet=STLPktBuilder(pkt=pkt1 / pad1), \
              mode=STLTXSingleBurst(pps=burst_size_b1, total_pkts = burst_size_b1), \
              next ='s1_b2',flow_stats = STLFlowStats(pg_id = 1))
        s1_b2 = STLStream( name = 's1_b2', self_start = False,  packet=STLPktBuilder(pkt=pkt1 / pad1), \
              mode=STLTXSingleBurst(pps=burst_size_b2, total_pkts = burst_size_b2),\
              flow_stats = STLFlowStats(pg_id = 2))

        # stream s2 is a delay critcial, contains two bursts s2_b1 and s2_b2 with burt size burst_size_b1 and burst_size_b2
        # rate (in pps) for each burst is set as same as burst size
        s2_b1 = STLStream( name = 's2_b1', packet=STLPktBuilder(pkt=pkt2 / pad2), \
              mode=STLTXSingleBurst(pps = burst_size_b1, total_pkts = burst_size_b1), \
              next ='s2_b2', flow_stats = STLFlowStats(pg_id = 3))
        s2_b2 = STLStream( name = 's2_b2', self_start = False,  packet=STLPktBuilder(pkt=pkt2 / pad2), \
              mode=STLTXSingleBurst(pps = burst_size_b2, total_pkts = burst_size_b2), \
              flow_stats = STLFlowStats(pg_id = 4))

        # prepare ports
        self.client.reset(ports=[0,1])

        # add sterams
        self.client.add_streams(streams=[s1_b1, s1_b2], ports=[0])
        self.client.add_streams(streams=[s2_b1, s2_b2], ports=[0])


        logging.info(
                "Starting traffic, duration: %d sec", args.duration,
        )

        # Start sending traffic
        self.client.start(SENDER_PORT, duration=args.duration)
        pgids = self.client.get_active_pgids()


        logging.info("Waiting until all traffic stop")
        self.client.wait_on_traffic(ports=SENDER_PORT)

        # stats for s1 and s2
        stats                 = self.client.get_pgid_stats()['flow_stats']
        flow_stats_s1_b1      = stats.get(1)
        flow_stats_s1_b2      = stats.get(2)
        flow_stats_s2_b1      = stats.get(3)
        flow_stats_s2_b2      = stats.get(4)

        tx_pkts_s1_b1         = flow_stats_s1_b1['tx_pkts'].get(0, 0)
        rx_pkts_s1_b1         = flow_stats_s1_b1['rx_pkts'].get(1, 0)
        pkt_drop_s1_b1        = tx_pkts_s1_b1 - rx_pkts_s1_b1
        tx_gbps_s1_b1         = (tx_pkts_s1_b1 * 1500 * 8)/10**9
        rx_gbps_s1_b1         = (rx_pkts_s1_b1 * 1500 * 8)/10**9

        tx_pkts_s1_b2         = flow_stats_s1_b2['tx_pkts'].get(0, 0)
        rx_pkts_s1_b2         = flow_stats_s1_b2['rx_pkts'].get(1, 0)
        pkt_drop_s1_b2        = tx_pkts_s1_b2 - rx_pkts_s1_b2
        tx_gbps_s1_b2         = (tx_pkts_s1_b2 * 1500 * 8)/10**9
        rx_gbps_s1_b2         = (rx_pkts_s1_b2 * 1500 * 8)/10**9

        tx_pkts_s2_b1         = flow_stats_s2_b1['tx_pkts'].get(0, 0)
        rx_pkts_s2_b1         = flow_stats_s2_b1['rx_pkts'].get(1, 0)
        pkt_drop_s2_b1        = tx_pkts_s2_b1 - rx_pkts_s2_b1
        tx_gbps_s2_b1         = (tx_pkts_s2_b1 * 1500 * 8)/10**9
        rx_gbps_s2_b1         = (rx_pkts_s2_b1 * 1500 * 8)/10**9

        tx_pkts_s2_b2         = flow_stats_s2_b2['tx_pkts'].get(0, 0)
        rx_pkts_s2_b2         = flow_stats_s2_b2['rx_pkts'].get(1, 0)
        pkt_drop_s2_b2        = tx_pkts_s2_b2 - rx_pkts_s2_b2
        tx_gbps_s2_b2         = (tx_pkts_s2_b2 * 1500 * 8)/10**9
        rx_gbps_s2_b2         = (rx_pkts_s2_b2 * 1500 * 8)/10**9

        print(" \n TX and RX flow stats and packet dopped for s1 with metering (i.e., delay critical): ")
        print(" \n for s1 burst 1 : ")
        print("  tx packets   : {0}".format(tx_pkts_s1_b1))
        print("  rx packets   : {0}".format(rx_pkts_s1_b1))
        print("  dropped pkts : {0}".format(pkt_drop_s1_b1))
        print("  tx gbps      : {0}".format(tx_gbps_s1_b1))
        print("  rx gbps      : {0}".format(rx_gbps_s1_b1))

        print(" \n for s1 burst 2 : ")
        print("  tx packets   : {0}".format(tx_pkts_s1_b2))
        print("  rx packets   : {0}".format(rx_pkts_s1_b2))
        print("  dropped pkts : {0}".format(pkt_drop_s1_b2))
        print("  tx gbps      : {0}".format(tx_gbps_s1_b2))
        print("  rx gbps      : {0}".format(rx_gbps_s1_b2))

        print(" \n TX and RX flow stats and packet dopped for s2 without metering (i.e., delay critical): ")
        print(" \n for s2 burst 1 : ")
        print("  tx packets   : {0}".format(tx_pkts_s2_b1))
        print("  rx packets   : {0}".format(rx_pkts_s2_b1))
        print("  dropped pkts : {0}".format(pkt_drop_s2_b1))
        print("  tx gbps      : {0}".format(tx_gbps_s2_b1))
        print("  rx gbps      : {0}".format(rx_gbps_s2_b1))

        print(" \n for s2 burst 2 : ")
        print("  tx packets   : {0}".format(tx_pkts_s2_b2))
        print("  rx packets   : {0}".format(rx_pkts_s2_b2))
        print("  dropped pkts : {0}".format(pkt_drop_s2_b2))
        print("  tx gbps      : {0}".format(tx_gbps_s2_b2))
        print("  rx gbps      : {0}".format(rx_gbps_s2_b2))


        total_pkt_drops_s2 = pkt_drop_s2_b1 + pkt_drop_s2_b2

        # since pir is set to 2 Gbps and pbs is 1 Gb, the total allowable bytes will be around 3Gb for each burst of s1
        # Note: initally tocken bucket is filled with 1 Gb. If the first burst of s1 contians 3Gb, then for the second burst,
        # the allowable bytes will be only 1 Gb in case of tx burst rate > pir
        # Since s2 is without metering, there should be 0 packets drop
        assert (total_pkt_drops_s2 == 0 and pkt_drop_s1_b1 == 0 and 3*0.99 < rx_gbps_s1_b2 <= 3.0), \
        "meter test failed."
