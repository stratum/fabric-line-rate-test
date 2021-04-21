# SPDX-FileCopyrightText: Copyright 2021-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import logging
from argparse import ArgumentParser
from datetime import datetime

from lib.base_test import StatelessTest
from lib.gtpu import GTPU
from lib.utils import list_port_status
from lib.xnt import analysis_report_pcap
from scapy.layers.all import IP, TCP, UDP, Ether
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont

SOURCE_MAC = "00:00:00:00:00:01"
DEST_MAC = "00:90:fb:71:64:8a"
SOURCE_IP = "192.168.10.1"
DEST_IP = "8.8.8.8"
SENDER_PORTS = [0, 1]
INT_COLLECTPR_PORTS = [3]


class Congestion(StatelessTest):
    """
    Sends two high speed traffic(e.g., 40G) into a low speed traffic port(e.g., 10G)
    """

    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        parser.add_argument("--duration", type=int, help="Test duration", default=5)

    def start(self, args) -> None:
        pkt = (
            Ether(src=SOURCE_MAC, dst=DEST_MAC)
            / IP(src=SOURCE_IP, dst=DEST_IP)
            / UDP()
            / ("*" * 1500)
        )

        stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=[]), mode=STLTXCont())

        logging.info("Setting up ports")
        self.client.add_streams(stream, ports=SENDER_PORTS)

        pkt_capture_limit = args.duration * 3
        logging.info(
            "Start capturing first %s RX packet from INT collector", pkt_capture_limit
        )
        self.client.set_service_mode(ports=INT_COLLECTPR_PORTS, enabled=True)
        capture = self.client.start_capture(
            rx_ports=INT_COLLECTPR_PORTS,
            limit=pkt_capture_limit,
            bpf_filter="udp and dst port 32766",
        )

        logging.info(
            "Starting traffic, duration: %ds, throughput: 100%%", args.duration
        )
        self.client.start(ports=SENDER_PORTS, mult="100%", duration=args.duration)
        logging.info("Waiting until all traffic stop")
        self.client.wait_on_traffic(ports=SENDER_PORTS)

        logging.info("Stop capturing packet from INT collector port")
        output = "/tmp/congestion-report-{}.pcap".format(
            datetime.now().strftime("%Y%m%d-%H%M%S")
        )
        self.client.stop_capture(capture["id"], output)
        analysis_report_pcap(output)
        list_port_status(self.client.get_stats())
