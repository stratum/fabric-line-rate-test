# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import logging

from lib.base_test import StatelessTest
from lib.utils import list_port_status
from lib.xnt import analyze_int_reports
from scapy.layers.all import IP, UDP, Ether
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont

SOURCE_MAC = "00:00:00:00:00:01"
DEST_MAC = "00:00:00:00:00:03"
SOURCE_IP = "192.168.10.1"
DEST_IP = "192.168.10.3"
SENDER_PORTS = [0]
INT_COLLECTPR_PORTS = [3]


class IntSingleFlow(StatelessTest):
    # A simple test that sends UDP traffic from 192.168.10.1 to 192.168.10.3

    def start(self) -> None:
        pkt = (
            Ether(src=SOURCE_MAC, dst=DEST_MAC)
            / IP(src=SOURCE_IP, dst=DEST_IP)
            / UDP(sport=1234, dport=4567)
            / ("*" * 1500)
        )
        stream = STLStream(packet=STLPktBuilder(pkt=pkt, vm=[]), mode=STLTXCont())

        logging.info("Setting up ports")
        self.client.add_streams(stream, ports=SENDER_PORTS)

        pkt_capture_limit = self.duration * 3
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
            "Starting traffic, duration: %ds, throughput: %s", self.duration, self.mult
        )
        self.client.start(ports=SENDER_PORTS, mult=self.mult, duration=self.duration)
        logging.info("Waiting until all traffic stop")
        self.client.wait_on_traffic(ports=SENDER_PORTS)

        logging.info("Stop capturing packet from INT collector port")
        output = []
        self.client.stop_capture(capture["id"], output)

        num_pkts = len(output)
        logging.info("%d packet captured", num_pkts)

        int_report_pkts = [
            Ether(pkt_info["binary"]) for pkt_info in output if "binary" in pkt_info
        ]

        analyze_int_reports(int_report_pkts, self.duration)
        list_port_status(self.client.get_stats())
