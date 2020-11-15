# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import logging

from lib.base_test import BaseTest
from lib.utils import get_readable_port_stats
from lib.xnt import IntL45ReportFixed, get_readable_int_report_str
from scapy.layers.all import IP, UDP, Ether
from trex_stl_lib.api import STLClient, STLPktBuilder, STLStream, STLTXCont

SOURCE_MAC = "00:00:00:00:00:01"
DEST_MAC = "00:00:00:00:00:03"
SOURCE_IP = "192.168.10.1"
DEST_IP = "192.168.10.3"
SENDER_PORTS = [0]
INT_COLLECTPR_PORTS = [3]


class IntSingleFlow(BaseTest):
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
        self.stl_client.add_streams(stream, ports=SENDER_PORTS)

        pkt_capture_limit = self.duration * 3
        logging.info(
            "Start capturing first %s RX packet from INT collector", pkt_capture_limit
        )
        self.stl_client.set_service_mode(ports=INT_COLLECTPR_PORTS, enabled=True)
        capture = self.stl_client.start_capture(
            rx_ports=INT_COLLECTPR_PORTS,
            limit=pkt_capture_limit,
            bpf_filter="udp and dst port 32766",
        )

        logging.info(
            "Starting traffic, duration: %ds, throughput: %s", self.duration, self.mult
        )
        self.stl_client.start(
            ports=SENDER_PORTS, mult=self.mult, duration=self.duration
        )
        logging.info("Waiting until all traffic stop")
        self.stl_client.wait_on_traffic(ports=SENDER_PORTS)

        logging.info("Stop capturing packet from INT collector port")
        output = []
        self.stl_client.stop_capture(capture["id"], output)

        num_pkts = len(output)
        logging.info("%d packet captured", num_pkts)

        # We should receive 1 packet per second, and allows +/- 1 packet.
        if num_pkts not in range(self.duration - 1, self.duration + 2):
            logging.error(
                "Expected to receive %d +/- 1 pakcets, but got %d",
                self.duration,
                num_pkts,
            )

        prev_seq_no = None
        for pkt_info in output:
            pkt = Ether(pkt_info["binary"])
            logging.info("%s", get_readable_int_report_str(pkt))

            if IntL45ReportFixed in pkt:
                seq_no = pkt[IntL45ReportFixed].seq_no
                if prev_seq_no and seq_no != (prev_seq_no + 1):
                    logging.error(
                        "Expect to get seq no %d, but got %d", prev_seq_no + 1, seq_no
                    )
                prev_seq_no = seq_no

        port_stats = self.stl_client.get_stats()
        for port in [0, 1, 2, 3]:
            readable_stats = get_readable_port_stats(port_stats[port])
            logging.info("States from port {}: \n{}".format(port, readable_stats))


def get_test(
    stl_client: STLClient, duration: int = 1, mult: str = "10gbpsl1"
) -> IntSingleFlow:
    return IntSingleFlow(stl_client, duration, mult)
