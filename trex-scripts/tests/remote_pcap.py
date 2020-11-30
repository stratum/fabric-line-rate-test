# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import logging
from argparse import ArgumentParser
from os.path import basename

from lib.base_test import StatelessTest
from lib.utils import list_port_status
from lib.xnt import analyze_int_reports
from scapy.layers.all import Ether

SENDER_PORTS = [0]
INT_COLLECTPR_PORTS = [3]


class CaidaChicago(StatelessTest):
    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--remote-pcap-file",
            type=str,
            help="The PCAP file which stores in remote server",
            required=True,
        )
        parser.add_argument(
            "--speed-multiplier", type=float, help="The speed multiplier", default=1
        )
        parser.add_argument("--duration", type=int, help="Test duration", default=5)
        parser.add_argument(
            "--print-reports",
            action="store_true",
            help="Print INT reports, default will store reports in tmp directory",
            default=False,
        )

    def start(self, args: dict) -> None:
        pkt_capture_limit = args.duration * 10
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
            "Starting traffic, duration: %ds, speedup: %f",
            args.duration,
            args.speed_multiplier,
        )
        self.client.push_remote(
            args.remote_pcap_file,
            speedup=args.speed_multiplier,
            duration=args.duration,
            ports=SENDER_PORTS,
        )

        logging.info("Waiting until all traffic stop")
        self.client.wait_on_traffic(ports=SENDER_PORTS)

        logging.info("Stop capturing packet from INT collector port")

        if args.print_reports:
            output = []
        else:
            # [Original pcap name]-int-report.pcap
            filename = basename(args.remote_pcap_file)[:-5] + "-int-report.pcap"
            output = "/tmp/" + filename
        self.client.stop_capture(capture["id"], output)

        if args.print_reports:
            num_pkts = len(output)
            logging.info("%d packet captured", num_pkts)

            int_report_pkts = [
                Ether(pkt_info["binary"]) for pkt_info in output if "binary" in pkt_info
            ]

            analyze_int_reports(int_report_pkts)
        list_port_status(self.client.get_stats())
