# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from argparse import ArgumentParser
from datetime import datetime

from lib.base_test import StatelessTest
from lib.utils import list_port_status
from lib.xnt import analyze_int_reports
from scapy.layers.all import Ether

SENDER_PORTS = [0]
INT_COLLECTPR_PORTS = [3]


class RemotePcap(StatelessTest):
    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--remote-pcap-file-dir",
            type=str,
            help="The directory which stores pcap files on the remove server.",
            default="/",
        )
        parser.add_argument(
            "--remote-pcap-files",
            type=str,
            help="The PCAP files which stores in remote server",
            required=True,
            nargs="+",
        )
        parser.add_argument(
            "--speed-multiplier", type=float, help="The speed multiplier", default=1
        )
        parser.add_argument("--duration", type=float, help="Test duration", default=-1)
        parser.add_argument(
            "--print-reports",
            action="store_true",
            help="Print INT reports, default will store reports in the tmp directory",
            default=False,
        )
        parser.add_argument(
            "--capture-limit", type=int, default=1000, help="INT report capture limit"
        )

    def start(self, args: dict) -> None:
        logging.info(
            "Start capturing first %s RX packet from INT collector", args.capture_limit
        )
        self.client.set_service_mode(ports=INT_COLLECTPR_PORTS, enabled=True)
        capture = self.client.start_capture(
            rx_ports=INT_COLLECTPR_PORTS,
            limit=args.capture_limit,
            bpf_filter="udp and dst port 32766",
        )

        logging.info(
            "Starting traffic, speedup: %f", args.speed_multiplier,
        )
        duration = args.duration
        if args.duration > 0:
            duration = args.duration / len(args.remote_pcap_files)
        for remote_pcap_file in args.remote_pcap_files:
            self.client.push_remote(
                args.remote_pcap_file_dir + os.path.sep + remote_pcap_file,
                speedup=args.speed_multiplier,
                duration=duration,
                ports=SENDER_PORTS,
            )

            logging.info("Sending packets from file {}....".format(remote_pcap_file))
            self.client.wait_on_traffic(ports=SENDER_PORTS)

        logging.info("Stop capturing packet from INT collector port")
        list_port_status(self.client.get_stats())

        if args.print_reports:
            output = []
        else:
            output = "/tmp/remote-pcap-{}.pcap".format(
                datetime.now().strftime("%Y%m%d-%H%M%S")
            )
            logging.info("INT report pcap file stored in {}".format(output))
        self.client.stop_capture(capture["id"], output)

        if args.print_reports:
            num_pkts = len(output)
            logging.info("%d packet captured", num_pkts)

            int_report_pkts = [
                Ether(pkt_info["binary"]) for pkt_info in output if "binary" in pkt_info
            ]
            analyze_int_reports(int_report_pkts)
