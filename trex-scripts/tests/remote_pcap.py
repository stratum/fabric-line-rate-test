# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from argparse import ArgumentParser
from datetime import datetime

from lib.base_test import StatelessTest
from lib.utils import list_port_status
from lib.xnt import analysis_report_pcap, plot_int_result


SENDER_PORTS = [0]
INT_COLLECTPR_PORTS = [3]


class RemotePcap(StatelessTest):

    # setup_subparser is an optional class method
    # You can implement this method if you want to add additional command line
    # parameters for your test.
    # Those parameters will be parsed and be passed to the "start" method below as
    # "args" argument.
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
            "--capture-limit", type=int, default=1000, help="INT report capture limit"
        )
        parser.add_argument(
            "--total-flows",
            type=int,
            default=0,
            help="Total flows(5-tuple) in the traffic trace, this number is used to"
            + "analysis the accuracy score",
        )

    # The entrypoint of a test
    def start(self, args: dict) -> None:
        logging.info(
            "Start capturing first %s RX packet from INT collector", args.capture_limit
        )

        # Start capturing packet from INT collector port
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
            # Start the traffic on ports with given duration, speedup, and pcap file.
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

        output = "/tmp/remote-pcap-{}.pcap".format(
            datetime.now().strftime("%Y%m%d-%H%M%S")
        )

        self.client.stop_capture(capture["id"], output)
        logging.info("INT report pcap file stored in {}".format(output))
        logging.info("Analyzing report pcap file...")
        report_summary_file = analysis_report_pcap(output)
        logging.info(
            "INT report summary file can be found here: {}".format(report_summary_file)
        )
        total_flow_reported = 0
        total_irgs = 0
        bad_irgs = 0
        summary = ""
        with open(report_summary_file, "r") as f:
            for l in f:
                if "---- IRGs below ----" in l:
                    break
                if "Total Inner IPv4 5-tuples" in l:
                    total_flow_reported = int(l.split(":")[1])

                if "Total INT IRGs" in l:
                    total_irgs = int(l.split(":")[1])
                if "Bad IRGs" in l:
                    bad_irgs = int(l.split(":")[1])
                    continue
                summary += l

        if args.total_flows != 0:
            summary += "Accuracy score: {}\n".format(total_flow_reported * 100 / args.total_flows)
        summary += "Efficiency score: {}\n".format((total_irgs - bad_irgs) * 100 / total_irgs)
        logging.info("INT report summary:")
        logging.info(summary)
        logging.info("Ploting the CDF from {}".format(report_summary_file))
        report_plot_file = plot_int_result(report_summary_file)
        logging.info(
            "Histogram and CDF graph can be found here: {}".format(report_plot_file)
        )
