# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import logging
from argparse import ArgumentParser
from datetime import datetime

from lib.base_test import StatelessTest
from lib.fabric_tna import *
from lib.gtpu import GTPU
from lib.p4r_client import P4RuntimeClient
from lib.utils import list_port_status
from lib.xnt import analysis_report_pcap
from scapy.layers.all import IP, TCP, UDP, Ether
from trex_stl_lib.api import STLPktBuilder, STLStream, STLTXCont

SOURCE_MAC = "00:00:00:00:00:01"
DEST_MAC = "00:00:00:00:00:03"
COL_MAC = "00:00:00:00:00:04"
COL_IP = "192.168.40.1"
SWITCH_MAC = "c0:ff:ee:c0:ff:ee"
SOURCE_IP = "192.168.10.1"
DEST_IP = "192.168.30.1"
SWITCH_IP = "192.168.40.254"
INNER_SRC_IP = "10.240.0.1"
INNER_DEST_IP = "8.8.8.8"
IP_PREFIX = 32
SENDER_PORTS = [0]
INT_COLLECTPR_PORTS = [3]
SWITCH_PORTS = [272, 280, 256, 264]  # 29, 30, 31, 32
DEFAULT_VLAN = 10
SWITCH_ID = 1
INT_REPORT_MIRROR_IDS = [300, 301, 302, 303]
RECIRC_PORTS = [68, 196, 324, 452]


class IntSingleFlow(StatelessTest):
    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        parser.add_argument("--duration", type=int, help="Test duration", default=5)
        parser.add_argument(
            "--mult", type=str, help="Traffic multiplier", default="1pps"
        )
        parser.add_argument("--pkt-type", type=str, help="Packet type", default="tcp")
        parser.add_argument(
            "--set-up-flows",
            type=bool,
            help="Set up flows on the switch",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "--switch-addr",
            type=str,
            help="P4Runtime server address",
            default="localhost:9339",
        )
        parser.add_argument("--p4info", type=str, help="P4Info file", default="")
        parser.add_argument(
            "--pipeline-config", type=str, help="Pipeline config file", default=""
        )

    def get_sample_packet(self, pkt_type):
        if pkt_type == "tcp":
            return (
                Ether(src=SOURCE_MAC, dst=SWITCH_MAC)
                / IP(src=SOURCE_IP, dst=DEST_IP)
                / TCP()
                / ("*" * 1500)
            )
        elif pkt_type == "gtpu-udp":
            return (
                Ether(src=SOURCE_MAC, dst=SWITCH_MAC)
                / IP(src=SOURCE_IP, dst=DEST_IP)
                / UDP()
                / GTPU()
                / IP()
                / UDP()
                / ("*" * 1500)
            )
        else:
            # UDP
            return (
                Ether(src=SOURCE_MAC, dst=SWITCH_MAC)
                / IP(src=SOURCE_IP, dst=DEST_IP)
                / UDP()
                / ("*" * 1500)
            )

    def set_up_flows(self) -> None:
        # Filtering rules
        for i in range(0, 4):
            set_up_port(self.p4r_client, SWITCH_PORTS[i], DEFAULT_VLAN)
            set_forwarding_type(
                self.p4r_client,
                SWITCH_PORTS[i],
                SWITCH_MAC,
                ethertype=ETH_TYPE_IPV4,
                fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
            )
        # Forwarding rules
        add_forwarding_routing_v4_entry(self.p4r_client, DEST_IP, IP_PREFIX, 100)
        add_forwarding_routing_v4_entry(self.p4r_client, COL_IP, IP_PREFIX, 101)

        # Next rules
        # Send to the dest host
        add_next_routing(self.p4r_client, 100, SWITCH_PORTS[1], SWITCH_MAC, DEST_MAC)
        # Send to the collector
        add_next_routing(self.p4r_client, 101, SWITCH_PORTS[3], SWITCH_MAC, COL_MAC)
        add_next_vlan(self.p4r_client, 100, DEFAULT_VLAN)
        add_next_vlan(self.p4r_client, 101, DEFAULT_VLAN)
        # INT rules
        set_up_watchlist_flow(self.p4r_client, SOURCE_IP, DEST_IP)
        set_up_int_mirror_flow(self.p4r_client, SWITCH_ID)
        set_up_report_flow(
            self.p4r_client, SWITCH_MAC, COL_MAC, SWITCH_IP, COL_IP, SWITCH_PORTS[3]
        )

        for i in range(0, 4):
            set_up_report_mirror_flow(
                self.p4r_client, INT_REPORT_MIRROR_IDS[i], RECIRC_PORTS[i]
            )

    def start(self, args) -> None:
        if args.set_up_flows:
            self.p4r_client = P4RuntimeClient(
                grpc_addr=args.switch_addr,
                p4info_path=args.p4info,
                pipeline_config=args.pipeline_config,
            )
            self.set_up_flows()
        pkt = self.get_sample_packet(args.pkt_type)
        if not pkt:
            return 1

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
            "Starting traffic, duration: %ds, throughput: %s", args.duration, args.mult
        )
        self.client.start(ports=SENDER_PORTS, mult=args.mult, duration=args.duration)
        logging.info("Waiting until all traffic stop")
        self.client.wait_on_traffic(ports=SENDER_PORTS)

        logging.info("Stop capturing packet from INT collector port")
        output = "/tmp/int-single-flow-{}-{}.pcap".format(
            args.pkt_type, datetime.now().strftime("%Y%m%d-%H%M%S")
        )
        self.client.stop_capture(capture["id"], output)
        analysis_report_pcap(output)
        list_port_status(self.client.get_stats())
