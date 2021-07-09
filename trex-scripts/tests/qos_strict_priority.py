# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import os
import pprint
from argparse import ArgumentParser
from datetime import datetime

from lib.base_test import StatelessTest
from lib.utils import get_readable_port_stats, list_port_status
from lib.xnt import analysis_report_pcap
from scapy.layers.all import IP, TCP, UDP, Ether
from trex_stl_lib.api import *


pp = pprint.PrettyPrinter()

SOURCE_MAC = "00:00:00:00:00:01"
DEST_MAC = "00:00:00:00:00:02"

QUEUE_ID_BEST_EFFORT = 0
QUEUE_ID_SYSTEM = 1
QUEUE_ID_CONTROL = 2

CONTROL_QUEUE_MAX_RATE_BPS = 60000000
SYSTEM_QUEUE_MAX_RATE_BPS = 10000000

L4_DPORT_BEST_EFFORT = 1000
L4_DPORT_SYSTEM = 1001
L4_DPORT_CONTROL = 1002

K = 1000
M = K * 1000
G = M * 1000

BACKGROUND_SENDER_PORT = [0]
PRIORITY_SENDER_PORT = [2]
ALL_SENDER_PORTS = [0, 2]
RECEIVER_PORT = [1]
ALL_PORTS = [0, 1, 2]

class PortShapingSTL(StatelessTest):
    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        parser.add_argument("--duration", type=float, help="Test duration", default=10)

    def push_chassis_config(self) -> None:
        # TODO
        pass

    def setup_flow_state(self) -> None:
        flows = """
# Clear previous entries.
table_entry['FabricIngress.acl.acl'].read(lambda e: e.delete())
table_entry['FabricEgress.egress_next.egress_vlan'].read(lambda e: e.delete())
table_entry['FabricIngress.slice_tc_classifier.classifier'].read(lambda e: e.delete())
table_entry['FabricIngress.qos.queues'].read(lambda e: e.delete())

# Remove default vlan tag for untagged egress.
te = table_entry['FabricEgress.egress_next.egress_vlan'](action='FabricEgress.egress_next.pop_vlan')
te.match['vlan_id'] = '0xFFE'
te.match['eg_port'] = '296'
te.insert()
te.match['eg_port'] = '288'
te.insert()
te.match['eg_port'] = '272'
te.insert()

# Classify UDP dport={L4_DPORT_CONTROL} traffic and assign to control queue.
te = table_entry["FabricIngress.slice_tc_classifier.classifier"](action="set_slice_id_tc")
te.match["l4_dport"] = "{L4_DPORT_CONTROL}"
te.priority = 10
te.action["slice_id"] = "1"
te.action["tc"] = "0"
te.counter_data
te.insert()
te = table_entry["FabricIngress.qos.queues"](action="set_queue")
te.match["slice_id"] = "1"
te.match["tc"] = "0"
te.priority = 10
te.action["qid"] = "{QUEUE_ID_CONTROL}"
te.counter_data
te.insert()

# Classify UDP dport={L4_DPORT_SYSTEM} traffic and assign to system queue.
te = table_entry["FabricIngress.slice_tc_classifier.classifier"](action="set_slice_id_tc")
te.match["l4_dport"] = "{L4_DPORT_SYSTEM}"
te.priority = 10
te.action["slice_id"] = "2"
te.action["tc"] = "0"
te.counter_data
te.insert()
te = table_entry["FabricIngress.qos.queues"](action="set_queue")
te.match["slice_id"] = "2"
te.match["tc"] = "0"
te.priority = 10
te.action["qid"] = "{QUEUE_ID_SYSTEM}"
te.counter_data
te.insert()

# Funnel traffic from two ports into port 288.
te = table_entry['FabricIngress.acl.acl'](action='FabricIngress.acl.set_output_port')
te.priority = 10
te.counter_data
# 27 -> 28
te.match['ig_port'] = '296'
te.action['port_num'] = '288'
te.insert()
# 29 -> 28
te.match['ig_port'] = '272'
te.action['port_num'] = '288'
te.insert()
""".format_map({
    'QUEUE_ID_BEST_EFFORT': QUEUE_ID_BEST_EFFORT,
    'QUEUE_ID_SYSTEM': QUEUE_ID_SYSTEM,
    'QUEUE_ID_CONTROL': QUEUE_ID_CONTROL,
    'L4_DPORT_BEST_EFFORT': L4_DPORT_BEST_EFFORT,
    'L4_DPORT_SYSTEM': L4_DPORT_SYSTEM,
    'L4_DPORT_CONTROL': L4_DPORT_CONTROL,
})
        print("Paste the following into a P4RT-shell:")
        print(flows)
        input("Press Enter to continue...")

    # Create a background traffic stream.
    def create_background_stream(self) -> STLStream:
        pkt = Ether(dst=DEST_MAC) / IP() / TCP(dport=443) / ("*" * 1400)
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(percentage=100))

    # Create a highest priority control stream.
    def create_control_stream(self, pg_id) -> STLStream:
        pkt = Ether(dst=DEST_MAC) / IP() / UDP(dport=L4_DPORT_CONTROL) / ("*" * 128)
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(bps_L1=CONTROL_QUEUE_MAX_RATE_BPS),
            isg=50000, # wait 50 ms till start to let queues fill up
            flow_stats = STLFlowLatencyStats(pg_id = pg_id))

    # Create a second highest priority system stream.
    def create_system_stream(self, pg_id) -> STLStream:
        pkt = Ether(dst=DEST_MAC) / IP() / UDP(dport=L4_DPORT_SYSTEM) / ("*" * 128)
        return STLStream(
            packet=STLPktBuilder(pkt=pkt),
            mode=STLTXCont(bps_L1=SYSTEM_QUEUE_MAX_RATE_BPS),
            isg=50000, # wait 50 ms till start to let queues fill up
            flow_stats = STLFlowLatencyStats(pg_id = pg_id))

    def start(self, args: dict) -> None:
        pg_id = 7
        self.push_chassis_config()
        self.setup_flow_state()
        # Create a background traffic stream
        background_stream = self.create_background_stream()
        self.client.add_streams(background_stream, ports=BACKGROUND_SENDER_PORT)
        # Create the control stream
        control_stream = self.create_control_stream(pg_id)
        self.client.add_streams(control_stream, ports=PRIORITY_SENDER_PORT)
        # Create the system stream
        system_pg_id = 2
        system_stream = self.create_system_stream(system_pg_id)
        self.client.add_streams(system_stream, ports=PRIORITY_SENDER_PORT)

        # Start sending traffic
        logging.info(
            "Starting traffic, duration: %d sec", args.duration,
        )
        self.client.start(ALL_SENDER_PORTS, mult='1', duration=args.duration)

        logging.info("Waiting until all traffic is sent")
        self.client.wait_on_traffic(ports=ALL_SENDER_PORTS, rx_delay_ms=100)

        # Get latency stats
        stats = self.client.get_stats()
        lat_stats = stats['latency'].get(pg_id)
        flow_stats = stats["flow_stats"].get(pg_id)
        pp.pprint(stats)

        print("Flow stats for pg_id {0}: {1}".format(pg_id, flow_stats))
        print("Latency stats for pg_id {0}: {1}".format(pg_id, lat_stats))
        lat = lat_stats['latency']
        jitter = lat['jitter']
        avg = lat['average']
        tot_max = lat['total_max']
        tot_min = lat['total_min']
        last_max = lat['last_max']
        hist = lat['histogram']
        total_rx = flow_stats['rx_pkts']['total']
        total_tx = flow_stats['tx_pkts']['total']
        drops = lat_stats['err_cntrs']['dropped']
        ooo = lat_stats['err_cntrs']['out_of_order']
        dup = lat_stats['err_cntrs']['dup']
        sth = lat_stats['err_cntrs']['seq_too_high']
        stl = lat_stats['err_cntrs']['seq_too_low']
        print("Latency info for pg_id {0}:".format(pg_id))
        print("  Dropped packets: {0}".format(drops))
        print("  Maximum latency: {0} us".format(tot_max))
        print("  Minimum latency: {0} us".format(tot_min))
        print("  Maximum latency in last sampling period: {0} us".format(last_max))
        print("  Average latency: {0} us".format(avg))
        print("  Jitter: {0} us".format(jitter))
        print("  Latency distribution histogram:")
        l = list(hist.keys()) # need to listify in order to be able to sort them.
        l.sort()
        for sample in l:
            range_start = sample
            if range_start == 0:
                range_end = 10
            else:
                range_end  = range_start + pow(10, (len(str(range_start))-1))
            val = hist[sample]
            print ("    Packets with latency between {0} us and {1} us: {2}".format(range_start, range_end, val))

        # Get statistics for TX and RX ports
        for port in ALL_PORTS:
            readable_stats = get_readable_port_stats(stats[port])
            print("Statistics for port {}: {}".format(port, readable_stats))

        # Check SLAs.
        assert(total_rx > 0), "No control traffic has been received"
        assert(drops == 0), "Control traffic has been dropped: {}".format(drops)
        assert(sth == 0 and stl == 0), "Control traffic has been dropped or reordered: {}, {}".format(sth, stl)
        assert(tot_max <= 1000), "Maximum latency in control traffic is too high: {}".format(tot_max)
        assert(avg <= 500), "Average latency in control traffic is too high: {}".format(avg)
