# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

from trex_stl_lib.api import *
from scapy.layers.all import *
from lib.base_test import BaseTest
from lib.utils import get_readable_port_stats
import logging


class SimpleTcpTest(BaseTest):
    # A simple test that sends TCP traffic from port 0 and 1
    def start(self) -> None:
        ports = [0, 1]
        pkt_info = Ether()/IP()/TCP(sport=1234, dport=80)/('*' * 64)
        stream = STLStream(packet=STLPktBuilder(
            pkt=pkt_info, vm=[]), mode=STLTXCont())

        # Bring ports to service mode to set attributes like L2/L3 mode.
        # Need to disable the service mode before we start the traffic.
        logging.info('Setting up ports')
        self.stl_client.set_service_mode(ports=ports, enabled=True)
        self.stl_client.set_l2_mode(port=0, dst_mac='00:00:00:00:00:02')
        self.stl_client.set_l2_mode(port=1, dst_mac='00:00:00:00:00:01')
        self.stl_client.add_streams(stream, ports=ports)
        self.stl_client.set_service_mode(ports=ports, enabled=False)

        logging.info('Start capturing TX packet from port 0')
        capture = self.stl_client.start_capture(
            tx_ports=[0], limit=10, bpf_filter='tcp')

        logging.info('Starting traffic')
        self.stl_client.start(
            ports=ports, mult='100pps', duration=self.duration)

        # Set the port to service mode to capture packets
        self.stl_client.set_service_mode(ports=ports, enabled=True)
        self.stl_client.wait_on_traffic(ports=ports)

        logging.info('Stop capturing TX of port 0')
        output = []
        self.stl_client.stop_capture(capture['id'], output)

        logging.info('Packet captured: %d', len(output))

        # Each element in the 'output' list is an dictionary which contains:
        # 'binary' - binary bytes of the packet
        # 'origin' - RX or TX origin
        # 'ts'     - timestamp relative to the start of the capture
        # 'index'  - order index in the capture
        # 'port'   - port did the packet arrive or was transmitted from

        for pkt_info in output:
            logging.info('%s -> orig: %s, ts: %s, port: %s',
                         pkt_info['index'], pkt_info['origin'],
                         pkt_info['ts'], pkt_info['port'])
            pkt = Ether(pkt_info['binary'])
            logging.info('\n%s', pkt.show(dump=True))

        port_stats = self.stl_client.get_stats()
        for port in ports:
            readable_stats = get_readable_port_stats(port_stats[port])
            logging.info('States from port {}: \n{}'.format(
                port, readable_stats))


def get_test(stl_client: STLClient, duration: int = 1) -> SimpleTcpTest:
    return SimpleTcpTest(stl_client, duration)
