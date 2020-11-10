# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

from trex_stl_lib.api import *
from scapy.layers.all import *
from lib.base_test import BaseTest


class SimpleTcpTest(BaseTest):
    # A simple test that sends TCP traffic from port 0 and 2

    def start(self) -> None:
        pkt = Ether()/IP()/TCP(sport=1234, dport=80)/('*' * 64)
        stream = STLStream(packet=STLPktBuilder(
            pkt=pkt, vm=[]), mode=STLTXCont())
        self.stl_client.add_streams(stream, ports=[0, 2])
        self.stl_client.start(
            ports=[0, 2], mult='1gbps', duration=self.duration)
        self.stl_client.wait_on_traffic(ports=[0, 2])


def get_test(stl_client: STLClient, duration: int = 1) -> SimpleTcpTest:
    return SimpleTcpTest(stl_client, duration)
