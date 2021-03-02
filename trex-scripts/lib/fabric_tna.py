# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

# Utilities to generate table entries and groups for fabric-tna pipeline

from argparse import ArgumentParser

from lib.p4r import P4RuntimeTest
from lib.utils import ipv4_to_binary, mac_to_binary, stringify

DEFAULT_PRIORITY = 10
MAC_MASK = ":".join(["ff"] * 6)
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_MPLS_UNICAST = 0x8847
FORWARDING_TYPE_UNICAST_IPV4 = 2
MIRROR_TYPE_INT_REPORT = 1
BRIDGED_MD_TYPE_EGRESS_MIRROR = 2
INT_REPORT_TYPE_LOCAL = 1


class FabricTnaTest(P4RuntimeTest):
    @classmethod
    def setup_subparser(cls, parser: ArgumentParser) -> None:
        P4RuntimeTest.setup_subparser(parser)

    def connect(
        self,
        grpc_addr="localhost:9339",
        device_id=1,
        p4info=None,
        election_id=1,
        pipeline_config=None,
    ):
        super().connect(
            grpc_addr=grpc_addr,
            device_id=device_id,
            p4info=p4info,
            election_id=election_id,
            pipeline_config=pipeline_config,
        )
        self.next_mbr_id = 1

    def set_ingress_port_vlan(
        self,
        ingress_port,
        vlan_valid=False,
        vlan_id=0,
        internal_vlan_id=0,
        inner_vlan_id=None,
        priority=DEFAULT_PRIORITY,
    ):
        ingress_port_ = stringify(ingress_port, 2)
        vlan_valid_ = b"\x01" if vlan_valid else b"\x00"
        vlan_id_ = stringify(vlan_id, 2)
        vlan_id_mask_ = stringify(4095 if vlan_valid else 0, 2)
        new_vlan_id_ = stringify(internal_vlan_id, 2)
        action_name = "permit" if vlan_valid else "permit_with_internal_vlan"
        action_params = [] if vlan_valid else [("vlan_id", new_vlan_id_)]
        matches = [
            self.Exact("ig_port", ingress_port_),
            self.Exact("vlan_is_valid", vlan_valid_),
        ]
        if vlan_id_mask_ != b"\x00\x00":
            matches.append(self.Ternary("vlan_id", vlan_id_, vlan_id_mask_))
        if inner_vlan_id is not None:
            # Match on inner_vlan, only when explicitly requested
            inner_vlan_id_ = stringify(inner_vlan_id, 2)
            inner_vlan_id_mask_ = stringify(4095, 2)
            matches.append(
                self.Ternary("inner_vlan_id", inner_vlan_id_, inner_vlan_id_mask_)
            )

        return self.send_request_add_entry_to_action(
            "filtering.ingress_port_vlan",
            matches,
            "filtering." + action_name,
            action_params,
            priority,
        )

    def set_egress_vlan_pop(self, egress_port, vlan_id):
        egress_port = stringify(egress_port, 2)
        vlan_id = stringify(vlan_id, 2)
        self.send_request_add_entry_to_action(
            "egress_next.egress_vlan",
            [self.Exact("vlan_id", vlan_id), self.Exact("eg_port", egress_port),],
            "egress_next.pop_vlan",
            [],
        )

    def set_up_port(
        self, port_id, vlan_id, tagged=False, double_tagged=False, inner_vlan_id=0,
    ):
        if double_tagged:
            self.set_ingress_port_vlan(
                ingress_port=port_id,
                vlan_id=vlan_id,
                vlan_valid=True,
                inner_vlan_id=inner_vlan_id,
            )
        elif tagged:
            self.set_ingress_port_vlan(
                ingress_port=port_id, vlan_id=vlan_id, vlan_valid=True
            )
        else:
            self.set_ingress_port_vlan(
                ingress_port=port_id, vlan_valid=False, internal_vlan_id=vlan_id,
            )
            self.set_egress_vlan_pop(egress_port=port_id, vlan_id=vlan_id)

    def set_forwarding_type(
        self,
        ingress_port,
        eth_dstAddr,
        eth_dstMask=MAC_MASK,
        ethertype=ETH_TYPE_IPV4,
        fwd_type=FORWARDING_TYPE_UNICAST_IPV4,
    ):
        ingress_port_ = stringify(ingress_port, 2)
        eth_dstAddr_ = mac_to_binary(eth_dstAddr)
        eth_mask_ = mac_to_binary(eth_dstMask)
        if ethertype == ETH_TYPE_IPV4:
            ethertype_ = stringify(0, 2)
            ethertype_mask_ = stringify(0, 2)
            ip_eth_type = stringify(ethertype, 2)
        elif ethertype == ETH_TYPE_MPLS_UNICAST:
            ethertype_ = stringify(ETH_TYPE_MPLS_UNICAST, 2)
            ethertype_mask_ = stringify(0xFFFF, 2)
            # FIXME: this will work only for MPLS+IPv4 traffic
            ip_eth_type = stringify(ETH_TYPE_IPV4, 2)
        else:
            # TODO: what should we match on? I should never reach this point.
            return
        fwd_type_ = stringify(fwd_type, 1)
        matches = [
            self.Exact("ig_port", ingress_port_),
            self.Ternary("eth_dst", eth_dstAddr_, eth_mask_),
            self.Exact("ip_eth_type", ip_eth_type),
        ]
        if ethertype_mask_ != b"\x00\x00":
            matches.append(self.Ternary("eth_type", ethertype_, ethertype_mask_))
        self.send_request_add_entry_to_action(
            "filtering.fwd_classifier",
            matches,
            "filtering.set_forwarding_type",
            [("fwd_type", fwd_type_)],
            priority=DEFAULT_PRIORITY,
        )

    def add_forwarding_routing_v4_entry(self, ipv4_dstAddr, ipv4_pLen, next_id):
        ipv4_dstAddr_ = ipv4_to_binary(ipv4_dstAddr)
        next_id_ = stringify(next_id, 4)
        self.send_request_add_entry_to_action(
            "forwarding.routing_v4",
            [self.Lpm("ipv4_dst", ipv4_dstAddr_, ipv4_pLen)],
            "forwarding.set_next_id_routing_v4",
            [("next_id", next_id_)],
        )

    def add_next_routing(self, next_id, egress_port, smac, dmac):
        egress_port_ = stringify(egress_port, 2)
        smac_ = mac_to_binary(smac)
        dmac_ = mac_to_binary(dmac)
        self.add_next_hashed_group_action(
            next_id,
            egress_port,
            [
                [
                    "next.routing_hashed",
                    [("port_num", egress_port_), ("smac", smac_), ("dmac", dmac_)],
                ]
            ],
        )

    def add_next_vlan(self, next_id, new_vlan_id):
        next_id_ = stringify(next_id, 4)
        vlan_id_ = stringify(new_vlan_id, 2)
        self.send_request_add_entry_to_action(
            "next.next_vlan",
            [self.Exact("next_id", next_id_)],
            "next.set_vlan",
            [("vlan_id", vlan_id_)],
        )

    def set_up_report_flow(
        self, src_mac, mon_mac, src_ip, mon_ip, mon_port, mon_label=None
    ):
        action = "do_report_encap"
        action_params = [
            ("src_mac", mac_to_binary(src_mac)),
            ("mon_mac", mac_to_binary(mon_mac)),
            ("src_ip", ipv4_to_binary(src_ip)),
            ("mon_ip", ipv4_to_binary(mon_ip)),
            ("mon_port", stringify(mon_port, 2)),
        ]
        if mon_label:
            action = "do_report_encap_mpls"
            action_params.append(("mon_label", stringify(mon_label, 3)))

        self.send_request_add_entry_to_action(
            "report",
            [
                self.Exact("bmd_type", stringify(BRIDGED_MD_TYPE_EGRESS_MIRROR, 1)),
                self.Exact("mirror_type", stringify(MIRROR_TYPE_INT_REPORT, 1)),
                self.Exact("int_report_type", stringify(INT_REPORT_TYPE_LOCAL, 1)),
            ],
            action,
            action_params,
        )

    def set_up_report_mirror_flow(self, mirror_id, port):
        self.add_clone_group(mirror_id, [port])

    def set_up_flow_report_filter_config(self, hop_latency_mask, timestamp_mask):
        self.send_request_add_entry_to_action(
            "FabricEgress.int_egress.flow_report_filter.config",
            [],
            "FabricEgress.int_egress.flow_report_filter.set_config",
            [
                ("hop_latency_mask", stringify(hop_latency_mask, 4)),
                ("timestamp_mask", stringify(timestamp_mask, 6)),
            ],
        )

    def set_up_watchlist_flow(
        self,
        ipv4_src,
        ipv4_dst,
        ipv4_src_mask="255.255.255.255",
        ipv4_dst_mask="255.255.255.255",
        sport=None,
        dport=None,
    ):
        ipv4_src_ = ipv4_to_binary(ipv4_src)
        ipv4_dst_ = ipv4_to_binary(ipv4_dst)
        ipv4_src_mask_ = ipv4_to_binary(ipv4_src_mask)
        ipv4_dst_mask_ = ipv4_to_binary(ipv4_dst_mask)
        # Use full range of TCP/UDP ports by default.
        sport_low = stringify(0, 2)
        sport_high = stringify(0xFFFF, 2)
        dport_low = stringify(0, 2)
        dport_high = stringify(0xFFFF, 2)

        if sport:
            sport_low = stringify(sport, 2)
            sport_high = stringify(sport, 2)

        if dport:
            dport_low = stringify(dport, 2)
            dport_high = stringify(dport, 2)

        self.send_request_add_entry_to_action(
            "watchlist",
            [
                self.Ternary("ipv4_src", ipv4_src_, ipv4_src_mask_),
                self.Ternary("ipv4_dst", ipv4_dst_, ipv4_dst_mask_),
                self.Range("l4_sport", sport_low, sport_high),
                self.Range("l4_dport", dport_low, dport_high),
            ],
            "mark_to_report",
            [],
            priority=DEFAULT_PRIORITY,
        )

    def set_up_int_mirror_flow(self, switch_id, report_type=INT_REPORT_TYPE_LOCAL):
        switch_id_ = stringify(switch_id, 4)
        report_type_ = stringify(report_type, 1)
        self.send_request_add_entry_to_action(
            "int_metadata",
            [self.Exact("int_report_type", report_type_),],
            "set_metadata",
            [("switch_id", switch_id_)],
        )

    # actions is a tuple (action_name, param_tuples)
    # params_tuples contains a tuple for each param (param_name, param_value)
    def add_next_hashed_group_action(self, next_id, grp_id, actions=()):
        next_id_ = stringify(next_id, 4)
        mbr_ids = []
        for action in actions:
            mbr_id = self.get_next_mbr_id()
            mbr_ids.append(mbr_id)
            self.send_request_add_member(
                "FabricIngress.next.hashed_profile", mbr_id, *action
            )
        self.send_request_add_group(
            "FabricIngress.next.hashed_profile",
            grp_id,
            grp_size=len(mbr_ids),
            mbr_ids=mbr_ids,
        )
        self.send_request_add_entry_to_group(
            "next.hashed", [self.Exact("next_id", next_id_)], grp_id
        )

    def get_next_mbr_id(self):
        mbr_id = self.next_mbr_id
        self.next_mbr_id += 1
        return mbr_id
