# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0
import logging

from scapy.fields import BitField, ShortField, XByteField, XIntField, XShortField
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers


class IntMetaHdr(Packet):
    name = "INT_META"
    fields_desc = [
        BitField("ver", 0, 4),
        BitField("rep", 0, 2),
        BitField("c", 0, 1),
        BitField("e", 0, 1),
        BitField("rsvd1", 0, 3),
        BitField("ins_cnt", 0, 5),
        BitField("max_hop_cnt", 32, 8),
        BitField("total_hop_cnt", 0, 8),
        ShortField("inst_mask", 0),
        ShortField("rsvd2", 0x0000),
    ]


class IntL45Head(Packet):
    name = "INT_L45_HEAD"
    fields_desc = [
        XByteField("int_type", 0x01),
        XByteField("rsvd0", 0x00),
        XByteField("length", 0x00),
        XByteField("rsvd1", 0x00),
    ]


class IntL45Tail(Packet):
    name = "INT_L45_TAIL"
    fields_desc = [
        XByteField("next_proto", 0x01),
        XShortField("proto_param", 0x0000),
        XByteField("rsvd", 0x00),
    ]


class IntL45ReportFixed(Packet):
    name = "INT_L45_REPORT_FIXED"
    fields_desc = [
        BitField("ver", 0, 4),
        BitField("nproto", 0, 4),
        BitField("d", 0, 1),
        BitField("q", 0, 1),
        BitField("f", 0, 1),
        BitField("rsvd", 0, 15),
        BitField("hw_id", 1, 6),
        XIntField("seq_no", 0),
        XIntField("ingress_tstamp", 0),
    ]


class IntL45LocalReport(Packet):
    name = "INT_L45_LOCAL_REPORT"
    fields_desc = [
        XIntField("switch_id", 0),
        XShortField("ingress_port_id", 0),
        XShortField("egress_port_id", 0),
        BitField("queue_id", 0, 8),
        BitField("queue_occupancy", 0, 24),
        XIntField("egress_tstamp", 0),
    ]


bind_layers(UDP, IntL45ReportFixed, dport=32766)
bind_layers(IntL45ReportFixed, IntL45LocalReport, nproto=2)
bind_layers(IntL45LocalReport, Ether)


def get_readable_int_report_str(pkt: Packet) -> str:
    if IntL45ReportFixed not in pkt:
        return "No INT report in this packet"
    fixed_report = pkt[IntL45ReportFixed]
    report_types = []
    if fixed_report.d:
        report_types.append("Drop")
    if fixed_report.q:
        report_types.append("Queue")
    if fixed_report.f:
        report_types.append("Flow")
    report_type = ", ".join(report_types)
    hw_id = fixed_report.hw_id
    seq_no = fixed_report.seq_no
    ig_tstamp = fixed_report.ingress_tstamp
    readable_int_info = "Type: {}, HW ID: {}, Seq: {}, Ingress time: {}"

    if IntL45LocalReport not in pkt:
        return readable_int_info.format(report_type, hw_id, seq_no, ig_tstamp)

    local_report = pkt[IntL45LocalReport]
    sw_id = local_report.switch_id
    ig_port = local_report.ingress_port_id
    eg_port = local_report.egress_port_id
    q_id = local_report.queue_id
    q_oc = local_report.queue_occupancy
    eg_tstamp = local_report.egress_tstamp
    latency = eg_tstamp - ig_tstamp

    if latency < 0:
        # Fix the latency number
        latency += 2 ** 32

    readable_int_info += (
        ", Switch ID: {}, Ingress: {}, Egress: {}, "
        + "Queue: {}, Queue occupancy: {}, Egress time: {}, latency: {}"
    )
    return readable_int_info.format(
        report_type,
        hw_id,
        seq_no,
        ig_tstamp,
        sw_id,
        ig_port,
        eg_port,
        q_id,
        q_oc,
        eg_tstamp,
        latency,
    )


def analyze_int_reports(report_packets: list, expected_report_num: int) -> None:
    """
    Analyze INT reposts.

    :paraeteres:
    report_packets: list
        List of INT report packet.
    expected_report_num: int
        The expected number of reports, should be 1 per flow per second if there for
        normal case.
    """

    if len(report_packets) not in range(
        expected_report_num - 1, expected_report_num + 2
    ):
        logging.error(
            "Expected to receive %d +/- 1 pakcets, but got %d",
            expected_report_num,
            len(report_packets),
        )

    prev_seq_no = None
    for pkt in report_packets:
        logging.info("%s", get_readable_int_report_str(pkt))
        if IntL45ReportFixed in pkt:
            seq_no = pkt[IntL45ReportFixed].seq_no
            if prev_seq_no and seq_no != (prev_seq_no + 1):
                logging.error(
                    "Expect to get seq no %d, but got %d", prev_seq_no + 1, seq_no
                )
            prev_seq_no = seq_no
