# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0
import logging
import os
from os.path import abspath, exists, splitext

import matplotlib.pyplot as plt
import numpy as np
from scapy.fields import BitField, ShortField, XByteField, XIntField, XShortField
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers
from scapy.utils import RawPcapReader, inet_aton
from scipy import stats

log = logging.getLogger("INT Util")
log.setLevel(logging.INFO)


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


class IntL45DropReport(Packet):
    name = "INT_L45_DROP_REPORT"
    fields_desc = [
        XIntField("switch_id", 0),
        XShortField("ingress_port_id", 0),
        XShortField("egress_port_id", 0),
        BitField("queue_id", 0, 8),
        BitField("pad", 0, 24),
    ]


bind_layers(UDP, IntL45ReportFixed, dport=32766)
bind_layers(IntL45ReportFixed, IntL45DropReport, nproto=1)
bind_layers(IntL45ReportFixed, IntL45LocalReport, nproto=2)
bind_layers(IntL45LocalReport, Ether)
bind_layers(IntL45DropReport, Ether)


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


def analysis_report_pcap(pcap_file: str, total_flows_from_trace: int = 0) -> None:
    pcap_reader = RawPcapReader(pcap_file)
    skipped = 0
    dropped = 0  # based on seq number
    prev_seq_no = {}  # HW ID -> seq number

    # Local report
    local_reports = 0
    five_tuple_to_prev_local_report_time = {}  # 5-tuple -> latest report time
    flow_with_multiple_local_reports = set()
    valid_local_report_irgs = []
    bad_local_report_irgs = []
    invalid_local_report_irgs = []

    # Drop report
    drop_reports = 0
    five_tuple_to_prev_drop_report_time = {}  # 5-tuple -> latest report time
    flow_with_multiple_drop_reports = set()
    valid_drop_report_irgs = []
    bad_drop_report_irgs = []
    invalid_drop_report_irgs = []

    while True:
        try:
            packet_info = pcap_reader.next()
        except EOFError:
            break
        except StopIteration:
            break

        # packet_info = (raw-bytes, packet-metadata)
        report_pkt = Ether(packet_info[0])
        packet_enter_time = packet_info[1].sec * 1000000 + packet_info[1].usec

        if IntL45ReportFixed not in report_pkt:
            skipped += 1
            continue

        int_fix_report = report_pkt[IntL45ReportFixed]
        if IntL45LocalReport in report_pkt:
            local_reports += 1
            int_report = report_pkt[IntL45LocalReport]
            packet_enter_time = int_report.egress_tstamp
            five_tuple_to_prev_report_time = five_tuple_to_prev_local_report_time
            flow_with_multiple_reports = flow_with_multiple_local_reports
            valid_report_irgs = valid_local_report_irgs
            bad_report_irgs = bad_local_report_irgs
            invalid_report_irgs = invalid_local_report_irgs
        elif IntL45DropReport not in report_pkt:
            drop_reports += 1
            int_report = report_pkt[IntL45LocalReport]
            five_tuple_to_prev_report_time = five_tuple_to_prev_drop_report_time
            flow_with_multiple_reports = flow_with_multiple_drop_reports
            valid_report_irgs = valid_drop_report_irgs
            bad_report_irgs = bad_drop_report_irgs
            invalid_report_irgs = invalid_drop_report_irgs
        else:
            # TODO: handle queue report
            skipped += 1
            continue

        # Check the sequence number
        hw_id = int_fix_report.hw_id
        seq_no = int_fix_report.seq_no
        if hw_id in prev_seq_no:
            dropped += seq_no - prev_seq_no[hw_id] - 1
        prev_seq_no[hw_id] = seq_no

        # Curently we only process IPv4 packets, but we can process IPv6 if needed.
        if IP not in int_report:
            skipped += 1
            continue

        # Checks the internal packet
        # Here we skip packets that is not a TCP or UDP packet since they can be
        # fragmented or something else.

        if TCP in int_report:
            internal_l4 = int_report[TCP]
        elif UDP in int_report:
            internal_l4 = int_report[UDP]
        else:
            skipped += 1
            continue

        internal_ip = int_report[IP]
        five_tuple = (
            inet_aton(internal_ip.src)
            + inet_aton(internal_ip.dst)
            + int.to_bytes(internal_ip.proto, 1, "big")
            + int.to_bytes(internal_l4.sport, 2, "big")
            + int.to_bytes(internal_l4.dport, 2, "big")
        )

        if five_tuple in five_tuple_to_prev_report_time:
            prev_report_time = five_tuple_to_prev_report_time[five_tuple]
            irg = (packet_enter_time - prev_report_time) / 1000000000
            if irg > 0:
                valid_report_irgs.append(irg)
            flow_with_multiple_reports.add(five_tuple)

            if 0 < irg and irg < 0.9:
                bad_report_irgs.append(irg)
            if irg <= 0:
                invalid_report_irgs.append(irg)

        five_tuple_to_prev_report_time[five_tuple] = packet_enter_time

    # Local report
    log.info("Local reports: {}".format(local_reports))
    log.info("Total 5-tuples: {}".format(len(five_tuple_to_prev_local_report_time)))
    log.info(
        "Flows with multiple report: {}".format(len(flow_with_multiple_local_reports))
    )
    log.info("Total INT IRGs: {}".format(len(valid_local_report_irgs)))
    log.info("Total bad INT IRGs(<0.9s): {}".format(len(bad_local_report_irgs)))
    log.info("Total invalid INT IRGs(<=0s): {}".format(len(invalid_local_report_irgs)))
    if total_flows_from_trace != 0:
        log.info(
            "Accuracy score: {}".format(
                len(five_tuple_to_prev_local_report_time) * 100 / total_flows_from_trace
            )
        )

    if len(valid_local_report_irgs) <= 0:
        log.info("No valid IRGs")
        return

    log.info(
        "Efficiency score: {}".format(
            (len(valid_local_report_irgs) - len(bad_local_report_irgs))
            * 100
            / len(valid_local_report_irgs)
        )
    )

    # Drop report
    log.info("----------------------")
    log.info("Drop reports: {}".format(drop_reports))
    log.info("Total 5-tuples: {}".format(len(five_tuple_to_prev_drop_report_time)))
    log.info(
        "Flows with multiple report: {}".format(len(flow_with_multiple_drop_reports))
    )
    log.info("Total INT IRGs: {}".format(len(valid_drop_report_irgs)))
    log.info("Total bad INT IRGs(<0.9s): {}".format(len(bad_drop_report_irgs)))
    log.info("Total invalid INT IRGs(<=0s): {}".format(len(invalid_drop_report_irgs)))
    log.info("Total report dropped: {}".format(dropped))
    log.info("Skipped packets: {}".format(skipped))

    # Plot Histogram and CDF
    report_plot_file = abspath(splitext(pcap_file)[0] + "-local" + ".png")
    plot_histogram_and_cdf(report_plot_file, valid_local_report_irgs)
    report_plot_file = abspath(splitext(pcap_file)[0] + "-drop" + ".png")
    plot_histogram_and_cdf(report_plot_file, valid_drop_report_irgs)


def plot_histogram_and_cdf(report_plot_file, valid_report_irgs):
    if exists(report_plot_file):
        os.remove(report_plot_file)
    bin_size = 0.25  # sec
    max_val = max(np.max(valid_report_irgs), 3)
    percentile_of_900_msec = stats.percentileofscore(valid_report_irgs, 0.9)
    percentile_of_one_sec = stats.percentileofscore(valid_report_irgs, 1)
    percentile_of_two_sec = stats.percentileofscore(valid_report_irgs, 2)
    percentiles = [
        1,
        5,
        10,
        percentile_of_900_msec,
        percentile_of_one_sec,
        percentile_of_two_sec,
    ]
    vlines = np.percentile(valid_report_irgs, percentiles)

    bins = np.arange(0, max_val + bin_size, bin_size)
    hist, bins = np.histogram(valid_report_irgs, bins=bins)

    # to percentage
    hist = hist / hist.sum()

    CY = np.cumsum(hist)

    _, ax = plt.subplots(figsize=(10, 10))

    fig_y_max = percentile_of_two_sec / 100 + 0.1
    ax.set_yticks(np.arange(0, fig_y_max, 0.1))
    ax.hlines(np.arange(0, fig_y_max, 0.1), 0, 2, colors="y", linestyles=["dotted"])
    ax.vlines(vlines, 0, 1, colors="green", linestyles=["dotted"])

    t = int(2 / bin_size) + 1  # 2 sec -> 8+1 bins
    ax.plot(bins[:t], hist[:t])
    ax.plot(bins[:t], CY[:t], "r--")

    for i in range(0, len(vlines)):
        x = vlines[i]
        y = percentiles[i] / 100
        ax.text(x, y, "({:.2f}%: {:.2f})".format(percentiles[i], x))

    plt.savefig(report_plot_file)
    log.info("Histogram and CDF graph can be found here: {}".format(report_plot_file))
    return report_plot_file
