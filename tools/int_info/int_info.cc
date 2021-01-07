// SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
// SPDX-License-Identifier: Apache-2.0
#include <CRC.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <Packet.h>
#include <PayloadLayer.h>
#include <PcapFileDevice.h>
#include <ProtocolType.h>
#include <RawPacket.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <arpa/inet.h>
#include <gflags/gflags.h>
#include <sys/time.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "common/utils.h"
#include "common/xnt.h"

DEFINE_string(i, "", "The input pcap file.");
DEFINE_string(o, "", "The file that stores output, default will be stdout.");
DEFINE_bool(summary, false, "Print summary only");

int main(int argc, char* argv[]) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  std::stringstream output;

  if (FLAGS_i.empty()) {
    output << "Input file name was not given" << std::endl;
    return 1;
  }

  // open a pcap file for reading
  pcpp::IFileReaderDevice* reader =
      pcpp::IFileReaderDevice::getReader(FLAGS_i.c_str());

  if (!reader->open()) {
    delete reader;
    output << "Error opening input pcap file\n";
    return 1;
  }
  pcpp::PcapFileReaderDevice* pcap_reader =
      dynamic_cast<pcpp::PcapFileReaderDevice*>(reader);

  if (pcap_reader == nullptr) {
    output << "Unknown file format";
  }

  uint32_t total_reports = 0;
  uint32_t skipped = 0;

  std::unordered_set<V4Tuple, V4TupleHasher> five_tuples;
  std::unordered_map<V4Tuple, std::shared_ptr<IntFixedHeader>, V4TupleHasher>
      latest_flow_fixed_report;
  std::unordered_map<V4Tuple, std::shared_ptr<IntLocalReport>, V4TupleHasher>
      latest_flow_local_report;
  std::unordered_set<V4Tuple, V4TupleHasher> flows_with_multiple_report;
  std::vector<uint64_t> all_irgs;
  std::unordered_set<uint32_t> flow_hashes;
  pcpp::RawPacket raw_packet;
  uint32_t prev_seq_no = 0;
  uint64_t timestamp_overflow = 0;
  uint64_t other_short_irgs = 0;
  uint64_t bad_irgs = 0;
  while (pcap_reader->getNextPacket(raw_packet)) {
    total_reports++;
    pcpp::Packet parsedPacket(&raw_packet);

    pcpp::UdpLayer* udp_layer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    if (!udp_layer) {
      output << "No UDP header" << std::endl;
      skipped++;
      continue;
    }
    uint16_t l4_dport = ntohs(udp_layer->getUdpHeader()->portDst);

    if (l4_dport != 32766) {
      output << "UDP port not 32766: " << l4_dport << std::endl;
      skipped++;
      continue;
    }
    pcpp::PayloadLayer* payload_layer =
        parsedPacket.getLayerOfType<pcpp::PayloadLayer>();

    // Parse INT Header
    uint8_t* payload = payload_layer->getPayload();
    size_t payload_len = payload_layer->getPayloadLen();

    std::shared_ptr<IntFixedHeader> int_fix_report =
        ParseIntFixedHeader(&payload, &payload_len);

    if (!int_fix_report) {
      output << "No fix report" << std::endl;
      skipped++;
      continue;
    }

    uint32_t seq_no = int_fix_report->SeqNo();
    if (prev_seq_no == 0) {
      prev_seq_no = seq_no;
    } else {
      if (prev_seq_no != seq_no - 1) {
        output << "Wrong sequence number: " << seq_no << ", should be "
               << prev_seq_no + 1 << std::endl;
      }
      prev_seq_no = seq_no;
    }

    std::shared_ptr<IntLocalReport> int_local_report =
        ParseIntLocalReport(&payload, &payload_len);

    if (!int_local_report) {
      output << "No local report" << std::endl;
      skipped++;
      continue;
    }

    // The inner packet
    struct timeval t = {0};
    pcpp::RawPacket inner_packet(payload, payload_len, t, false,
                                 pcpp::LINKTYPE_ETHERNET);
    pcpp::Packet inner_parsed_packet(&inner_packet);
    pcpp::IPv4Layer* inner_ipv4_layer =
        inner_parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::TcpLayer* inner_tcp_layer =
        inner_parsed_packet.getLayerOfType<pcpp::TcpLayer>();
    pcpp::UdpLayer* inner_udp_layer =
        inner_parsed_packet.getLayerOfType<pcpp::UdpLayer>();

    if (inner_ipv4_layer) {
      uint32_t inner_src = inner_ipv4_layer->getSrcIpAddress().toInt();
      uint32_t inner_dst = inner_ipv4_layer->getDstIpAddress().toInt();
      uint8_t inner_proto = inner_ipv4_layer->getIPv4Header()->protocol;
      uint16_t inner_l4_sport = 0;
      uint16_t inner_l4_dport = 0;
      if (inner_tcp_layer) {
        inner_l4_sport = ntohs(inner_tcp_layer->getTcpHeader()->portSrc);
        inner_l4_dport = ntohs(inner_tcp_layer->getTcpHeader()->portDst);
      } else if (inner_udp_layer) {
        inner_l4_sport = ntohs(inner_udp_layer->getUdpHeader()->portSrc);
        inner_l4_dport = ntohs(inner_udp_layer->getUdpHeader()->portDst);
      } else {
        // non_tcp_udp++;
      }
      V4Tuple f_tuple = {inner_src, inner_dst, inner_proto, inner_l4_sport,
                         inner_l4_dport};
      five_tuples.insert(f_tuple);
      uint32_t crc32 = CRC::Calculate(&f_tuple, sizeof(V4Tuple), CRC::CRC_32());
      flow_hashes.insert(crc32);
      if (latest_flow_fixed_report.find(f_tuple) !=
              latest_flow_fixed_report.end() &&
          latest_flow_local_report.find(f_tuple) !=
              latest_flow_local_report.end()) {
        auto latest_fixed_report = latest_flow_fixed_report[f_tuple];
        auto latest_local_report = latest_flow_local_report[f_tuple];
        uint64_t irg =
            int_local_report->EgTime() - latest_local_report->EgTime();
        if (irg < 900000000) {
          bad_irgs++;
          uint64_t ig1 = latest_flow_fixed_report[f_tuple]->IgTime();
          uint64_t ig2 = int_fix_report->IgTime();
          if ((ig2 & 0xffffc0000000L) != (ig1 & 0xffffc0000000L)) {
            timestamp_overflow++;
          } else {
            other_short_irgs++;
          }
        }
        all_irgs.push_back(irg);
        flows_with_multiple_report.insert(f_tuple);
      }
      latest_flow_fixed_report[f_tuple] = int_fix_report;
      latest_flow_local_report[f_tuple] = int_local_report;
    } else {
      output << "No Inner IP header" << std::endl;
      skipped++;
    }
  }
  reader->close();
  delete reader;

  output << std::endl;
  output << "Total reports: " << total_reports << std::endl;
  output << "Total skipped: " << skipped << std::endl;

  output << "Total Inner IPv4 5-tuples: " << five_tuples.size() << std::endl;
  // output << "Total Inner IPv4 5-tuple hashes: " << flow_hashes.size()
  //        << std::endl;
  output << "Flows with single report: "
         << five_tuples.size() - flows_with_multiple_report.size() << std::endl;
  output << "Flows with multiple reports(can calculate IRGs): "
         << flows_with_multiple_report.size() << std::endl;
  output << "Total INT IRGs: " << all_irgs.size() << std::endl;
  output << "Bad IRGs: " << bad_irgs << std::endl;

  if (!FLAGS_summary) {
    sort(all_irgs.begin(), all_irgs.end(), std::greater<uint64_t>());
    output << "---- IRGs below ----" << std::endl;
    for (auto it = all_irgs.begin(); it != all_irgs.end(); ++it) {
      output << *it << std::endl;
    }
  }

  if (FLAGS_o.empty()) {
    std::cout << output.rdbuf();
  } else {
    auto fs = std::ofstream(FLAGS_o, std::ofstream::out);
    fs << output.rdbuf();
    fs.close();
  }
  return 0;
}
