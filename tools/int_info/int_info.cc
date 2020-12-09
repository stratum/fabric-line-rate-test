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

  // print file summary
  output << "File summary:" << std::endl;
  output << "~~~~~~~~~~~~~" << std::endl;
  output << "   File name: " << reader->getFileName() << std::endl;
  output << "   File size: " << reader->getFileSize() << " bytes" << std::endl;

  pcpp::PcapFileReaderDevice* pcap_reader =
      dynamic_cast<pcpp::PcapFileReaderDevice*>(reader);

  if (pcap_reader == nullptr) {
    output << "Unknown file format";
  }

  uint32_t total_reports = 0;
  uint32_t skipped = 0;

  std::unordered_map<V4Tuple, uint64_t, V4TupleHasher> flow_reports; // <flow id, previous time>
  std::vector<uint64_t> all_intervals;
  std::unordered_set<uint32_t> flow_hashes;
  pcpp::RawPacket raw_packet;
  uint32_t prev_seq_no = 0;
  size_t flow_with_multiple_report = 0;
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

    uint32_t seq_no = ntohl(int_fix_report->seq_no);
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
      pcpp::iphdr* iph = inner_ipv4_layer->getIPv4Header();
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
      }
      V4Tuple f_tuple = {inner_src, inner_dst, inner_proto, inner_l4_sport,
                         inner_l4_dport};
      uint32_t crc32 = CRC::Calculate(&f_tuple, sizeof(V4Tuple), CRC::CRC_32());
      flow_hashes.insert(crc32);
      timespec timestamp = raw_packet.getPacketTimeStamp();
      uint64_t time_ns =
          (uint64_t)timestamp.tv_sec * 1000000000 + (uint64_t)timestamp.tv_nsec;
      if (flow_reports.find(f_tuple) != flow_reports.end()) {
        all_intervals.push_back(time_ns - flow_reports[f_tuple]);
        flow_with_multiple_report++;
      }
      flow_reports[f_tuple] = time_ns;
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

  output << "Total Inner IPv4 5-tuples: " << flow_reports.size() << std::endl;
  output << "Total Inner IPv4 5-tuple hashes: " << flow_hashes.size()
         << std::endl;
  output << "Flows with single report: "
         << all_intervals.size() - flow_with_multiple_report
         << std::endl;
  output << "Flows with multiple report: " << flow_with_multiple_report
         << std::endl;
  output << "Total INT report intervals: " << all_intervals.size() << std::endl;

  sort(all_intervals.begin(), all_intervals.end(), std::greater<uint64_t>());

  for (auto it = all_intervals.begin(); it != all_intervals.end(); ++it) {
    output << *it << std::endl;
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
