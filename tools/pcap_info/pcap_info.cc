// SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
// SPDX-License-Identifier: Apache-2.0
#include <CRC.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <RawPacket.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <gflags/gflags.h>

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "common/utils.h"

DEFINE_string(i, "", "The input pcap file.");
DEFINE_string(o, "", "The file that stores output, default will be stdout.");

bool SortFlowsByCount(const std::pair<V4Tuple, uint32_t>& a,
                      const std::pair<V4Tuple, uint32_t>& b) {
  return a.second > b.second;
}

int main(int argc, char* argv[]) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  std::stringstream output;

  if (FLAGS_i.empty()) {
    output << "Input file name was not given" << std::endl;
    return 1;
  }

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

  pcpp::LinkLayerType linkLayer = pcap_reader->getLinkLayerType();
  output << "   Link layer type: ";
  if (linkLayer == pcpp::LINKTYPE_ETHERNET)
    output << "Ethernet";
  else if (linkLayer == pcpp::LINKTYPE_LINUX_SLL)
    output << "Linux cooked capture";
  else if (linkLayer == pcpp::LINKTYPE_NULL)
    output << "Null/Loopback";
  else if (linkLayer == pcpp::LINKTYPE_RAW ||
           linkLayer == pcpp::LINKTYPE_DLT_RAW1 ||
           linkLayer == pcpp::LINKTYPE_DLT_RAW2) {
    output << "Raw IP (" << linkLayer << ")";
  }
  uint32_t total_pkts = 0;
  uint32_t num_ipv4 = 0;
  uint32_t num_ipv6 = 0;
  uint32_t num_others = 0;
  std::unordered_map<V4Tuple, uint32_t, V4TupleHasher> flows;
  std::unordered_set<uint32_t> flow_hashes;
  pcpp::RawPacket raw_packet;
  while (pcap_reader->getNextPacket(raw_packet)) {
    pcpp::Packet parsedPacket(&raw_packet);
    pcpp::IPv4Layer* ipv4_layer =
        parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::IPv6Layer* ipv6_layer =
        parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
    pcpp::TcpLayer* tcp_layer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    pcpp::UdpLayer* udp_layer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    if (ipv4_layer) {
      num_ipv4++;
      uint32_t src = ipv4_layer->getSrcIpAddress().toInt();
      uint32_t dst = ipv4_layer->getDstIpAddress().toInt();
      uint8_t proto = ipv4_layer->getIPv4Header()->protocol;
      uint16_t l4_sport = 0;
      uint16_t l4_dport = 0;
      if (tcp_layer) {
        l4_sport = ntohs(tcp_layer->getTcpHeader()->portSrc);
        l4_dport = ntohs(tcp_layer->getTcpHeader()->portDst);
      } else if (udp_layer) {
        l4_sport = ntohs(udp_layer->getUdpHeader()->portSrc);
        l4_dport = ntohs(udp_layer->getUdpHeader()->portDst);
      }
      V4Tuple f_tple = {src, dst, proto, l4_sport, l4_dport};
      uint32_t crc32 = CRC::Calculate(&f_tple, sizeof(V4Tuple), CRC::CRC_32());
      flow_hashes.insert(crc32);

      if (flows.find(f_tple) == flows.end()) {
        flows[f_tple] = 1;
      } else {
        flows[f_tple]++;
      }
    } else if (ipv6_layer) {
      num_ipv6++;
    } else {
      num_others++;
    }
    total_pkts++;
  }
  reader->close();
  delete reader;

  output << std::endl;
  output << "Total IPv4: " << num_ipv4 << " ("
         << (double)num_ipv4 / total_pkts * 100 << "%)" << std::endl;
  output << "Total IPv6: " << num_ipv6 << " ("
         << (double)num_ipv6 / total_pkts * 100 << "%)" << std::endl;
  output << "Other types of packet: " << num_others << " ("
         << (double)num_others / total_pkts * 100 << "%)" << std::endl;
  output << "Total IPv4 5-tuples: " << flows.size() << std::endl;
  output << "Total IPv4 5-tuple hashes: " << flow_hashes.size() << std::endl;
  output << "Total: " << total_pkts << std::endl;

  // Sort and print flows based on the number pakets of the flow
  std::vector<std::pair<V4Tuple, uint32_t>> flows_in_order;
  for (auto it = flows.begin(); it != flows.end(); ++it) {
    flows_in_order.push_back(std::make_pair(it->first, it->second));
  }
  sort(flows_in_order.begin(), flows_in_order.end(), SortFlowsByCount);
  for (auto it = flows_in_order.begin(); it != flows_in_order.end(); ++it) {
    output << it->first.ToString() << " : " << it->second << std::endl;
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