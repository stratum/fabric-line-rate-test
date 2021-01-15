// SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
// SPDX-License-Identifier: Apache-2.0
#ifndef UTILS_H
#define UTILS_H

#include <CRC.h>
#include <IpAddress.h>
#include <RawPacket.h>
#include <sys/time.h>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

struct V4Tuple {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint8_t proto;
  uint16_t l4_sport;
  uint16_t l4_dport;
  bool operator==(V4Tuple const& other) const {
    return src_ip == other.src_ip && dst_ip == other.dst_ip &&
           proto == other.proto && l4_sport == other.l4_sport &&
           l4_dport == other.l4_dport;
  }

  std::string ToString() const {
    std::stringstream ss;
    pcpp::IPv4Address src(src_ip);
    pcpp::IPv4Address dst(dst_ip);
    uint32_t p = proto;
    ss << std::setw(15) << src.toString() << " " << std::setw(15)
       << dst.toString() << " " << std::setw(3) << p << " " << std::setw(5)
       << l4_sport << " " << std::setw(5) << l4_dport;
    return ss.str();
  }
};

struct V4TupleHasher {
  std::size_t operator()(V4Tuple const& v4tuple) const noexcept {
    return CRC::Calculate(&v4tuple, sizeof(V4Tuple), CRC::CRC_32());
  }
};

void DumpPacketHex(const pcpp::RawPacket& packet) {
  const uint8_t* raw_data = packet.getRawData();
  int len = packet.getRawDataLen();

  for (int c = 0; c < len; c++) {
    std::cout << std::setfill('0') << std::setw(2) << std::hex
              << (uint16_t)raw_data[c] << " ";
  }

  std::cout << std::endl;
}

#endif  // UTILS_H
