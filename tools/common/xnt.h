// SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
// SPDX-License-Identifier: Apache-2.0
#ifndef XNT_H
#define XNT_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <sstream>

struct IntFixedHeader {
  uint8_t ver_proto;
  uint8_t dqf_rsvd;     // 3-bit + 5-bit
  uint16_t rsvd_hw_id;  // 10-bit + 6-bit
  uint32_t seq_no;
  uint32_t ig_tstamp;

  uint32_t SeqNo() {
    return ntohl(seq_no);
  }

  uint32_t IgTime() {
    return ntohl(ig_tstamp);
  }

  IntFixedHeader() {}
  std::string ToString() {
    std::stringstream ss;
    ss << "seq " << SeqNo() << ", ig time " << IgTime();
    return ss.str();
  }
};

struct IntLocalReport {
  uint32_t switch_id;
  uint16_t ig_port;
  uint16_t eg_port;
  uint32_t queue_id_occupancy;
  uint32_t eg_tstamp;

  uint16_t IgPort() {
    return ntohs(ig_port);
  }

  uint16_t EgPort() {
    return ntohs(eg_port);
  }

  uint32_t QueueId() {
    return queue_id_occupancy & 0xff;
  }

  uint32_t QueueOccupancy() {
    return ntohl(queue_id_occupancy) & 0xffffff;
  }

  uint32_t EgTime() {
    return ntohl(eg_tstamp);
  }

  IntLocalReport() {}
  std::string ToString() {
    std::stringstream ss;
    ss << "ig " << IgPort() << ", eg " << EgPort()
       << ", qid " << QueueId()
       << ", qoc "<< QueueOccupancy()
       << ", eg time " << EgTime();
    return ss.str();
  }
};

std::shared_ptr<IntFixedHeader> ParseIntFixedHeader(uint8_t** data,
                                                    size_t* data_len) {
  if (*data_len < sizeof(IntFixedHeader)) {
    return nullptr;
  }
  IntFixedHeader fix_header;
  std::memcpy(&fix_header, *data, sizeof(IntFixedHeader));
  *data += sizeof(IntFixedHeader);
  data_len -= sizeof(IntFixedHeader);
  return std::make_shared<IntFixedHeader>(fix_header);
}

std::shared_ptr<IntLocalReport> ParseIntLocalReport(uint8_t** data,
                                                    size_t* data_len) {
  if (*data_len < sizeof(IntLocalReport)) {
    return nullptr;
  }
  IntLocalReport local_report;
  std::memcpy(&local_report, *data, sizeof(IntLocalReport));
  *data += sizeof(IntLocalReport);
  data_len -= sizeof(IntFixedHeader);
  return std::make_shared<IntLocalReport>(local_report);
}

#endif  // XNT_H
