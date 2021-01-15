# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

.PHONY: pcap-info int-info
current_dir=$(abspath $(dir $(MAKEFILE_LIST)))
INCLUDE_PATH := -I. -I/usr/local/include/pcapplusplus -I/usr/include/netinet
LIBS := -static-libstdc++ -lPcap++ -lPacket++ -lCommon++ -lpcap -lpthread -lgflags_nothreads -static
OTHER_FLAGS := -std=c++11
BASE_IMAGE := pcap-tool-base

pcap-info:
	docker run --rm -v $(current_dir):$(current_dir) -w $(current_dir) $(BASE_IMAGE) \
		g++ $(INCLUDE_PATH) -o pcap-info pcap_info/pcap_info.cc $(LIBS) $(OTHER_FLAGS)

image:
	docker build -t $(BASE_IMAGE) .

clean:
	rm -f pcap-info
