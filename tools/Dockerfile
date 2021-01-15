# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:20.04 as builder

RUN apt update && apt install -y wget build-essential libpcap-dev libgflags-dev
RUN wget https://github.com/seladb/PcapPlusPlus/releases/download/v20.08/pcapplusplus-20.08-ubuntu-20.04-gcc-9.tar.gz
RUN gzip -d pcapplusplus-20.08-ubuntu-20.04-gcc-9.tar.gz
RUN tar zxf pcapplusplus-20.08-ubuntu-20.04-gcc-9.tar
RUN cd pcapplusplus-20.08-ubuntu-20.04-gcc-9 && \
    ./install.sh
RUN wget https://github.com/d-bahr/CRCpp/archive/release-1.0.1.0.tar.gz && \
    tar xf release-1.0.1.0.tar.gz && \
    cp CRCpp-release-1.0.1.0/inc/CRC.h /usr/local/include/
