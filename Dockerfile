# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0
ARG TREX_VER=2.85
ARG TREX_EXT_LIBS=/external_libs
ARG TREX_LIBS=/trex-python

FROM alpine:3.12.1 as builder
ARG TREX_VER
ARG TREX_EXT_LIBS
ARG TREX_LIBS
# Install Trex library
ENV TREX_SCRIPT_DIR=/trex-core-${TREX_VER}/scripts
# RUN apt update && apt install -y wget
RUN wget https://github.com/cisco-system-traffic-generator/trex-core/archive/v${TREX_VER}.tar.gz
RUN tar xf v${TREX_VER}.tar.gz && \
    mkdir -p /output/${TREX_EXT_LIBS} && \
    mkdir -p /output/${TREX_LIBS} && \
    cp -r ${TREX_SCRIPT_DIR}/automation/trex_control_plane/interactive/* /output/${TREX_LIBS} && \
    cp -r ${TREX_SCRIPT_DIR}/external_libs/* /output/${TREX_EXT_LIBS} && \
    cp -r ${TREX_SCRIPT_DIR}/automation/trex_control_plane/stf/trex_stf_lib /output/${TREX_LIBS}

FROM python:3.8.6-alpine as runtime
ARG TREX_EXT_LIBS
ARG TREX_LIBS
# Dependency for ZeroMQ
RUN apk add libstdc++ dumb-init
ENV TREX_EXT_LIBS=${TREX_EXT_LIBS}
ENV PYTHONPATH=/workspace/trex-scripts:${TREX_EXT_LIBS}:${TREX_LIBS}
COPY --from=builder /output /

WORKDIR /workspace
ENTRYPOINT [ "dumb-init", "python3", "-m", "control" ]
