# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.12.1 as builder

# Install Trex library
ARG TREX_VER=2.85
ENV PYTHONPATH=/output/usr/local/lib/python3.8/site-packages
# RUN apt update && apt install -y wget
RUN wget https://github.com/cisco-system-traffic-generator/trex-core/archive/v${TREX_VER}.tar.gz && \
    tar xf v${TREX_VER}.tar.gz && \
    mkdir -p ${PYTHONPATH} && \
    cp -r /trex-core-${TREX_VER}/scripts/automation/trex_control_plane/interactive/* ${PYTHONPATH} && \
    cp -r /trex-core-${TREX_VER}/scripts/external_libs/* ${PYTHONPATH}


FROM python:3.8.6-alpine as runtime
# Dependency for ZeroMQ
RUN apk add libstdc++ dumb-init
ENV TREX_EXT_LIBS=/usr/local/lib/python3.8/site-packages
ENV PYTHONPATH=/workspace/trex-scripts
COPY --from=builder /output /
COPY . /workspace
WORKDIR /workspace
ENTRYPOINT [ "dumb-init", "python3", "-m", "control" ]
