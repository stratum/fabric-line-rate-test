#!/bin/bash
# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

set -e
TREX_VER=2.85
wget https://github.com/cisco-system-traffic-generator/trex-core/archive/v${TREX_VER}.tar.gz
tar xf v${TREX_VER}.tar.gz
