# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

current_dir=$(shell pwd)
IMAGE:=fabric-line-rate-test:0.0.1
SERVER_ADDR?=10.128.13.27
TEST?=simple_tcp
TREX_CONFIG:=$(current_dir)/trex-configs
TREX_SCRIPTS:=$(current_dir)/trex-scripts

default:

build-image:
	docker build -t $(IMAGE) . -f Dockerfile

run-test:
	# TODO: Run stratum-replay tool to set up the switch
	docker run --rm \
						-v $(current_dir)/trex-configs:/workspace/trex-configs \
						-v $(current_dir)/trex-scripts:/workspace/trex-scripts \
						$(IMAGE) \
						--server $(SERVER_ADDR) \
						--trex-config /workspace/trex-configs/$(TEST).yaml \
						$(TEST)

dev:
	docker run --rm \
						-it \
						-v $(current_dir)/trex-configs:/workspace/trex-configs \
						-v $(current_dir)/trex-scripts:/workspace/trex-scripts \
						--entrypoint sh \
						$(IMAGE)
