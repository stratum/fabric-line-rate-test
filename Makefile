# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

.PHONY: stratum-replay

current_dir=$(shell pwd)
IMAGE:=fabric-line-rate-test:0.0.1
SERVER_ADDR?=10.128.13.27
SWITCH_ADDR?=10.128.13.29
TEST?=int_single_flow
TREX_CONFIG:=$(current_dir)/trex-configs
TREX_SCRIPTS:=$(current_dir)/trex-scripts
EXTRA_TEST_ARGS?=

default:
	@echo "Nothing here"

build-image:
	docker build -t $(IMAGE) . -f Dockerfile

run-test:
	docker run --rm \
						-v $(current_dir)/trex-configs:/workspace/trex-configs \
						-v $(current_dir)/trex-scripts:/workspace/trex-scripts \
						$(IMAGE) \
						--server $(SERVER_ADDR) \
						--trex-config /workspace/trex-configs/$(TEST).yaml \
						$(EXTRA_TEST_ARGS) $(TEST)

dev:
	docker run --rm \
						-it \
						-v $(current_dir)/trex-configs:/workspace/trex-configs \
						-v $(current_dir)/trex-scripts:/workspace/trex-scripts \
						--entrypoint sh \
						$(IMAGE)

stratum-replay:
	docker run --rm \
		-v $(current_dir)/stratum-replay/$(TEST):/configs \
		-w /configs \
		stratumproject/stratum-replay \
		-grpc-addr=$(SWITCH_ADDR):9339 \
		-pipeline-cfg /configs/pipeline_cfg.pb.txt \
		/configs/p4_writes.pb.txt

onos-start:
	docker-compose -f tost/docker-compose.yaml up -d

onos-stop:
	docker-compose -f tost/docker-compose.yaml down -t 0

onos-logs:
	docker-compose -f tost/docker-compose.yaml logs -f

onos-cli:
	ssh -p 8101 karaf@127.0.0.1

netcfg:
	curl --fail -sSL --user onos:rocks --noproxy localhost \
		-X POST -H 'Content-Type:application/json' \
		http://localhost:8181/onos/v1/network/configuration -d@./tost/netcfg.json