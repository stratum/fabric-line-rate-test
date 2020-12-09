# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

.PHONY: stratum-replay

current_dir=$(abspath $(dir $(MAKEFILE_LIST)))
IMAGE:=fabric-line-rate-test:0.0.1
SERVER_ADDR?=10.128.13.27
SWITCH_ADDR?=10.128.13.29
TEST?=int_single_flow
TREX_CONFIG:=$(current_dir)/trex-configs
TREX_SCRIPTS:=$(current_dir)/trex-scripts

default:
	@echo "Nothing here"

build-image:
	@docker build -t $(IMAGE) . -f Dockerfile

.venv:
	@python3 -m venv .venv

set-up-dev-env: .venv
	@. $(current_dir)/.venv/bin/activate; pip3 install -r requirements.txt
	-docker rm set_up_dev_env
	@docker run -d --name set_up_dev_env $(IMAGE) sh
	@docker cp set_up_dev_env:/trex_python .
	@cp -r trex_python/* .venv/lib/python3.8/site-packages/
	@rm -rf trex_python
	@docker rm set_up_dev_env

dev:
	@docker run --rm \
						-it \
						-v $(current_dir)/trex-configs:/workspace/trex-configs \
						-v $(current_dir)/trex-scripts:/workspace/trex-scripts \
						-v $(current_dir)/tmp:/tmp \
						--entrypoint sh \
						$(IMAGE)

stratum-replay:
	@docker run --rm \
		-v $(current_dir)/stratum-replay/$(TEST):/configs \
		-w /configs \
		stratumproject/stratum-replay \
		-grpc-addr=$(SWITCH_ADDR):9339 \
		-pipeline-cfg /configs/pipeline_cfg.pb.txt \
		/configs/p4_writes.pb.txt

# Temporary key to login to the ONOS karaf
tmp/keys/id_rsa:
	@mkdir -p tmp/keys
	@ssh-keygen -q -t rsa -N '' -f tmp/keys/id_rsa

onos-start: tmp/keys/id_rsa
	@docker-compose -f tost/docker-compose.yaml up -d
	$(eval KEY := $(shell cut -d\  -f2 tmp/keys/id_rsa.pub))
	@docker exec tost bash -c 'echo "$(USER)=$(KEY),_g_:admingroup" >> apache-karaf-*/etc/keys.properties'

onos-stop:
	@docker-compose -f tost/docker-compose.yaml down -t 0

onos-logs:
	@docker-compose -f tost/docker-compose.yaml logs -f

onos-cli: tmp/keys/id_rsa
	@ssh -o StrictHostKeyChecking=no -p 8101 -i tmp/keys/id_rsa $(USER)@127.0.0.1

onos-ui:
	open http://127.0.0.1:8181/onos/ui

netcfg:
	@curl --fail -sSL --user onos:rocks --noproxy localhost \
		-X POST -H 'Content-Type:application/json' \
		http://localhost:8181/onos/v1/network/configuration -d@./tost/netcfg.json

clean:
	-rm -rf tmp
