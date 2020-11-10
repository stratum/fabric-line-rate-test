# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

current_dir=$(shell pwd)
SERVER_ADDR?=127.0.0.1
TEST?=simple_tcp
IMAGE:=fabric-line-rate-test:0.0.1

build-image:
	docker build -t $(IMAGE) . -f Dockerfile

run-test:
	docker run --rm $(IMAGE) --server $(SERVER_ADDR) $(TEST)

dev:
	docker run -it -v $(current_dir):/workspace -w /workspace --entrypoint sh $(IMAGE)
