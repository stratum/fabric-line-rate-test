#!/bin/bash
# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

set -e

function help() {
  echo "Usage $0 -h -s [server IP address] [test name] [test params]"
}

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SERVER_ADDR="10.128.13.27"
TEST=""
IMAGE="fabric-line-rate-test:0.0.1"
TEST_FLAGS=""

while (( "$#" )); do
  case "$1" in
    -s)
      SERVER_ADDR=$2
      shift 2
      ;;
    -h|--help)
      help
      exit 0
      ;;
    -*)
      echo "Unkonwon flag $1"
      help
      exit 1
      ;;
    *)
      # Test and test parameters
      TEST=$1
      shift 1
      TEST_FLAGS=$*
      break
  esac
done

if [ -z "$SERVER_ADDR" ]; then
  echo "Server address cannot be empty"
  exit 1
fi

if [ -z "$TEST" ]; then
  echo "Test name cannot be empty"
  exit 1
fi

# shellcheck disable=SC2086
docker run --rm \
           -v "${DIR}/trex-configs:/workspace/trex-configs" \
           -v "${DIR}/trex-scripts:/workspace/trex-scripts" \
           -v "${DIR}/tmp:/tmp" \
           -w /workspace \
           "${IMAGE}" \
           --server "${SERVER_ADDR}" \
           --trex-config "/workspace/trex-configs/${TEST}.yaml" \
           ${TEST} ${TEST_FLAGS}
