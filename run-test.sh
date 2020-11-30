#!/bin/bash
# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
IMAGE="fabric-line-rate-test:0.0.1"
TEST_ARGS=()

mkdir -p "${DIR}/tmp"

while (( "$#" )); do
  case "$1" in
    --trex-config)
      # Copy the Trex config to tmp directory and use it
      cp -f "$2" "${DIR}/tmp/"
      TEST_ARGS+=("$1" "/tmp/$(basename "$2")")
      # TEST_ARGS="$TEST_ARGS $1 /tmp/$(basename $2)"
      shift 2
      ;;
    *)
      TEST_ARGS+=("$1")
      # TEST_ARGS="$TEST_ARGS $1"
      shift 1
      ;;
  esac
done

docker run --rm \
           -v "${DIR}/trex-scripts:/workspace/trex-scripts" \
           -v "${DIR}/tmp:/tmp" \
           -w /workspace \
           "${IMAGE}" \
           "${TEST_ARGS[@]}"
