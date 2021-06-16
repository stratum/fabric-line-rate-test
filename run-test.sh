#!/bin/bash
# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
IMAGE="stratumproject/testvectors:ptf"
TEST_ARGS=()

mkdir -p "${DIR}/tmp"

while (( "$#" )); do
  case "$1" in
    # Override the --trex-config parameter since we need to copy the actual config file
    # to the container.
    --trex-config)
      # Copy the Trex config to tmp directory and use it
      cp -f "$2" "${DIR}/tmp/"
      TEST_ARGS+=("$1" "/tmp/$(basename "$2")")
      shift 2
      ;;
    *)
      TEST_ARGS+=("$1")
      shift 1
      ;;
  esac
done

docker run --rm \
           -v "${DIR}/trex-scripts:/workspace/trex-scripts" \
           -v "${DIR}/tools:/workspace/tools" \
           -v "${DIR}/tmp:/tmp" \
           -w /workspace \
           --mount "type=bind,source=$PWD/entrypoint.sh,target=/entrypoint.sh" \
           --entrypoint /entrypoint.sh \
           "${IMAGE}" \
           "${TEST_ARGS[@]}"
