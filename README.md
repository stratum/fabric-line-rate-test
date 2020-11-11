<!--
SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
SPDX-License-Identifier: Apache-2.0
-->
Fabric Line Rate Test
====

![pycodestyle](https://github.com/stratum/fabric-line-rate-test/workflows/Check%20Python%20code%20style/badge.svg?branch=master)
![License check](https://github.com/stratum/fabric-line-rate-test/workflows/Check%20license/badge.svg)

Scripts and configs to run line rate test

# Requirements:

 - make
 - Docker (Tested with 19.03.13 on MacOS)
 - A server which runs Trex 2.85 with stateless mode

# Prepare the base container image

To build the base container image, use the following command:

```bash
$ make build-image
```

# Run the test

To start a test, use:

```bash
$ make run-test SERVER_ADDR=[server address] TEST=[strem profile]
```

You can find the test profiles located at [trex/test](trex/test) directory.
