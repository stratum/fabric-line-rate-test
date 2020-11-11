<!--
SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
SPDX-License-Identifier: Apache-2.0
-->
Fabric Line Rate Test
====

![Python Code Style](https://github.com/stratum/fabric-line-rate-test/workflows/Python%20Code%20Style/badge.svg)
![REUSE](https://github.com/stratum/fabric-line-rate-test/workflows/REUSE/badge.svg)
![Container Image](https://github.com/stratum/fabric-line-rate-test/workflows/Container%20Image/badge.svg)

Scripts and configs to run line rate test

# Requirements:

 - make
 - Docker (Tested with 19.03.13 on MacOS)
 - Trex 2.85 daemon server process running on a server

# Repository structure

```
.
├── Dockerfile
├── Makefile
├── README.md
├── stratum-replay ------------> Pipeline and P4Runtime write requests to deploied to the switch
├── trex-configs --------------> Trex config for all test cases
│   └── simple_tcp.yaml
└── trex-scripts
    ├── control.py ------------> The main program of the test tool (A Trex client)
    ├── lib -------------------> Utilities and test library
    │   ├── __init__.py
    │   ├── base_test.py
    │   └── utils.py
    └── tests -----------------> Test profiles
        ├── __init__.py
        └── simple_tcp.py
```

# Getting started

## Build the container image

Here we provide a container image that includes all necessary Trex Python dependencies.
To build the container image, use the following command:

```bash
$ make build-image
```

## Add new test

To add new test

## Start the Test

To start a test, use:

```bash
$ make run-test
```

# Create new test

To create new test, you need to prepare few files:

 - The Trex config for the test
 - The script that creates traffic, capture packets and analyze it

## Create Trex config for test

Below is a sample Trex config

```yaml
- version: 2
  interfaces: ['3b:00.0', '3b:00.1']
  port_bandwidth_gb: 40
```

This config file includes two ports, which will be port 0 and port 1 in the test.

For more information about Trex cofig, checkout the [Trex manual][trex-manual]

## Develop a test script

> TBD


[trex-manual]: https://trex-tgn.cisco.com/trex/doc/trex_manual.html#_platform_yaml_cfg_argument
