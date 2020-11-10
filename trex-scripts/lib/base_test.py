# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

from trex_stl_lib.api import *


class BaseTest():
    def __init__(self, stl_client: STLClient, duration: int = 1) -> None:
        self.stl_client = stl_client
        self.duration = duration

    def start(self) -> None:
        pass
