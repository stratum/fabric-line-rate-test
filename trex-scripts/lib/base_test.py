# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

from trex_stl_lib.api import STLClient


class BaseTest:
    def __init__(
        self, stl_client: STLClient, duration: int = 1, mult: str = "1pps"
    ) -> None:
        """
        Create and initialize a test

        :parameters:
            stl_client: STLClient
                The Trex tatelesss client
            duration: int
                The duration of the traffic (seconds).
                Default is 1 second.
            mult: str
                Multiplier in a form of pps, bps, or line util in %.
                Default is 1pps.
        """
        self.stl_client = stl_client
        self.duration = duration
        self.mult = mult

    def start(self) -> None:
        """
        Start the traffic
        """
        pass
