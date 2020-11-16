# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

from trex_stl_lib.api import STLClient
from trex.astf.api import ASTFClient


class BaseTest:
    def __init__(self, duration: int = 1, mult: str = "1pps") -> None:
        """
        Create and initialize a base test

        :parameters:
            duration: int
                The duration of the traffic (seconds).
                Default is 1 second.
            mult: str
                Multiplier in a form of pps, bps, or line util in %.
                Default is 1pps.
        """
        self.duration = duration
        self.mult = mult


class StatelessTest(BaseTest):
    def __init__(
        self, client: STLClient, duration: int = 1, mult: str = "1pps"
    ) -> None:
        """
        Create and initialize a test

        :parameters:
            client: STLClient
                The Trex statelesss client
            duration: int
                The duration of the traffic (seconds).
                Default is 1 second.
            mult: str
                Multiplier in a form of pps, bps, or line util in %.
                Default is 1pps.
        """
        super().__init__(duration, mult)
        self.client = client

    def start(self) -> None:
        """
        Start the traffic
        """
        pass


class StatefulTest(BaseTest):
    def __init__(
        self, client: ASTFClient, duration: int = 1, mult: str = "1pps"
    ) -> None:
        """
        Create and initialize a test

        :parameters:
            client: ASTFClient
                The Trex advance stateful client
            duration: int
                The duration of the traffic (seconds).
                Default is 1 second.
            mult: str
                Multiplier in a form of pps, bps, or line util in %.
                Default is 1pps.
        """
        super().__init__(duration, mult)
        self.client = client

    def start(self) -> None:
        """
        Start the traffic
        """
        pass
