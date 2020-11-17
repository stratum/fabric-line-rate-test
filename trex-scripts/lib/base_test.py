# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0
from abc import ABC, abstractclassmethod, abstractmethod

from trex.astf.api import ASTFClient
from trex_stl_lib.api import STLClient


class BaseTest(ABC):
    duration: int
    mult: str
    test_args: dict

    def __init__(
        self, duration: int = 1, mult: str = "1pps", test_args: dict = {}
    ) -> None:
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
        self.test_args = test_args

    @abstractmethod
    def start(self) -> None:
        """
        Start the traffic
        """
        pass

    @abstractclassmethod
    def test_type(cls) -> str:
        return None


class StatelessTest(BaseTest):
    client: STLClient

    def __init__(
        self,
        client: STLClient,
        duration: int = 1,
        mult: str = "1pps",
        test_args: dict = {},
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
        super().__init__(duration, mult, test_args)
        self.client = client

    @classmethod
    def test_type(cls) -> str:
        return "stateless"


class StatefulTest(BaseTest):
    client: ASTFClient

    def __init__(
        self,
        client: ASTFClient,
        duration: int = 1,
        mult: str = "1pps",
        test_args: dict = {},
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
        super().__init__(duration, mult, test_args)
        self.client = client

    @classmethod
    def test_type(cls) -> str:
        return "stateful"
