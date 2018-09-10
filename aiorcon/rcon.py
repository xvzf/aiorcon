# -*- coding: utf-8 -*-
"""
    aiorcon.rcon
    ~~~~~~~~~~~~

    RCON client for python

    :copyright: (c) 2018 by Matthias Riegler.
    :license: APACHEv2, see LICENSE.txt for more details.
"""

from asyncio import (open_connection,
                     get_event_loop,
                     AbstractEventLoop)
import asyncio
from struct import unpack
from logging import getLogger
from .rcon_packet import RconPacket


logger = getLogger(__name__)


class RconAuthorizationError(Exception):
    """ Rcon auth error """


class Rcon:
    """ Valves rcon """

    TIMEOUT_STEPS: int = 10

    def __init__(
            self,
            host: str,
            port: int = 27015,
            password: str = "",
            loop: AbstractEventLoop = None):
        """ Initializes the Rcon """

        # Setup id
        self._seq_id = 1
        # Set the eventloop
        self.loop = loop or get_event_loop()
        # Save connection information
        self._host, self._port, self._password = host, port, password
        # Establish connection
        self.loop.run_until_complete(self._connect())

    async def _connect(self):
        """ Creates a TCP connection """
        self._reader, self._writer = await open_connection(host=self._host,
                                                           port=self._port,
                                                           loop=self.loop)
        await self._authorize()

    async def _authorize(self):
        """ Try to authorize """
        await self.request(type=3,
                           id=0,
                           command=self._password)

        # === Somehow this is needed ===
        await self.request(type=2,
                           id=0,
                           command="")
        await self._reader.read(4096)

    @property
    def current_id(self):
        """ Current packet id """
        _to_return = self._seq_id
        self._seq_id += 1
        # Boundary check, 32bit signed int
        if self._seq_id > 2147483647:
            self._seq_id = 1
        return _to_return

    async def request(
            self,
            command: str,
            type: int = RconPacket.SERVERDATA_EXECCOMMAND,
            id: int = None,
            timeout: float = 2.0
            ) -> RconPacket:
        """ Execute an rcon command, rcon is a squential utility so we do not
        have to worry about anything happening asyncronously

        :param command: Command to execute
        :returns: Response packet, original sequence id
        """
        # Build request
        packet_id = self.current_id if id is None else id
        request = RconPacket(id=packet_id,
                             type=type,
                             body=command)

        # print("=== Request ===")
        # print(request.serialize())
        # print()

        # Transmit
        self._writer.write(request.serialize())
        await asyncio.sleep(0.1)
        # Read  response with timeout
        response = await self._reader.read(4)
        if not response:
            raise RconAuthorizationError("No response...")
        size, = unpack("<i", response)
        response += await self._reader.read(size)

        return RconPacket.parse(response)
