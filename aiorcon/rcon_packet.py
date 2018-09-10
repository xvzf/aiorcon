"""
    aiorcon.rcon_packet
    ~~~~~~~~~~~~~~~~~~~

    RCON packet

    :copyright: (c) 2018 by Matthias Riegler.
    :license: APACHEv2, see LICENSE.txt for more details.
"""

from dataclasses import dataclass
from struct import pack, unpack
from typing import ByteString


class RconPacketException(Exception):
    """ Rcon Packet Exception """


@dataclass
class RconPacket:
    """ Based on https://developer.valvesoftware.com/wiki/Source_RCON_Protocol
    """
    id: int
    type: int
    body: str

    SERVERDATA_AUTH = 3
    SERVERDATA_AUTH_RESPONSE = 2  # YES, they are both 2 for whatever
    SERVERDATA_EXECCOMMAND = 2    # reason
    SERVERDATA_RESPONSE_VALUE = 0

    PACKET_SIZE_LIMIT = 4096

    def serialize(self) -> ByteString:
        """ Serializes a packet so it can be transmitted """
        size = 10 + len(self.body)

        # Check package size, only constraint here!
        if size > self.PACKET_SIZE_LIMIT - 4:
            raise RconPacketException("Packet too big")

        return pack(
                "<iii",
                size,  # Packet length
                self.id,
                self.type) \
              + self.body.encode() + b"\x00" \
              + b"\x00" # Packet end

    @staticmethod
    def parse(packet: ByteString):
        """ Parses a packet and creats the corresponding object

        :returns: RconPacket
        :throws: RconPacketexception if something went wrong
        """
        try:
            size, id, type = unpack("<iii", packet[:12])

            # Check the size and if the last byte matches the packet
            # description
            if len(packet) - 4 != size or packet[-1] != 0x00:
                raise RconPacketException()

            return RconPacket(
                    id=id,
                    type=type,
                    body=packet[12:-1].decode())

        except:  # @TODO!!!
            raise RconPacketException()

