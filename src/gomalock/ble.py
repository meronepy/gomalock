"""BLE data structures and parsing utilities for Sesame devices.

This module provides classes and functions for handling BLE advertisement data,
notifications, responses, and command packetization for Sesame devices.
"""

from dataclasses import dataclass
from typing import Self
from uuid import UUID

from .const import (
    ItemCodes,
    OpCodes,
    ResultCodes,
    PacketTypes,
    ProductModels,
)


@dataclass(frozen=True)
class SesameAdvertisementData:
    """Parsed advertisement data from a Sesame BLE device.

    Attributes:
        product_model: The product model of the Sesame device.
        is_registered: Whether the Sesame device is registered.
        device_uuid: The UUID of the Sesame device.
    """

    product_model: ProductModels
    is_registered: bool
    device_uuid: UUID

    @classmethod
    def from_manufacturer_data(cls, manufacturer_data: bytes) -> Self:
        """Parses the manufacturer data advertised via BLE.

        Args:
            manufacturer_data: CANDYHOUSE, Inc-specific data.
        """
        product_model = ProductModels(
            int.from_bytes(manufacturer_data[0:2], byteorder="little")
        )
        is_registered = bool(manufacturer_data[2])
        device_uuid = UUID(bytes=manufacturer_data[3:19])
        return cls(product_model, is_registered, device_uuid)


@dataclass(frozen=True)
class ReceivedSesamePacket:
    """A single BLE packet fragment received from a Sesame device.

    Attributes:
        header: A header indicating the type of packet.
        payload: The payload portion of the received packet
            excluding a 1-byte header.
    """

    header: int
    payload: bytes

    @classmethod
    def from_ble_data(cls, ble_data: bytes) -> Self:
        """Parses a raw BLE packet fragment.

        Args:
            ble_data: Raw BLE packet bytes, including a 1-byte header.

        Returns:
            A ReceivedSesamePacket instance.
        """
        header = ble_data[0]
        payload = ble_data[1:]
        return cls(header, payload)

    @property
    def is_beginning(self) -> bool:
        """Whether the packet is marked as the first packet."""
        return bool(self.header & PacketTypes.BEGINNING)

    @property
    def is_end(self) -> bool:
        """Whether the packet is marked as the end of the packet."""
        return bool(
            self.header & (PacketTypes.PLAINTEXT_END | PacketTypes.ENCRYPTED_END)
        )

    @property
    def is_encrypted(self) -> bool:
        """Whether the packet is marked as the encrypted end of the packet."""
        return bool(self.header & PacketTypes.ENCRYPTED_END)


@dataclass(frozen=True)
class ReceivedSesameMessage:
    """A reassembled data from a Sesame device.

    Attributes:
        op_code: The operation code of the received message.
        payload: The raw byte data which contains publish or response data.
    """

    op_code: OpCodes
    payload: bytes

    @classmethod
    def from_reassembled_data(cls, reassembled_data: bytes) -> Self:
        """Parses a reassembled BLE message into an opcode and payload.

        Args:
            reassembled_data: The full BLE message after reassembly.

        Returns:
            A ReceivedSesameMessage instance.
        """
        op_code = OpCodes(reassembled_data[0])
        payload = reassembled_data[1:]
        return cls(op_code, payload)


@dataclass(frozen=True)
class ReceivedSesameResponse:
    """A response type data from a Sesame device.

    Attributes:
        item_code: The item code indicating the type of response.
        result_code: The result code indicating the success or failure of the request.
        payload: The specific data associated with the item code.
    """

    item_code: ItemCodes
    result_code: ResultCodes
    payload: bytes

    @classmethod
    def from_sesame_message(cls, message_payload: bytes) -> Self:
        """Parses a `ReceivedSesameMessage.payload` into response.

        Args:
            message_payload: The payload of a Sesame response message.

        Returns:
            A ReceivedSesameResponse instance.
        """
        item_code = ItemCodes(message_payload[0])
        result_code = ResultCodes(message_payload[1])
        payload = message_payload[2:]
        return cls(item_code, result_code, payload)


@dataclass(frozen=True)
class ReceivedSesamePublish:
    """A publish type data from a Sesame device.

    Attributes:
        item_code: The item code indicating the type of publish.
        payload: The specific data associated with the item code.
    """

    item_code: ItemCodes
    payload: bytes

    @classmethod
    def from_sesame_message(cls, message_payload: bytes) -> Self:
        """Parses a `ReceivedSesameMessage.payload` into publish.

        Args:
            message_payload: The payload of a Sesame publish message.

        Returns:
            A ReceivedSesamePublish instance.
        """
        item_code = ItemCodes(message_payload[0])
        payload = message_payload[1:]
        return cls(item_code, payload)


@dataclass(frozen=True)
class SesameCommand:
    """A command to be sent to Sesame devices.

    Attributes:
        item_code: The item code indicating the type of request.
        payload: The specific data associated with the item code.
    """

    item_code: ItemCodes
    payload: bytes

    @property
    def transmission_data(self) -> bytes:
        """Returns the encoded data to be transmitted over BLE.

        Returns:
            A bytes object with item code prepended to payload.
        """
        return bytes([self.item_code.value]) + self.payload
