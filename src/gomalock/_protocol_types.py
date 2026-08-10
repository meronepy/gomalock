"""Defines data structures and parsers for Sesame BLE payloads.

This module provides classes for encapsulating and parsing advertisement data,
incoming BLE packets, reassembled messages, and constructed commands.
"""

import struct
from dataclasses import dataclass, field
from typing import Self
from uuid import UUID

from bleak.backends.device import BLEDevice

from ._const import ItemCode, OpCode, PacketType, ProductModel, ResultCode


@dataclass(frozen=True)
class SesameAdvertisementData:
    """Represents the parsed manufacturer data from a Sesame advertisement.

    Attributes:
        product_model: The identified hardware model of the device.
        is_registered: Indicates whether the device has already been registered.
        device_uuid: The unique UUID broadcast by the device.
    """

    product_model: ProductModel
    is_registered: bool
    device_uuid: UUID

    @classmethod
    def from_manufacturer_data(cls, manufacturer_data: bytes) -> Self:
        """Decodes the raw manufacturer data into an advertisement object.

        Args:
            manufacturer_data: The manufacturer-specific byte string from the BLE
                advertisement.

        Returns:
            A populated SesameAdvertisementData instance.

        Raises:
            struct.error: If the byte string length or format does not match expectations.
            ValueError: If the unpacked model or UUID values are invalid.
        """
        model_value, registered_value, uuid_value = struct.unpack(
            "<HB16s", manufacturer_data
        )
        product_model = ProductModel(model_value)
        is_registered = bool(registered_value)
        device_uuid = UUID(bytes=uuid_value)
        return cls(product_model, is_registered, device_uuid)


@dataclass(frozen=True)
class ScannedSesameDevice:
    """Represents a Sesame device detected during scanning.

    Attributes:
        address: The address of the detected device.
        advertisement_data: The Sesame-specific advertisement data.
    """

    address: str
    advertisement_data: SesameAdvertisementData


@dataclass(frozen=True)
class ScannedSesameWithBLE(ScannedSesameDevice):
    """Internal scanned device retaining the Bleak device for direct connection.

    Attributes:
        ble_device: The original BLEDevice instance from the scan,
            not included in repr or comparisons.
    """

    ble_device: BLEDevice = field(repr=False, compare=False)


@dataclass(frozen=True)
class ReceivedSesamePacket:
    """Represents a single parsed chunk of a BLE GATT notification.

    Attributes:
        header: The 1-byte integer header indicating packet sequence and encryption.
        payload: The remaining byte data following the header.
    """

    header: int
    payload: bytes

    @classmethod
    def from_ble_data(cls, ble_data: bytes) -> Self:
        """Splits raw BLE packet data into a header and payload.

        Args:
            ble_data: The unparsed byte string received from a GATT notification.

        Returns:
            A populated ReceivedSesamePacket instance.

        Raises:
            IndexError: If the provided byte string is empty.
        """
        header = ble_data[0]
        payload = ble_data[1:]
        return cls(header, payload)

    @property
    def is_beginning(self) -> bool:
        """Indicates whether this packet is the start of a sequence."""
        return bool(self.header & PacketType.BEGINNING)

    @property
    def is_end(self) -> bool:
        """Indicates whether this packet concludes a sequence."""
        return bool(self.header & (PacketType.PLAINTEXT_END | PacketType.ENCRYPTED_END))

    @property
    def is_encrypted(self) -> bool:
        """Indicates whether this packet marks the message as encrypted."""
        return bool(self.header & PacketType.ENCRYPTED_END)


@dataclass(frozen=True)
class ReceivedSesameMessage:
    """Represents a fully reassembled message payload from the device.

    Attributes:
        op_code: The operation code identifying the message type.
        payload: The remaining bytes representing the specific message content.
    """

    op_code: OpCode
    payload: bytes

    @classmethod
    def from_reassembled_data(cls, reassembled_data: bytes) -> Self:
        """Parses a complete, concatenated BLE message into an opcode and payload.

        Args:
            reassembled_data: The full byte string reconstructed from multiple packets.

        Returns:
            A populated ReceivedSesameMessage instance.

        Raises:
            IndexError: If the provided byte string is empty.
            ValueError: If the extracted opcode is unknown.
        """
        op_code = OpCode(reassembled_data[0])
        payload = reassembled_data[1:]
        return cls(op_code, payload)


@dataclass(frozen=True)
class ReceivedSesameResponse:
    """Represents a parsed response to a previously issued command.

    Attributes:
        item_code: The code corresponding to the original command.
        result_code: The outcome status of the command.
        payload: Any additional data returned by the device.
    """

    item_code: ItemCode
    result_code: ResultCode
    payload: bytes

    @classmethod
    def from_sesame_message(cls, message_payload: bytes) -> Self:
        """Decodes a response message payload into its components.

        Args:
            message_payload: The byte string from a ReceivedSesameMessage.

        Returns:
            A populated ReceivedSesameResponse instance.

        Raises:
            IndexError: If the payload is too short to contain the required headers.
            ValueError: If the item code or result code are unknown.
        """
        item_code = ItemCode(message_payload[0])
        result_code = ResultCode(message_payload[1])
        payload = message_payload[2:]
        return cls(item_code, result_code, payload)


@dataclass(frozen=True)
class ReceivedSesamePublish:
    """Represents an asynchronous publish notification from the device.

    Attributes:
        item_code: The code identifying the type of published data.
        payload: The actual data content of the notification.
    """

    item_code: ItemCode
    payload: bytes

    @classmethod
    def from_sesame_message(cls, message_payload: bytes) -> Self:
        """Decodes a publish message payload into its components.

        Args:
            message_payload: The byte string from a ReceivedSesameMessage.

        Returns:
            A populated ReceivedSesamePublish instance.

        Raises:
            IndexError: If the payload is empty.
            ValueError: If the item code is unknown.
        """
        item_code = ItemCode(message_payload[0])
        payload = message_payload[1:]
        return cls(item_code, payload)


@dataclass(frozen=True)
class SesameCommand:
    """Encapsulates a command intended for transmission to the device.

    Attributes:
        item_code: The target item code for the operation.
        payload: The specific data parameters for the command.
    """

    item_code: ItemCode
    payload: bytes

    @property
    def transmission_data(self) -> bytes:
        """Constructs the full byte string to be sent over BLE.

        Returns:
            The combined bytes of the item code and payload.
        """
        return self.item_code.value.to_bytes(1, byteorder="little") + self.payload
