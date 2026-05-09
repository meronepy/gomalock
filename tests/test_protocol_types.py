"""Tests for public protocol payload types."""

import struct

import pytest

from gomalock import const, protocol_types

from .conftest import DEVICE_UUID, make_manufacturer_data


def test_from_manufacturer_data_registered_payload() -> None:
    """Parses registered advertisement data."""
    result = protocol_types.SesameAdvertisementData.from_manufacturer_data(
        make_manufacturer_data()
    )

    assert result.product_model == const.ProductModels.SESAME5
    assert result.is_registered is True
    assert result.device_uuid == DEVICE_UUID


def test_from_manufacturer_data_unregistered_payload() -> None:
    """Parses unregistered advertisement data."""
    result = protocol_types.SesameAdvertisementData.from_manufacturer_data(
        make_manufacturer_data(is_registered=False)
    )

    assert result.is_registered is False


def test_from_manufacturer_data_short_payload() -> None:
    """Raises struct.error for malformed advertisement data."""
    with pytest.raises(struct.error):
        protocol_types.SesameAdvertisementData.from_manufacturer_data(b"\x00")


def test_from_manufacturer_data_unknown_model() -> None:
    """Raises ValueError for unsupported product model IDs."""
    data = struct.pack("<HB16s", 999, 1, DEVICE_UUID.bytes)

    with pytest.raises(ValueError):
        protocol_types.SesameAdvertisementData.from_manufacturer_data(data)


def test_from_ble_data_complete_payload() -> None:
    """Parses a BLE packet header and payload."""
    data = bytes([const.PacketTypes.BEGINNING]) + b"payload"

    packet = protocol_types.ReceivedSesamePacket.from_ble_data(data)

    assert packet.header == const.PacketTypes.BEGINNING
    assert packet.payload == b"payload"
    assert packet.is_beginning is True
    assert packet.is_end is False


def test_from_ble_data_empty_payload() -> None:
    """Raises IndexError for empty BLE data."""
    with pytest.raises(IndexError):
        protocol_types.ReceivedSesamePacket.from_ble_data(b"")


def test_is_end_encrypted_end() -> None:
    """Treats encrypted-end packets as final encrypted fragments."""
    packet = protocol_types.ReceivedSesamePacket(
        const.PacketTypes.ENCRYPTED_END, b""
    )

    assert packet.is_end is True
    assert packet.is_encrypted is True


def test_from_reassembled_data_response_payload() -> None:
    """Parses an opcode and message payload."""
    message = protocol_types.ReceivedSesameMessage.from_reassembled_data(
        bytes([const.OpCodes.RESPONSE.value]) + b"data"
    )

    assert message.op_code == const.OpCodes.RESPONSE
    assert message.payload == b"data"


def test_from_reassembled_data_unknown_opcode() -> None:
    """Raises ValueError for unsupported opcodes."""
    with pytest.raises(ValueError):
        protocol_types.ReceivedSesameMessage.from_reassembled_data(b"\xff")


def test_from_sesame_message_success_response() -> None:
    """Parses response item, result, and payload bytes."""
    response = protocol_types.ReceivedSesameResponse.from_sesame_message(
        bytes([const.ItemCodes.LOGIN.value, const.ResultCodes.SUCCESS.value])
        + b"ok"
    )

    assert response.item_code == const.ItemCodes.LOGIN
    assert response.result_code == const.ResultCodes.SUCCESS
    assert response.payload == b"ok"


def test_from_sesame_message_short_response() -> None:
    """Raises IndexError when response headers are incomplete."""
    with pytest.raises(IndexError):
        protocol_types.ReceivedSesameResponse.from_sesame_message(b"\x02")


def test_from_sesame_message_publish_payload() -> None:
    """Parses publish item and payload bytes."""
    publish = protocol_types.ReceivedSesamePublish.from_sesame_message(
        bytes([const.ItemCodes.MECH_STATUS.value]) + b"status"
    )

    assert publish.item_code == const.ItemCodes.MECH_STATUS
    assert publish.payload == b"status"


def test_from_sesame_message_empty_publish() -> None:
    """Raises IndexError when publish data is empty."""
    with pytest.raises(IndexError):
        protocol_types.ReceivedSesamePublish.from_sesame_message(b"")


def test_transmission_data_empty_payload() -> None:
    """Builds command bytes from an item code and empty payload."""
    command = protocol_types.SesameCommand(const.ItemCodes.LOCK, b"")

    assert command.transmission_data == bytes([const.ItemCodes.LOCK.value])
