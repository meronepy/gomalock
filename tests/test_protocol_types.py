# pylint: disable=missing-module-docstring
import struct

import pytest

from gomalock import const, protocol_types
from tests.conftest import TEST_UUID, make_manufacturer_data


def test_from_manufacturer_data_registered() -> None:
    """Parses product model, registration state, and UUID."""
    result = protocol_types.SesameAdvertisementData.from_manufacturer_data(
        make_manufacturer_data()
    )

    assert result.product_model == const.ProductModels.SESAME5
    assert result.is_registered is True
    assert result.device_uuid == TEST_UUID


def test_from_manufacturer_data_unregistered() -> None:
    """Parses a false registration flag."""
    result = protocol_types.SesameAdvertisementData.from_manufacturer_data(
        make_manufacturer_data(registered=0)
    )

    assert result.is_registered is False


def test_from_manufacturer_data_invalid_length() -> None:
    """Raises struct.error for malformed manufacturer data."""
    with pytest.raises(struct.error):
        protocol_types.SesameAdvertisementData.from_manufacturer_data(b"\x00")


def test_from_manufacturer_data_unknown_model() -> None:
    """Raises ValueError for unsupported product models."""
    data = struct.pack("<HB16s", 999, 1, TEST_UUID.bytes)

    with pytest.raises(ValueError):
        protocol_types.SesameAdvertisementData.from_manufacturer_data(data)


def test_from_ble_data_with_payload() -> None:
    """Splits the header byte from the BLE packet payload."""
    packet = protocol_types.ReceivedSesamePacket.from_ble_data(b"\x03payload")

    assert packet.header == 3
    assert packet.payload == b"payload"


def test_from_ble_data_empty() -> None:
    """Raises IndexError when the packet is empty."""
    with pytest.raises(IndexError):
        protocol_types.ReceivedSesamePacket.from_ble_data(b"")


@pytest.mark.parametrize(
    ("header", "is_beginning", "is_end", "is_encrypted"),
    [
        (const.PacketTypes.BEGINNING, True, False, False),
        (const.PacketTypes.PLAINTEXT_END, False, True, False),
        (const.PacketTypes.ENCRYPTED_END, False, True, True),
        (
            const.PacketTypes.BEGINNING | const.PacketTypes.ENCRYPTED_END,
            True,
            True,
            True,
        ),
    ],
)
def test_packet_properties_flags(
    header: const.PacketTypes,
    is_beginning: bool,
    is_end: bool,
    is_encrypted: bool,
) -> None:
    """Reflects packet sequencing and encryption flags."""
    packet = protocol_types.ReceivedSesamePacket(header, b"")

    assert packet.is_beginning is is_beginning
    assert packet.is_end is is_end
    assert packet.is_encrypted is is_encrypted


def test_from_reassembled_data_valid() -> None:
    """Parses an opcode and message payload."""
    result = protocol_types.ReceivedSesameMessage.from_reassembled_data(
        bytes([const.OpCodes.PUBLISH.value]) + b"payload"
    )

    assert result.op_code == const.OpCodes.PUBLISH
    assert result.payload == b"payload"


def test_from_reassembled_data_empty() -> None:
    """Raises IndexError when reassembled data is empty."""
    with pytest.raises(IndexError):
        protocol_types.ReceivedSesameMessage.from_reassembled_data(b"")


def test_from_reassembled_data_unknown_opcode() -> None:
    """Raises ValueError for unsupported opcodes."""
    with pytest.raises(ValueError):
        protocol_types.ReceivedSesameMessage.from_reassembled_data(b"\xff")


def test_from_sesame_message_response_success() -> None:
    """Parses response item, result, and payload."""
    result = protocol_types.ReceivedSesameResponse.from_sesame_message(
        bytes([const.ItemCodes.LOGIN.value, const.ResultCodes.SUCCESS.value])
        + b"payload"
    )

    assert result.item_code == const.ItemCodes.LOGIN
    assert result.result_code == const.ResultCodes.SUCCESS
    assert result.payload == b"payload"


def test_from_sesame_message_response_short() -> None:
    """Raises IndexError when response headers are incomplete."""
    with pytest.raises(IndexError):
        protocol_types.ReceivedSesameResponse.from_sesame_message(b"\x02")


def test_from_sesame_message_response_unknown_item() -> None:
    """Raises ValueError for an unknown response item code."""
    with pytest.raises(ValueError):
        protocol_types.ReceivedSesameResponse.from_sesame_message(b"\xff\x00")


def test_from_sesame_message_publish_success() -> None:
    """Parses publish item code and payload."""
    result = protocol_types.ReceivedSesamePublish.from_sesame_message(
        bytes([const.ItemCodes.MECH_STATUS.value]) + b"payload"
    )

    assert result.item_code == const.ItemCodes.MECH_STATUS
    assert result.payload == b"payload"


def test_from_sesame_message_publish_empty() -> None:
    """Raises IndexError when publish payload is empty."""
    with pytest.raises(IndexError):
        protocol_types.ReceivedSesamePublish.from_sesame_message(b"")


def test_transmission_data_with_payload() -> None:
    """Prefixes command payloads with the item code."""
    command = protocol_types.SesameCommand(const.ItemCodes.LOGIN, b"payload")

    assert (
        command.transmission_data == bytes([const.ItemCodes.LOGIN.value]) + b"payload"
    )


def test_transmission_data_empty_payload() -> None:
    """Returns only the item code for empty command payloads."""
    command = protocol_types.SesameCommand(const.ItemCodes.LOCK, b"")

    assert command.transmission_data == bytes([const.ItemCodes.LOCK.value])
