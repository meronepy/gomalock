import struct
from uuid import UUID

import pytest

from gomalock import const, protocol


class TestSesameAdvertisementData:
    """Tests for SesameAdvertisementData.from_manufacturer_data."""

    def test_from_manufacturer_data_valid(self) -> None:
        """Parses valid manufacturer data into advertisement fields."""
        device_uuid = UUID("01234567-89ab-cdef-0123-456789abcdef")
        data = struct.pack(
            "<HB16s",
            const.ProductModels.SESAME5.value,
            1,
            device_uuid.bytes,
        )

        result = protocol.SesameAdvertisementData.from_manufacturer_data(data)

        assert result.product_model == const.ProductModels.SESAME5
        assert result.is_registered is True
        assert result.device_uuid == device_uuid

    def test_from_manufacturer_data_unregistered(self) -> None:
        """Parses unregistered device correctly."""
        device_uuid = UUID("01234567-89ab-cdef-0123-456789abcdef")
        data = struct.pack(
            "<HB16s",
            const.ProductModels.SESAME5_PRO.value,
            0,
            device_uuid.bytes,
        )

        result = protocol.SesameAdvertisementData.from_manufacturer_data(data)

        assert result.is_registered is False
        assert result.product_model == const.ProductModels.SESAME5_PRO

    def test_from_manufacturer_data_invalid_length(self) -> None:
        """Raises struct.error for too-short data."""
        with pytest.raises(struct.error):
            protocol.SesameAdvertisementData.from_manufacturer_data(b"\x00")

    def test_from_manufacturer_data_invalid_model(self) -> None:
        """Raises ValueError for unknown product model."""
        device_uuid = UUID("01234567-89ab-cdef-0123-456789abcdef")
        data = struct.pack("<HB16s", 999, 1, device_uuid.bytes)

        with pytest.raises(ValueError):
            protocol.SesameAdvertisementData.from_manufacturer_data(data)


class TestReceivedSesamePacketFromBleData:
    """Tests for ReceivedSesamePacket.from_ble_data."""

    def test_from_ble_data_valid(self) -> None:
        """Parses header byte and payload from raw BLE data."""
        header_byte = const.PacketTypes.BEGINNING
        raw = header_byte.to_bytes(1, "little") + b"payload"

        result = protocol.ReceivedSesamePacket.from_ble_data(raw)

        assert result.header == header_byte
        assert result.payload == b"payload"

    def test_from_ble_data_header_only(self) -> None:
        """Handles single-byte data with empty payload."""
        raw = b"\x01"

        result = protocol.ReceivedSesamePacket.from_ble_data(raw)

        assert result.header == 1
        assert result.payload == b""

    def test_from_ble_data_empty_raises(self) -> None:
        """Raises IndexError for empty data."""
        with pytest.raises(IndexError):
            protocol.ReceivedSesamePacket.from_ble_data(b"")


class TestReceivedSesamePacketProperties:
    """Tests for ReceivedSesamePacket boolean properties."""

    def test_is_beginning_true(self) -> None:
        """Returns True when BEGINNING flag is set."""
        packet = protocol.ReceivedSesamePacket(const.PacketTypes.BEGINNING, b"")
        assert packet.is_beginning is True

    def test_is_beginning_false(self) -> None:
        """Returns False when BEGINNING flag is not set."""
        packet = protocol.ReceivedSesamePacket(const.PacketTypes.PLAINTEXT_END, b"")
        assert packet.is_beginning is False

    def test_is_end_plaintext(self) -> None:
        """Returns True when PLAINTEXT_END flag is set."""
        packet = protocol.ReceivedSesamePacket(const.PacketTypes.PLAINTEXT_END, b"")
        assert packet.is_end is True

    def test_is_end_encrypted(self) -> None:
        """Returns True when ENCRYPTED_END flag is set."""
        packet = protocol.ReceivedSesamePacket(const.PacketTypes.ENCRYPTED_END, b"")
        assert packet.is_end is True

    def test_is_end_false(self) -> None:
        """Returns False when neither end flag is set."""
        packet = protocol.ReceivedSesamePacket(const.PacketTypes.BEGINNING, b"")
        assert packet.is_end is False

    def test_is_encrypted_true(self) -> None:
        """Returns True when ENCRYPTED_END flag is set."""
        packet = protocol.ReceivedSesamePacket(const.PacketTypes.ENCRYPTED_END, b"")
        assert packet.is_encrypted is True

    def test_is_encrypted_false_plaintext(self) -> None:
        """Returns False when only PLAINTEXT_END flag is set."""
        packet = protocol.ReceivedSesamePacket(const.PacketTypes.PLAINTEXT_END, b"")
        assert packet.is_encrypted is False

    def test_is_encrypted_false_beginning(self) -> None:
        """Returns False when only BEGINNING flag is set."""
        packet = protocol.ReceivedSesamePacket(const.PacketTypes.BEGINNING, b"")
        assert packet.is_encrypted is False


class TestReceivedSesameMessage:
    """Tests for ReceivedSesameMessage.from_reassembled_data."""

    def test_from_reassembled_data_valid(self) -> None:
        """Parses opcode and payload from reassembled data."""
        raw = const.OpCodes.PUBLISH.value.to_bytes(1, "little") + b"payload"

        result = protocol.ReceivedSesameMessage.from_reassembled_data(raw)

        assert result.op_code == const.OpCodes.PUBLISH
        assert result.payload == b"payload"

    def test_from_reassembled_data_empty_raises(self) -> None:
        """Raises IndexError for empty data."""
        with pytest.raises(IndexError):
            protocol.ReceivedSesameMessage.from_reassembled_data(b"")

    def test_from_reassembled_data_invalid_opcode_raises(self) -> None:
        """Raises ValueError for invalid opcode."""
        with pytest.raises(ValueError):
            protocol.ReceivedSesameMessage.from_reassembled_data(b"\xff")


class TestReceivedSesameResponse:
    """Tests for ReceivedSesameResponse.from_sesame_message."""

    def test_from_sesame_message_valid(self) -> None:
        """Parses item code, result code, and payload."""
        data = (
            const.ItemCodes.LOGIN.value.to_bytes(1, "little")
            + const.ResultCodes.SUCCESS.value.to_bytes(1, "little")
            + b"payload"
        )

        result = protocol.ReceivedSesameResponse.from_sesame_message(data)

        assert result.item_code == const.ItemCodes.LOGIN
        assert result.result_code == const.ResultCodes.SUCCESS
        assert result.payload == b"payload"

    def test_from_sesame_message_short_payload_raises(self) -> None:
        """Raises IndexError for data shorter than 2 bytes."""
        with pytest.raises(IndexError):
            protocol.ReceivedSesameResponse.from_sesame_message(b"\x02")

    def test_from_sesame_message_invalid_item_code_raises(self) -> None:
        """Raises ValueError for unknown item code."""
        with pytest.raises(ValueError):
            protocol.ReceivedSesameResponse.from_sesame_message(b"\xff\x00")


class TestReceivedSesamePublish:
    """Tests for ReceivedSesamePublish.from_sesame_message."""

    def test_from_sesame_message_valid(self) -> None:
        """Parses item code and payload."""
        data = const.ItemCodes.MECH_STATUS.value.to_bytes(1, "little") + b"payload"

        result = protocol.ReceivedSesamePublish.from_sesame_message(data)

        assert result.item_code == const.ItemCodes.MECH_STATUS
        assert result.payload == b"payload"

    def test_from_sesame_message_empty_raises(self) -> None:
        """Raises IndexError for empty data."""
        with pytest.raises(IndexError):
            protocol.ReceivedSesamePublish.from_sesame_message(b"")

    def test_from_sesame_message_invalid_item_code_raises(self) -> None:
        """Raises ValueError for unknown item code."""
        with pytest.raises(ValueError):
            protocol.ReceivedSesamePublish.from_sesame_message(b"\xff")


class TestSesameCommand:
    """Tests for SesameCommand.transmission_data property."""

    def test_transmission_data_format(self) -> None:
        """Returns item code byte followed by payload."""
        command = protocol.SesameCommand(const.ItemCodes.LOGIN, b"payload")

        result = command.transmission_data

        assert result[0] == const.ItemCodes.LOGIN.value
        assert result[1:] == b"payload"

    def test_transmission_data_empty_payload(self) -> None:
        """Returns single byte for empty payload."""
        command = protocol.SesameCommand(const.ItemCodes.LOCK, b"")

        result = command.transmission_data

        assert len(result) == 1
        assert result[0] == const.ItemCodes.LOCK.value
