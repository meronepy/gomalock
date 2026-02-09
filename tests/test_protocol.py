import struct
from uuid import UUID

import pytest

from src.gomalock import const, protocol


@pytest.fixture
def beginning_packet():
    return protocol.ReceivedSesamePacket(const.PacketTypes.BEGINNING, b"payload")


@pytest.fixture
def plaintext_end_packet():
    return protocol.ReceivedSesamePacket(const.PacketTypes.PLAINTEXT_END, b"payload")


@pytest.fixture
def encrypted_end_packet():
    return protocol.ReceivedSesamePacket(const.PacketTypes.ENCRYPTED_END, b"payload")


class TestSesameAdvertisementData:
    def test_from_manufacturer_data(self) -> None:
        manufacturer_data = struct.pack(
            "<HB16s",
            const.ProductModels.SESAME5.value,
            1,
            UUID("01234567-89ab-cdef-0123-456789abcdef").bytes,
        )
        advertisement_data = protocol.SesameAdvertisementData.from_manufacturer_data(
            manufacturer_data
        )
        assert advertisement_data.product_model == const.ProductModels.SESAME5
        assert advertisement_data.is_registered
        assert advertisement_data.device_uuid == UUID(
            "01234567-89ab-cdef-0123-456789abcdef"
        )


class TestReceivedSesamePacket:
    def test_from_ble_data(self) -> None:
        received_sesame_packet = protocol.ReceivedSesamePacket.from_ble_data(
            const.PacketTypes.BEGINNING.to_bytes(length=1, byteorder="little")
            + b"payload"
        )
        assert received_sesame_packet.header == const.PacketTypes.BEGINNING
        assert received_sesame_packet.payload == b"payload"

    def test_is_beginning(
        self, beginning_packet, plaintext_end_packet, encrypted_end_packet
    ) -> None:
        assert beginning_packet.is_beginning
        assert not plaintext_end_packet.is_beginning
        assert not encrypted_end_packet.is_beginning

    def test_is_end(
        self, beginning_packet, plaintext_end_packet, encrypted_end_packet
    ) -> None:
        assert not beginning_packet.is_end
        assert plaintext_end_packet.is_end
        assert encrypted_end_packet.is_end

    def test_is_encrypted(
        self, beginning_packet, plaintext_end_packet, encrypted_end_packet
    ) -> None:
        assert not beginning_packet.is_encrypted
        assert not plaintext_end_packet.is_encrypted
        assert encrypted_end_packet.is_encrypted


class TestReceivedSesameMessage:
    def test_from_reassembled_data(self) -> None:
        reassembled_data = (
            const.OpCodes.PUBLISH.value.to_bytes(length=1, byteorder="little")
            + b"payload"
        )
        received_sesame_message = protocol.ReceivedSesameMessage.from_reassembled_data(
            reassembled_data
        )
        assert received_sesame_message.op_code == const.OpCodes.PUBLISH
        assert received_sesame_message.payload == b"payload"


class TestReceivedSesameResponse:
    def test_from_sesame_message(self) -> None:
        message_payload = (
            const.ItemCodes.LOGIN.value.to_bytes(length=1, byteorder="little")
            + const.ResultCodes.SUCCESS.value.to_bytes(length=1, byteorder="little")
            + b"payload"
        )
        received_sesame_response = protocol.ReceivedSesameResponse.from_sesame_message(
            message_payload
        )
        assert received_sesame_response.item_code == const.ItemCodes.LOGIN
        assert received_sesame_response.result_code == const.ResultCodes.SUCCESS
        assert received_sesame_response.payload == b"payload"


class TestReceivedSesamePublish:
    def test_from_sesame_message(self) -> None:
        message_payload = (
            const.ItemCodes.LOGIN.value.to_bytes(length=1, byteorder="little")
            + b"payload"
        )
        received_sesame_publish = protocol.ReceivedSesamePublish.from_sesame_message(
            message_payload
        )
        assert received_sesame_publish.item_code == const.ItemCodes.LOGIN
        assert received_sesame_publish.payload == b"payload"


class TestSesameCommand:
    def test_transmission_data(self) -> None:
        sesame_command = protocol.SesameCommand(const.ItemCodes.LOGIN, b"payload")
        assert sesame_command.transmission_data[0] == const.ItemCodes.LOGIN.value
        assert sesame_command.transmission_data[1:] == b"payload"
