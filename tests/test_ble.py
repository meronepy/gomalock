import pytest
from pytest_mock import MockerFixture

from src.gomalock import ble, const, exc


class TestSesameBleHeader:
    def test_generate_header_only_beginning(self) -> None:
        beginning = int.from_bytes(
            ble.generate_header(is_beginning=True, is_end=False, is_encrypted=False),
            "little",
        )
        assert beginning & const.PacketTypes.BEGINNING
        assert not beginning & (
            const.PacketTypes.PLAINTEXT_END | const.PacketTypes.ENCRYPTED_END
        )

    def test_generate_header_only_plaintext_end(self) -> None:
        plaintext_end = int.from_bytes(
            ble.generate_header(is_beginning=False, is_end=True, is_encrypted=False),
            "little",
        )
        assert plaintext_end & const.PacketTypes.PLAINTEXT_END
        assert not plaintext_end & (
            const.PacketTypes.BEGINNING | const.PacketTypes.ENCRYPTED_END
        )

    def test_generate_header_only_encrypted_end(self) -> None:
        encrypted_end = int.from_bytes(
            ble.generate_header(is_beginning=False, is_end=True, is_encrypted=True),
            "little",
        )
        assert encrypted_end & const.PacketTypes.ENCRYPTED_END
        assert not encrypted_end & (
            const.PacketTypes.BEGINNING | const.PacketTypes.PLAINTEXT_END
        )

    def test_generate_header_beginning_and_plaintext_end(self) -> None:
        beginning_plaintext_end = int.from_bytes(
            ble.generate_header(is_beginning=True, is_end=True, is_encrypted=False),
            "little",
        )
        assert beginning_plaintext_end & (
            const.PacketTypes.BEGINNING | const.PacketTypes.PLAINTEXT_END
        )
        assert not beginning_plaintext_end & const.PacketTypes.ENCRYPTED_END

    def test_generate_header_beginning_and_encrypted_end(self) -> None:
        beginning_encrypted_end = int.from_bytes(
            ble.generate_header(is_beginning=True, is_end=True, is_encrypted=True),
            "little",
        )
        assert beginning_encrypted_end & (
            const.PacketTypes.BEGINNING | const.PacketTypes.ENCRYPTED_END
        )
        assert not beginning_encrypted_end & const.PacketTypes.PLAINTEXT_END

    def test_generate_header_neither_beginning_nor_end(self) -> None:
        neither = int.from_bytes(
            ble.generate_header(is_beginning=False, is_end=False, is_encrypted=False),
            "little",
        )
        assert neither == 0


@pytest.fixture
def callback_ble_device(mocker):
    ble_device = ble.SesameBleDevice("XX:XX:XX:XX:XX:XX", mocker.Mock())
    mock_callback = mocker.patch.object(ble_device, "_received_data_callback")
    return ble_device, mock_callback


class TestSesameBleNotification:
    def test_notification_handler_receives_fragment(
        self, mocker: MockerFixture, callback_ble_device
    ) -> None:
        ble_device, mock_callback = callback_ble_device
        mocker.patch.object(
            ble.ReceivedSesamePacket,
            "from_ble_data",
            return_value=ble.ReceivedSesamePacket(
                const.PacketTypes.BEGINNING, b"fragment"
            ),
        )
        ble_device.notification_handler(mocker.Mock(), bytearray())
        mock_callback.assert_not_called()

    def test_notification_handler_receives_complete_plaintext(
        self, mocker: MockerFixture, callback_ble_device
    ) -> None:
        ble_device, mock_callback = callback_ble_device
        mocker.patch.object(
            ble.ReceivedSesamePacket,
            "from_ble_data",
            return_value=ble.ReceivedSesamePacket(
                const.PacketTypes.BEGINNING | const.PacketTypes.PLAINTEXT_END,
                b"plaintext",
            ),
        )
        ble_device.notification_handler(mocker.Mock(), bytearray())
        mock_callback.assert_called_once_with(b"plaintext", False)

    def test_notification_handler_reassembles_packets(
        self, mocker: MockerFixture, callback_ble_device
    ) -> None:
        ble_device, mock_callback = callback_ble_device
        mocker.patch.object(
            ble.ReceivedSesamePacket,
            "from_ble_data",
            side_effect=[
                ble.ReceivedSesamePacket(const.PacketTypes.BEGINNING, b"part1-"),
                ble.ReceivedSesamePacket(0, b"part2"),
                ble.ReceivedSesamePacket(const.PacketTypes.ENCRYPTED_END, b"-part3"),
            ],
        )
        ble_device.notification_handler(mocker.Mock(), bytearray())
        ble_device.notification_handler(mocker.Mock(), bytearray())
        ble_device.notification_handler(mocker.Mock(), bytearray())
        mock_callback.assert_called_once_with(b"part1-part2-part3", True)


@pytest.fixture
def connected_ble_device(mocker):
    ble_device = ble.SesameBleDevice("XX:XX:XX:XX:XX:XX", mocker.Mock())
    mock_bleak_client = mocker.AsyncMock()
    type(mock_bleak_client).is_connected = mocker.PropertyMock(return_value=True)
    mocker.patch.object(ble_device, "_bleak_client", mock_bleak_client)
    return ble_device, mock_bleak_client


@pytest.fixture
def disconnected_ble_device(mocker):
    ble_device = ble.SesameBleDevice("XX:XX:XX:XX:XX:XX", mocker.Mock())
    mock_bleak_client = mocker.AsyncMock()
    type(mock_bleak_client).is_connected = mocker.PropertyMock(return_value=False)
    mocker.patch.object(ble_device, "_bleak_client", mock_bleak_client)
    return ble_device, mock_bleak_client


class TestSesameBleConnect:
    @pytest.mark.asyncio
    async def test_connect_and_start_notification_successful(
        self,
        mocker: MockerFixture,
        disconnected_ble_device,
    ) -> None:
        ble_device, mock_bleak_client = disconnected_ble_device
        mock_advertisement_data = mocker.Mock(
            product_model=mocker.Mock(name="MOCK_MODEL")
        )
        mocker.patch.object(
            ble.SesameScanner,
            "find_device_by_address",
            new=mocker.AsyncMock(
                return_value=("XX:XX:XX:XX:XX:XX", mock_advertisement_data)
            ),
        )
        await ble_device.connect_and_start_notification()
        mock_bleak_client.connect.assert_awaited_once()
        mock_bleak_client.start_notify.assert_awaited_once_with(
            const.UUID_NOTIFICATION, ble_device.notification_handler
        )
        assert ble_device.sesame_advertisement_data is mock_advertisement_data

    @pytest.mark.asyncio
    async def test_connect_and_start_notification_already_connected(
        self,
        mocker: MockerFixture,
        connected_ble_device,
    ) -> None:
        ble_device, mock_bleak_client = connected_ble_device
        with pytest.raises(exc.SesameConnectionError):
            await ble_device.connect_and_start_notification()
        mock_bleak_client.connect.assert_not_awaited()
        mock_bleak_client.start_notify.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_connect_device_not_found(
        self,
        mocker: MockerFixture,
        disconnected_ble_device,
    ) -> None:
        ble_device, _ = disconnected_ble_device
        mocker.patch.object(
            ble.SesameScanner,
            "find_device_by_address",
            new=mocker.AsyncMock(return_value=None),
        )
        with pytest.raises(exc.SesameError):
            await ble_device.connect_and_start_notification()


class TestSesameWriteGATT:
    @pytest.mark.asyncio
    async def test_write_gatt_without_fragmentation(self, connected_ble_device) -> None:
        ble_device, mock_bleak_client = connected_ble_device
        payload_max_len = const.MTU_SIZE - 1  # 1 byte for header
        mock_send_data = bytes([i for i in range(payload_max_len)])
        await ble_device.write_gatt(mock_send_data, is_encrypted=False)
        mock_bleak_client.write_gatt_char.assert_awaited_once()
        call_args = mock_bleak_client.write_gatt_char.await_args.args
        assert call_args[0] == const.UUID_WRITE
        packet = call_args[1]
        assert len(packet) == 1 + len(mock_send_data)
        assert packet[1:] == mock_send_data
        assert mock_bleak_client.write_gatt_char.await_args.kwargs == {
            "response": False
        }

    @pytest.mark.asyncio
    async def test_write_gatt_with_fragmentation(self, connected_ble_device) -> None:
        ble_device, mock_bleak_client = connected_ble_device
        fragmentation_count = 3
        payload_max_len = const.MTU_SIZE - 1
        mock_send_data = bytes(
            [i for i in range(payload_max_len * fragmentation_count)]
        )
        await ble_device.write_gatt(mock_send_data, is_encrypted=False)
        assert mock_bleak_client.write_gatt_char.await_count == fragmentation_count
        calls = mock_bleak_client.write_gatt_char.await_args_list
        for i, call in enumerate(calls):
            uuid, packet = call.args
            assert uuid == const.UUID_WRITE
            expected_chunk = mock_send_data[
                payload_max_len * i : payload_max_len * (i + 1)
            ]
            assert packet[1:] == expected_chunk
            assert call.kwargs == {"response": False}

    @pytest.mark.asyncio
    async def test_write_gatt_not_connected(self, disconnected_ble_device) -> None:
        ble_device, _ = disconnected_ble_device
        with pytest.raises(exc.SesameConnectionError):
            await ble_device.write_gatt(bytes(), is_encrypted=False)


class TestSesameBleDisconnect:
    @pytest.mark.asyncio
    async def test_disconnect_successful(self, connected_ble_device) -> None:
        ble_device, mock_bleak_client = connected_ble_device
        await ble_device.disconnect()
        mock_bleak_client.disconnect.assert_awaited_once()
        with pytest.raises(exc.SesameConnectionError):
            _ = ble_device.sesame_advertisement_data

    @pytest.mark.asyncio
    async def test_disconnect_not_connected(self, disconnected_ble_device) -> None:
        ble_device, mock_bleak_client = disconnected_ble_device
        await ble_device.disconnect()
        mock_bleak_client.disconnect.assert_not_awaited()


class TestSesameBleDeviceProperties:
    def test_mac_address(self, mocker: MockerFixture, connected_ble_device) -> None:
        ble_device, mock_bleak_client = connected_ble_device
        type(mock_bleak_client).address = mocker.PropertyMock(
            return_value="AA:BB:CC:DD:EE:FF"
        )
        assert ble_device.mac_address == "AA:BB:CC:DD:EE:FF"

    def test_is_connected_when_connected(self, connected_ble_device) -> None:
        ble_device, _ = connected_ble_device
        assert ble_device.is_connected

    def test_is_connected_when_disconnected(self, disconnected_ble_device) -> None:
        ble_device, _ = disconnected_ble_device
        assert not ble_device.is_connected

    def test_sesame_advertisement_data_when_connected(
        self, mocker: MockerFixture, connected_ble_device
    ) -> None:
        ble_device, _ = connected_ble_device
        mock_advertisement_data = mocker.Mock()
        ble_device._sesame_advertisement_data = mock_advertisement_data
        assert ble_device.sesame_advertisement_data is mock_advertisement_data

    def test_sesame_advertisement_data_when_not_connected(
        self, disconnected_ble_device
    ) -> None:
        ble_device, _ = disconnected_ble_device
        with pytest.raises(exc.SesameConnectionError):
            _ = ble_device.sesame_advertisement_data
