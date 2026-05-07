import pytest
from pytest_mock import MockerFixture

from gomalock import ble, const, exc


class TestGenerateHeader:
    """Tests for the generate_header function."""

    def test_generate_header_beginning_only(self) -> None:
        """Sets only the BEGINNING flag."""
        header = int.from_bytes(ble.generate_header(True, False, False), "little")
        assert header & const.PacketTypes.BEGINNING
        assert not header & (
            const.PacketTypes.PLAINTEXT_END | const.PacketTypes.ENCRYPTED_END
        )

    def test_generate_header_plaintext_end_only(self) -> None:
        """Sets only the PLAINTEXT_END flag."""
        header = int.from_bytes(ble.generate_header(False, True, False), "little")
        assert header & const.PacketTypes.PLAINTEXT_END
        assert not header & (
            const.PacketTypes.BEGINNING | const.PacketTypes.ENCRYPTED_END
        )

    def test_generate_header_encrypted_end_only(self) -> None:
        """Sets only the ENCRYPTED_END flag."""
        header = int.from_bytes(ble.generate_header(False, True, True), "little")
        assert header & const.PacketTypes.ENCRYPTED_END
        assert not header & (
            const.PacketTypes.BEGINNING | const.PacketTypes.PLAINTEXT_END
        )

    def test_generate_header_beginning_and_plaintext_end(self) -> None:
        """Sets BEGINNING and PLAINTEXT_END flags."""
        header = int.from_bytes(ble.generate_header(True, True, False), "little")
        assert header & const.PacketTypes.BEGINNING
        assert header & const.PacketTypes.PLAINTEXT_END
        assert not header & const.PacketTypes.ENCRYPTED_END

    def test_generate_header_beginning_and_encrypted_end(self) -> None:
        """Sets BEGINNING and ENCRYPTED_END flags."""
        header = int.from_bytes(ble.generate_header(True, True, True), "little")
        assert header & const.PacketTypes.BEGINNING
        assert header & const.PacketTypes.ENCRYPTED_END
        assert not header & const.PacketTypes.PLAINTEXT_END

    def test_generate_header_no_flags(self) -> None:
        """Returns zero when no flags are set."""
        header = int.from_bytes(ble.generate_header(False, False, False), "little")
        assert header == 0


def _make_ble_device(mocker: MockerFixture, *, is_connected: bool):
    """Helper to create a SesameBleDevice with a mocked BleakClient."""
    received_cb = mocker.Mock()
    disconnect_cb = mocker.Mock()
    device = ble.SesameBleDevice("AA:BB:CC:DD:EE:FF", received_cb, disconnect_cb)
    mock_client = mocker.AsyncMock()
    type(mock_client).is_connected = mocker.PropertyMock(return_value=is_connected)
    type(mock_client).address = mocker.PropertyMock(return_value="AA:BB:CC:DD:EE:FF")
    mocker.patch.object(device, "_bleak_client", mock_client)
    return device, mock_client, received_cb, disconnect_cb


class TestNotificationHandler:
    """Tests for SesameBleDevice.notification_handler."""

    def test_notification_handler_fragment_buffered(
        self, mocker: MockerFixture
    ) -> None:
        """Fragment packet is buffered without invoking callback."""
        device, _, received_cb, _ = _make_ble_device(mocker, is_connected=True)
        mocker.patch.object(
            ble.ReceivedSesamePacket,
            "from_ble_data",
            return_value=ble.ReceivedSesamePacket(
                const.PacketTypes.BEGINNING, b"fragment"
            ),
        )

        device.on_notification(mocker.Mock(), bytearray())

        received_cb.assert_not_called()

    def test_notification_handler_complete_plaintext(
        self, mocker: MockerFixture
    ) -> None:
        """Complete plaintext message invokes callback with is_encrypted=False."""
        device, _, received_cb, _ = _make_ble_device(mocker, is_connected=True)
        mocker.patch.object(
            ble.ReceivedSesamePacket,
            "from_ble_data",
            return_value=ble.ReceivedSesamePacket(
                const.PacketTypes.BEGINNING | const.PacketTypes.PLAINTEXT_END,
                b"plaintext",
            ),
        )

        device.on_notification(mocker.Mock(), bytearray())

        received_cb.assert_called_once_with(b"plaintext", False)

    def test_notification_handler_reassembles_fragments(
        self, mocker: MockerFixture
    ) -> None:
        """Multi-packet message is reassembled before invoking callback."""
        device, _, received_cb, _ = _make_ble_device(mocker, is_connected=True)
        mocker.patch.object(
            ble.ReceivedSesamePacket,
            "from_ble_data",
            side_effect=[
                ble.ReceivedSesamePacket(const.PacketTypes.BEGINNING, b"part1-"),
                ble.ReceivedSesamePacket(0, b"part2-"),
                ble.ReceivedSesamePacket(const.PacketTypes.ENCRYPTED_END, b"part3"),
            ],
        )

        device.on_notification(mocker.Mock(), bytearray())
        device.on_notification(mocker.Mock(), bytearray())
        device.on_notification(mocker.Mock(), bytearray())

        received_cb.assert_called_once_with(b"part1-part2-part3", True)


class TestConnectAndStartNotification:
    """Tests for SesameBleDevice.connect_and_start_notification."""

    @pytest.mark.asyncio
    async def test_connect_and_start_notification_success(
        self, mocker: MockerFixture
    ) -> None:
        """Scans, connects, and starts notifications."""
        device, mock_client, _, _ = _make_ble_device(mocker, is_connected=False)
        mock_adv = mocker.Mock(product_model=mocker.Mock(name="SESAME5"))
        mocker.patch.object(
            ble.SesameScanner,
            "find_device_by_address",
            new=mocker.AsyncMock(return_value=("AA:BB:CC:DD:EE:FF", mock_adv)),
        )

        await device.connect_and_start_notification()

        mock_client.connect.assert_awaited_once()
        mock_client.start_notify.assert_awaited_once_with(
            const.UUID_NOTIFICATION, device.on_notification
        )
        assert device.sesame_advertisement_data is mock_adv

    @pytest.mark.asyncio
    async def test_connect_and_start_notification_already_connected(
        self, mocker: MockerFixture
    ) -> None:
        """Raises SesameConnectionError if already connected."""
        device, mock_client, _, _ = _make_ble_device(mocker, is_connected=True)

        with pytest.raises(exc.SesameConnectionError):
            await device.connect_and_start_notification()

        mock_client.connect.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_connect_and_start_notification_device_not_found(
        self, mocker: MockerFixture
    ) -> None:
        """Raises SesameConnectionError when scan finds nothing."""
        device, _, _, _ = _make_ble_device(mocker, is_connected=False)
        mocker.patch.object(
            ble.SesameScanner,
            "find_device_by_address",
            new=mocker.AsyncMock(return_value=None),
        )

        with pytest.raises(exc.SesameConnectionError):
            await device.connect_and_start_notification()


class TestWriteGatt:
    """Tests for SesameBleDevice.write_gatt."""

    @pytest.mark.asyncio
    async def test_write_gatt_single_packet(self, mocker: MockerFixture) -> None:
        """Data fitting in one MTU is sent as a single packet."""
        device, mock_client, _, _ = _make_ble_device(mocker, is_connected=True)
        payload_max = const.MTU_SIZE - 1
        data = bytes(payload_max)

        await device.write_gatt(data, is_encrypted=False)

        mock_client.write_gatt_char.assert_awaited_once()
        _, packet = mock_client.write_gatt_char.await_args.args
        assert packet[1:] == data

    @pytest.mark.asyncio
    async def test_write_gatt_fragmented(self, mocker: MockerFixture) -> None:
        """Data exceeding MTU is fragmented into multiple packets."""
        device, mock_client, _, _ = _make_ble_device(mocker, is_connected=True)
        payload_max = const.MTU_SIZE - 1
        fragment_count = 3
        data = bytes(range(payload_max * fragment_count))

        await device.write_gatt(data, is_encrypted=False)

        assert mock_client.write_gatt_char.await_count == fragment_count
        calls = mock_client.write_gatt_char.await_args_list
        for i, call in enumerate(calls):
            _, packet = call.args
            expected_chunk = data[payload_max * i : payload_max * (i + 1)]
            assert packet[1:] == expected_chunk
            assert call.kwargs == {"response": False}

    @pytest.mark.asyncio
    async def test_write_gatt_not_connected(self, mocker: MockerFixture) -> None:
        """Raises SesameConnectionError when not connected."""
        device, _, _, _ = _make_ble_device(mocker, is_connected=False)

        with pytest.raises(exc.SesameConnectionError):
            await device.write_gatt(b"data", is_encrypted=False)


class TestDisconnect:
    """Tests for SesameBleDevice.disconnect."""

    @pytest.mark.asyncio
    async def test_disconnect_when_connected(self, mocker: MockerFixture) -> None:
        """Disconnects and clears advertisement data."""
        device, mock_client, _, _ = _make_ble_device(mocker, is_connected=True)
        device._sesame_advertisement_data = mocker.Mock()

        await device.disconnect()

        mock_client.disconnect.assert_awaited_once()
        with pytest.raises(exc.SesameConnectionError):
            _ = device.sesame_advertisement_data

    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected(self, mocker: MockerFixture) -> None:
        """Does nothing when already disconnected."""
        device, mock_client, _, _ = _make_ble_device(mocker, is_connected=False)

        await device.disconnect()

        mock_client.disconnect.assert_not_awaited()


class TestSesameBleDeviceProperties:
    """Tests for SesameBleDevice properties."""

    def test_mac_address_returns_bleak_address(self, mocker: MockerFixture) -> None:
        """Returns the address from BleakClient."""
        device, _, _, _ = _make_ble_device(mocker, is_connected=True)

        assert device.mac_address == "AA:BB:CC:DD:EE:FF"

    def test_is_connected_true(self, mocker: MockerFixture) -> None:
        """Returns True when BleakClient is connected."""
        device, _, _, _ = _make_ble_device(mocker, is_connected=True)

        assert device.is_connected is True

    def test_is_connected_false(self, mocker: MockerFixture) -> None:
        """Returns False when BleakClient is disconnected."""
        device, _, _, _ = _make_ble_device(mocker, is_connected=False)

        assert device.is_connected is False

    def test_sesame_advertisement_data_available(self, mocker: MockerFixture) -> None:
        """Returns advertisement data when available."""
        device, _, _, _ = _make_ble_device(mocker, is_connected=True)
        mock_adv = mocker.Mock()
        device._sesame_advertisement_data = mock_adv

        assert device.sesame_advertisement_data is mock_adv

    def test_sesame_advertisement_data_unavailable(self, mocker: MockerFixture) -> None:
        """Raises SesameConnectionError when not available."""
        device, _, _, _ = _make_ble_device(mocker, is_connected=False)

        with pytest.raises(exc.SesameConnectionError):
            _ = device.sesame_advertisement_data
