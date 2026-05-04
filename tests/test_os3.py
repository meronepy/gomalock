import asyncio
import base64
import struct
import time
from uuid import UUID

import pytest
from pytest_mock import MockerFixture

from gomalock import const, exc, os3, protocol


def _make_os3_device(mocker: MockerFixture, *, is_connected: bool = False):
    """Helper to create OS3Device with a mocked SesameBleDevice."""
    publish_cb = mocker.Mock()
    disconnect_cb = mocker.Mock()
    mock_ble = mocker.Mock()
    mock_ble.write_gatt = mocker.AsyncMock()
    mock_ble.connect_and_start_notification = mocker.AsyncMock()
    mock_ble.disconnect = mocker.AsyncMock()
    type(mock_ble).is_connected = mocker.PropertyMock(return_value=is_connected)
    type(mock_ble).mac_address = mocker.PropertyMock(return_value="AA:BB:CC:DD:EE:FF")
    type(mock_ble).sesame_advertisement_data = mocker.PropertyMock(
        return_value=mocker.Mock(is_registered=False)
    )
    mocker.patch("gomalock.os3.SesameBleDevice", return_value=mock_ble)
    device = os3.OS3Device("AA:BB:CC:DD:EE:FF", publish_cb, disconnect_cb)
    return device, mock_ble, publish_cb, disconnect_cb


class TestCalculateBatteryPercentage:
    """Tests for the calculate_battery_percentage function."""

    def test_calculate_battery_percentage_above_max(self) -> None:
        """Voltage above max returns highest percentage."""
        result = os3.calculate_battery_percentage(const.VOLTAGE_LEVELS[0] + 1.0)
        assert result == int(const.BATTERY_PERCENTAGES[0])

    def test_calculate_battery_percentage_at_max(self) -> None:
        """Voltage at max returns highest percentage."""
        result = os3.calculate_battery_percentage(const.VOLTAGE_LEVELS[0])
        assert result == int(const.BATTERY_PERCENTAGES[0])

    def test_calculate_battery_percentage_at_min(self) -> None:
        """Voltage at min returns lowest percentage."""
        result = os3.calculate_battery_percentage(const.VOLTAGE_LEVELS[-1])
        assert result == int(const.BATTERY_PERCENTAGES[-1])

    def test_calculate_battery_percentage_below_min(self) -> None:
        """Voltage below min returns lowest percentage."""
        result = os3.calculate_battery_percentage(const.VOLTAGE_LEVELS[-1] - 1.0)
        assert result == int(const.BATTERY_PERCENTAGES[-1])

    def test_calculate_battery_percentage_interpolates(self) -> None:
        """Mid-range voltage produces an interpolated percentage."""
        upper = const.VOLTAGE_LEVELS[0]
        lower = const.VOLTAGE_LEVELS[1]
        mid = (upper + lower) / 2
        expected = int(
            (const.BATTERY_PERCENTAGES[0] + const.BATTERY_PERCENTAGES[1]) / 2
        )
        assert os3.calculate_battery_percentage(mid) == expected

    def test_calculate_battery_percentage_nan_raises(self) -> None:
        """NaN voltage triggers AssertionError."""
        with pytest.raises(AssertionError):
            os3.calculate_battery_percentage(float("nan"))


class TestCreateHistoryTag:
    """Tests for the create_history_tag function."""

    def test_create_history_tag_normal(self) -> None:
        """Creates length-prefixed UTF-8 tag."""
        tag = os3.create_history_tag("test")
        assert tag[0] == 4
        assert tag[1:] == b"test"

    def test_create_history_tag_truncates_long_name(self) -> None:
        """Truncates names exceeding HISTORY_TAG_MAX_LEN."""
        long_name = "a" * (const.HISTORY_TAG_MAX_LEN + 10)
        tag = os3.create_history_tag(long_name)
        assert tag[0] == const.HISTORY_TAG_MAX_LEN
        assert tag[1:] == b"a" * const.HISTORY_TAG_MAX_LEN

    def test_create_history_tag_empty(self) -> None:
        """Empty name produces zero-length tag."""
        tag = os3.create_history_tag("")
        assert tag[0] == 0
        assert tag[1:] == b""

    def test_create_history_tag_multibyte_utf8(self) -> None:
        """Multi-byte characters are truncated at byte boundary."""
        tag = os3.create_history_tag("あ" * 20)
        assert tag[0] <= const.HISTORY_TAG_MAX_LEN


class TestOS3QRCode:
    """Tests for OS3QRCode parsing and generation."""

    def test_from_qr_url_roundtrip(self) -> None:
        """QR URL can be generated and parsed back to identical data."""
        device_uuid = UUID("01234567-89ab-cdef-0123-456789abcdef")
        info = os3.OS3QRCode(
            device_name="Sesame",
            key_level=const.KeyLevels.OWNER,
            product_model=const.ProductModels.SESAME5,
            device_uuid=device_uuid,
            secret_key=b"\x01" * 16,
            registration_session_token=b"\x02" * 4,
            key_index=b"\x03\x04",
        )

        parsed = os3.OS3QRCode.from_qr_url(info.qr_url)

        assert parsed.device_name == info.device_name
        assert parsed.key_level == info.key_level
        assert parsed.product_model == info.product_model
        assert parsed.device_uuid == info.device_uuid
        assert parsed.secret_key == info.secret_key
        assert parsed.registration_session_token == (info.registration_session_token)
        assert parsed.key_index == info.key_index

    def test_from_qr_url_invalid_key_level_raises(self) -> None:
        """Raises SesameError for unsupported key level."""
        shared_key = struct.pack(
            ">B16s4s2s16s",
            const.ProductModels.SESAME5.value,
            b"\x01" * 16,
            b"\x02" * 4,
            b"\x03\x04",
            UUID("01234567-89ab-cdef-0123-456789abcdef").bytes,
        )
        sk_b64 = base64.b64encode(shared_key).decode("ascii")
        qr_url = f"ssm://UI?t=sk&sk={sk_b64}&l=9&n=Sesame"

        with pytest.raises(exc.SesameError):
            os3.OS3QRCode.from_qr_url(qr_url)

    def test_qr_url_format(self) -> None:
        """Generated QR URL starts with expected scheme."""
        info = os3.OS3QRCode(
            device_name="Test",
            key_level=const.KeyLevels.OWNER,
            product_model=const.ProductModels.SESAME5,
            device_uuid=UUID("01234567-89ab-cdef-0123-456789abcdef"),
            secret_key=b"\x00" * 16,
        )

        assert info.qr_url.startswith("ssm://UI?")


class TestOS3DeviceOnReceived:
    """Tests for OS3Device.on_received method."""

    def test_on_received_encrypted_without_cipher_ignores(
        self, mocker: MockerFixture
    ) -> None:
        """Encrypted data before login is silently ignored."""
        device, _, _, _ = _make_os3_device(mocker)
        mock_from = mocker.patch.object(
            os3.ReceivedSesameMessage, "from_reassembled_data"
        )

        device.on_received(b"encrypted", True)

        mock_from.assert_not_called()

    @pytest.mark.asyncio
    async def test_on_received_dispatches_response(self, mocker: MockerFixture) -> None:
        """Encrypted response data is decrypted and dispatched."""
        device, _, _, _ = _make_os3_device(mocker)
        device._cipher = mocker.Mock()
        device._cipher.decrypt.return_value = b"decrypted"

        mock_msg = mocker.Mock(op_code=const.OpCodes.RESPONSE, payload=b"resp_payload")
        mocker.patch.object(
            os3.ReceivedSesameMessage,
            "from_reassembled_data",
            return_value=mock_msg,
        )
        mock_response = mocker.Mock(
            item_code=const.ItemCodes.LOGIN,
            result_code=const.ResultCodes.SUCCESS,
        )
        mocker.patch.object(
            os3.ReceivedSesameResponse,
            "from_sesame_message",
            return_value=mock_response,
        )

        future = asyncio.get_running_loop().create_future()
        device._response_futures[const.ItemCodes.LOGIN] = future
        device.on_received(b"encrypted", True)

        device._cipher.decrypt.assert_called_once_with(b"encrypted")
        assert future.result() is mock_response

    def test_on_received_dispatches_publish(self, mocker: MockerFixture) -> None:
        """Plaintext publish data is dispatched to callback."""
        device, _, publish_cb, _ = _make_os3_device(mocker)

        mock_msg = mocker.Mock(op_code=const.OpCodes.PUBLISH, payload=b"pub_payload")
        mocker.patch.object(
            os3.ReceivedSesameMessage,
            "from_reassembled_data",
            return_value=mock_msg,
        )
        mock_publish = mocker.Mock(item_code=const.ItemCodes.MECH_STATUS)
        mocker.patch.object(
            os3.ReceivedSesamePublish,
            "from_sesame_message",
            return_value=mock_publish,
        )

        device.on_received(b"plaintext", False)

        publish_cb.assert_called_once_with(mock_publish)

    @pytest.mark.asyncio
    async def test_on_received_publish_initial_sets_token(
        self, mocker: MockerFixture
    ) -> None:
        """INITIAL publish sets the session token future."""
        device, _, _, _ = _make_os3_device(mocker)
        device._session_token_future = asyncio.get_running_loop().create_future()

        mock_msg = mocker.Mock(op_code=const.OpCodes.PUBLISH, payload=b"pub_payload")
        mocker.patch.object(
            os3.ReceivedSesameMessage,
            "from_reassembled_data",
            return_value=mock_msg,
        )
        mock_publish = protocol.ReceivedSesamePublish(
            const.ItemCodes.INITIAL, b"\x01\x02\x03\x04"
        )
        mocker.patch.object(
            os3.ReceivedSesamePublish,
            "from_sesame_message",
            return_value=mock_publish,
        )

        device.on_received(b"data", False)

        assert device._session_token_future.result() == b"\x01\x02\x03\x04"

    def test_on_received_publish_initial_without_future_ignores(
        self, mocker: MockerFixture
    ) -> None:
        """INITIAL publish without pending future is silently ignored."""
        device, _, publish_cb, _ = _make_os3_device(mocker)

        mock_msg = mocker.Mock(op_code=const.OpCodes.PUBLISH, payload=b"pub_payload")
        mocker.patch.object(
            os3.ReceivedSesameMessage,
            "from_reassembled_data",
            return_value=mock_msg,
        )
        mock_publish = protocol.ReceivedSesamePublish(const.ItemCodes.INITIAL, b"token")
        mocker.patch.object(
            os3.ReceivedSesamePublish,
            "from_sesame_message",
            return_value=mock_publish,
        )

        device.on_received(b"data", False)

        publish_cb.assert_not_called()

    def test_on_received_unsupported_opcode_no_dispatch(
        self, mocker: MockerFixture
    ) -> None:
        """Unsupported opcodes do not dispatch to handlers."""
        device, _, publish_cb, _ = _make_os3_device(mocker)

        mock_msg = mocker.Mock(op_code=const.OpCodes.CREATE, payload=b"payload")
        mocker.patch.object(
            os3.ReceivedSesameMessage,
            "from_reassembled_data",
            return_value=mock_msg,
        )

        device.on_received(b"data", False)

        publish_cb.assert_not_called()


class TestOS3DeviceOnUnexpectedDisconnect:
    """Tests for OS3Device.on_unexpected_disconnect method."""

    def test_on_unexpected_disconnect_calls_callback(
        self, mocker: MockerFixture
    ) -> None:
        """Invokes the user callback and cleans up state."""
        device, _, _, disconnect_cb = _make_os3_device(mocker)
        device._cipher = mocker.Mock()

        device.on_unexpected_disconnect()

        disconnect_cb.assert_called_once()
        assert device._cipher is None


class TestOS3DeviceSendCommand:
    """Tests for OS3Device.send_command method."""

    @pytest.mark.asyncio
    async def test_send_command_success(self, mocker: MockerFixture) -> None:
        """Sends command and returns successful response."""
        device, mock_ble, _, _ = _make_os3_device(mocker)
        command = protocol.SesameCommand(const.ItemCodes.LOGIN, b"data")
        response = protocol.ReceivedSesameResponse(
            const.ItemCodes.LOGIN, const.ResultCodes.SUCCESS, b"ok"
        )

        async def complete_response():
            await asyncio.sleep(0)
            device._response_futures[const.ItemCodes.LOGIN].set_result(response)

        asyncio.create_task(complete_response())
        result = await device.send_command(command, False)

        assert result is response
        mock_ble.write_gatt.assert_awaited_once_with(command.transmission_data, False)

    @pytest.mark.asyncio
    async def test_send_command_encrypts_when_requested(
        self, mocker: MockerFixture
    ) -> None:
        """Encrypts payload when should_encrypt is True."""
        device, mock_ble, _, _ = _make_os3_device(mocker)
        device._cipher = mocker.Mock()
        device._cipher.encrypt.return_value = b"encrypted_data"
        command = protocol.SesameCommand(const.ItemCodes.USER, b"payload")
        response = protocol.ReceivedSesameResponse(
            const.ItemCodes.USER, const.ResultCodes.SUCCESS, b"ok"
        )

        async def complete_response():
            await asyncio.sleep(0)
            device._response_futures[const.ItemCodes.USER].set_result(response)

        asyncio.create_task(complete_response())
        result = await device.send_command(command, True)

        assert result is response
        mock_ble.write_gatt.assert_awaited_once_with(b"encrypted_data", True)

    @pytest.mark.asyncio
    async def test_send_command_encrypt_without_login_raises(
        self, mocker: MockerFixture
    ) -> None:
        """Raises SesameLoginError when encrypting without cipher."""
        device, _, _, _ = _make_os3_device(mocker)
        command = protocol.SesameCommand(const.ItemCodes.USER, b"payload")

        with pytest.raises(exc.SesameLoginError):
            await device.send_command(command, True)

    @pytest.mark.asyncio
    async def test_send_command_operation_failure_raises(
        self, mocker: MockerFixture
    ) -> None:
        """Raises SesameOperationError on non-SUCCESS result code."""
        device, _, _, _ = _make_os3_device(mocker)
        command = protocol.SesameCommand(const.ItemCodes.LOGIN, b"data")
        error_response = protocol.ReceivedSesameResponse(
            const.ItemCodes.LOGIN, const.ResultCodes.INVALID_ACTION, b"err"
        )

        async def complete_response():
            await asyncio.sleep(0)
            device._response_futures[const.ItemCodes.LOGIN].set_result(error_response)

        asyncio.create_task(complete_response())

        with pytest.raises(exc.SesameOperationError) as err_info:
            await device.send_command(command, False)

        assert err_info.value.result_code == const.ResultCodes.INVALID_ACTION


class TestOS3DeviceConnect:
    """Tests for OS3Device.connect method."""

    @pytest.mark.asyncio
    async def test_connect_success(self, mocker: MockerFixture) -> None:
        """Connects and waits for session token."""
        device, mock_ble, _, _ = _make_os3_device(mocker)

        async def fake_connect():
            device._session_token_future.set_result(b"\x01\x02\x03\x04")

        mock_ble.connect_and_start_notification.side_effect = fake_connect

        await device.connect()

        mock_ble.connect_and_start_notification.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_already_connected_raises(
        self, mocker: MockerFixture
    ) -> None:
        """Raises SesameConnectionError if already connected."""
        device, mock_ble, _, _ = _make_os3_device(mocker, is_connected=True)

        with pytest.raises(exc.SesameConnectionError):
            await device.connect()

        mock_ble.connect_and_start_notification.assert_not_awaited()


class TestOS3DeviceRegister:
    """Tests for OS3Device.register method."""

    @pytest.mark.asyncio
    async def test_register_success(self, mocker: MockerFixture) -> None:
        """Returns derived secret key on successful registration."""
        device, mock_ble, _, _ = _make_os3_device(mocker)
        type(mock_ble).sesame_advertisement_data = mocker.PropertyMock(
            return_value=mocker.Mock(is_registered=False)
        )
        mock_pub_key = b"\x11" * 64
        mocker.patch.object(
            os3,
            "generate_app_keys",
            return_value=(mock_pub_key, mocker.Mock()),
        )
        mocker.patch.object(
            os3, "generate_device_secret_key", return_value=b"secretkey_16byt"
        )
        mocker.patch.object(time, "time", return_value=123456789)

        response_payload = b"\x00" * 13 + b"\x22" * 64 + b"tail"
        mock_response = protocol.ReceivedSesameResponse(
            const.ItemCodes.REGISTRATION,
            const.ResultCodes.SUCCESS,
            response_payload,
        )
        device.send_command = mocker.AsyncMock(return_value=mock_response)

        result = await device.register()

        assert result == b"secretkey_16byt"
        expected_ts = int(123456789).to_bytes(4, "little")
        device.send_command.assert_awaited_once_with(
            protocol.SesameCommand(
                const.ItemCodes.REGISTRATION, mock_pub_key + expected_ts
            ),
            False,
        )

    @pytest.mark.asyncio
    async def test_register_already_registered_raises(
        self, mocker: MockerFixture
    ) -> None:
        """Raises SesameError if device is already registered."""
        device, mock_ble, _, _ = _make_os3_device(mocker)
        type(mock_ble).sesame_advertisement_data = mocker.PropertyMock(
            return_value=mocker.Mock(is_registered=True)
        )

        with pytest.raises(exc.SesameError):
            await device.register()


class TestOS3DeviceLogin:
    """Tests for OS3Device.login method."""

    @pytest.mark.asyncio
    async def test_login_success(self, mocker: MockerFixture) -> None:
        """Initializes cipher and returns timestamp."""
        device, _, _, _ = _make_os3_device(mocker)
        session_token = b"\x01\x02\x03\x04"
        device._session_token_future = asyncio.get_event_loop().create_future()
        device._session_token_future.set_result(session_token)

        mock_session_key = b"\x11" * 16
        mocker.patch.object(os3, "generate_session_key", return_value=mock_session_key)
        mock_cipher = mocker.Mock()
        mocker.patch.object(os3, "OS3Cipher", return_value=mock_cipher)

        response = protocol.ReceivedSesameResponse(
            const.ItemCodes.LOGIN,
            const.ResultCodes.SUCCESS,
            (987654321).to_bytes(4, "little"),
        )
        device.send_command = mocker.AsyncMock(return_value=response)

        result = await device.login(b"\x00" * 16)

        assert result == 987654321
        assert device._cipher is mock_cipher
        device.send_command.assert_awaited_once_with(
            protocol.SesameCommand(const.ItemCodes.LOGIN, mock_session_key[:4]),
            False,
        )

    @pytest.mark.asyncio
    async def test_login_already_logged_in_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameLoginError if already logged in."""
        device, _, _, _ = _make_os3_device(mocker)
        device._cipher = mocker.Mock()

        with pytest.raises(exc.SesameLoginError):
            await device.login(b"\x00" * 16)

    @pytest.mark.asyncio
    async def test_login_without_connection_raises(self, mocker: MockerFixture) -> None:
        """Raises SesameConnectionError without prior connect."""
        device, _, _, _ = _make_os3_device(mocker)

        with pytest.raises(exc.SesameConnectionError):
            await device.login(b"\x00" * 16)


class TestOS3DeviceDisconnect:
    """Tests for OS3Device.disconnect method."""

    @pytest.mark.asyncio
    async def test_disconnect_when_connected(self, mocker: MockerFixture) -> None:
        """Disconnects BLE and cleans up."""
        device, mock_ble, _, _ = _make_os3_device(mocker, is_connected=True)
        device._cipher = mocker.Mock()

        await device.disconnect()

        mock_ble.disconnect.assert_awaited_once()
        assert device._cipher is None

    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected(self, mocker: MockerFixture) -> None:
        """Does nothing when already disconnected."""
        device, mock_ble, _, _ = _make_os3_device(mocker, is_connected=False)

        await device.disconnect()

        mock_ble.disconnect.assert_not_awaited()


class TestOS3DeviceProperties:
    """Tests for OS3Device properties."""

    def test_mac_address(self, mocker: MockerFixture) -> None:
        """Returns MAC address from BLE device."""
        device, _, _, _ = _make_os3_device(mocker)

        assert device.mac_address == "AA:BB:CC:DD:EE:FF"

    def test_is_connected_delegates(self, mocker: MockerFixture) -> None:
        """Delegates to BLE device's is_connected."""
        device, _, _, _ = _make_os3_device(mocker, is_connected=True)

        assert device.is_connected is True

    def test_sesame_advertisement_data_delegates(self, mocker: MockerFixture) -> None:
        """Delegates to BLE device's sesame_advertisement_data."""
        device, mock_ble, _, _ = _make_os3_device(mocker)
        mock_adv = mocker.Mock()
        type(mock_ble).sesame_advertisement_data = mocker.PropertyMock(
            return_value=mock_adv
        )

        assert device.sesame_advertisement_data is mock_adv
